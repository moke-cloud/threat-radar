// Command collector polls every configured source, enriches the items, and
// writes them to the on-disk layout consumed by the static UI.
//
// Usage:
//
//	go run ./cmd/collector -config ../config.yaml -out ../data
//
// Flags:
//
//	-config <path>   YAML config file (required)
//	-out <path>      output directory (default ../data)
//	-only <id,id>    comma-separated source IDs to fetch (skip others)
//	-dry             parse + enrich but do not write outputs
//	-verbose         per-source progress
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/moke-cloud/SHIGOTOBA/threat-radar/collector/enrich"
	"github.com/moke-cloud/SHIGOTOBA/threat-radar/collector/normalize"
	"github.com/moke-cloud/SHIGOTOBA/threat-radar/collector/sources"
	"github.com/moke-cloud/SHIGOTOBA/threat-radar/collector/store"
)

type appConfig struct {
	HTTP struct {
		UserAgent      string `yaml:"user_agent"`
		TimeoutSeconds int    `yaml:"timeout_seconds"`
		Parallel       int    `yaml:"parallel"`
	} `yaml:"http"`
	Retain struct {
		IndexMaxItems  int `yaml:"index_max_items"`
		DailyFilesKeep int `yaml:"daily_files_keep"`
	} `yaml:"retain"`
	Watch struct {
		Vendors []string `yaml:"vendors"`
		Tags    []string `yaml:"tags"`
	} `yaml:"watch"`
	Sources []sources.Config `yaml:"sources"`
}

func main() {
	cfgPath := flag.String("config", "config.yaml", "path to YAML config")
	outDir := flag.String("out", "data", "output directory")
	only := flag.String("only", "", "comma-separated source IDs to limit to")
	dry := flag.Bool("dry", false, "do not write outputs")
	verbose := flag.Bool("verbose", false, "per-source progress")
	flag.Parse()

	logh := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo})
	slog.SetDefault(slog.New(logh))

	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "load config:", err)
		os.Exit(2)
	}

	httpCfg := sources.HTTPClientConfig{
		UserAgent:      cfg.HTTP.UserAgent,
		TimeoutSeconds: cfg.HTTP.TimeoutSeconds,
	}

	wantSet := splitCSVSet(*only)
	srcs := make([]sources.Source, 0, len(cfg.Sources))
	for _, sc := range cfg.Sources {
		if len(wantSet) > 0 {
			if _, ok := wantSet[sc.ID]; !ok {
				continue
			}
		}
		s, err := sources.Build(sc, httpCfg)
		if err != nil {
			slog.Warn("skipping source", "id", sc.ID, "err", err)
			continue
		}
		srcs = append(srcs, s)
	}

	parallel := cfg.HTTP.Parallel
	if parallel <= 0 {
		parallel = 8
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	collected, srcErrors := fetchAll(ctx, srcs, parallel, *verbose)
	slog.Info("collection done", "items", len(collected), "errors", len(srcErrors))

	st := store.New(*outDir, cfg.Retain.IndexMaxItems)

	// Dedup against last 7 days of items.
	seen, _ := st.LoadSeenIDs(7)

	now := time.Now().UTC()
	items := make([]normalize.Item, 0, len(collected))
	for _, raw := range collected {
		it := normalize.Normalize(raw, now)
		enrich.Tag(&it, cfg.Watch.Vendors)
		enrich.Score(&it, enrich.ScoreOptions{
			WatchVendors: cfg.Watch.Vendors,
			WatchTags:    cfg.Watch.Tags,
			Now:          now,
		})
		items = append(items, it)
	}

	items = enrich.Dedupe(items, seen)
	slog.Info("after dedup", "items", len(items))

	if *dry {
		for _, it := range items[:min(5, len(items))] {
			fmt.Printf("%-12s %-8s %3d  %s\n", it.Source, it.Severity, it.Score, it.Title)
		}
		fmt.Printf("(dry-run: %d items, no writes)\n", len(items))
		return
	}

	if err := st.AppendDaily(items); err != nil {
		slog.Error("append daily failed", "err", err)
		os.Exit(1)
	}
	if err := st.RebuildIndex(14); err != nil {
		slog.Error("rebuild index failed", "err", err)
		os.Exit(1)
	}
	if err := st.PurgeOlderThan(cfg.Retain.DailyFilesKeep); err != nil {
		slog.Warn("purge failed", "err", err)
	}

	slog.Info("threat-radar collection complete",
		"new_items", len(items), "errors", len(srcErrors), "out", *outDir)

	if len(srcErrors) > 0 && *verbose {
		for id, err := range srcErrors {
			slog.Warn("source error", "id", id, "err", err)
		}
	}
}

func loadConfig(path string) (*appConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg appConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// fetchAll runs all source.Fetch calls in parallel with a semaphore.
func fetchAll(ctx context.Context, srcs []sources.Source, parallel int, verbose bool) ([]sources.RawItem, map[string]error) {
	sem := make(chan struct{}, parallel)
	var (
		wg      sync.WaitGroup
		muOut   sync.Mutex
		out     []sources.RawItem
		muErr   sync.Mutex
		srcErrs = map[string]error{}
	)

	for _, s := range srcs {
		s := s
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			start := time.Now()
			items, err := s.Fetch(ctx)
			dur := time.Since(start)
			if err != nil {
				muErr.Lock()
				srcErrs[s.ID()] = err
				muErr.Unlock()
				slog.Warn("fetch failed", "source", s.ID(), "err", err, "ms", dur.Milliseconds())
				return
			}
			if verbose {
				slog.Info("fetched", "source", s.ID(), "items", len(items), "ms", dur.Milliseconds())
			}
			muOut.Lock()
			out = append(out, items...)
			muOut.Unlock()
		}()
	}
	wg.Wait()
	return out, srcErrs
}

func splitCSVSet(s string) map[string]struct{} {
	if s == "" {
		return nil
	}
	out := map[string]struct{}{}
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		if p != "" {
			out[p] = struct{}{}
		}
	}
	return out
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
