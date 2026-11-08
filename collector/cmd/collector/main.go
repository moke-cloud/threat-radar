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
	"syscall"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/moke-cloud/SHIGOTOBA/threat-radar/collector/normalize"
	"github.com/moke-cloud/SHIGOTOBA/threat-radar/collector/sources"
	"github.com/moke-cloud/SHIGOTOBA/threat-radar/collector/store"
)

const (
	defaultMaxItemAgeDays = 30
	defaultParallel       = 8
	indexDaysBack         = 14
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
		MaxItemAgeDays int `yaml:"max_item_age_days"`
	} `yaml:"retain"`
	EPSS struct {
		Enabled bool `yaml:"enabled"`
	} `yaml:"epss"`
	Translate translateConfig `yaml:"translate"`
	Watch     struct {
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
	skipFetch := flag.Bool("skip-fetch", false, "fetch no sources; only rebuild the index (and translate)")
	translateMode := flag.String("translate", translateRun, "run: call the local model; cache: apply cached translations only")
	flag.Parse()

	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo})))

	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "load config:", err)
		os.Exit(2)
	}
	if *translateMode != translateRun && *translateMode != translateCache {
		fmt.Fprintln(os.Stderr, "-translate must be run or cache")
		os.Exit(2)
	}
	opts := runOptions{only: splitCSVSet(*only), dry: *dry, verbose: *verbose, skipFetch: *skipFetch, translate: *translateMode}
	if err := run(cfg, *outDir, opts); err != nil {
		slog.Error("collector failed", "err", err)
		os.Exit(1)
	}
}

type runOptions struct {
	only      map[string]struct{}
	dry       bool
	verbose   bool
	skipFetch bool
	translate string
}

func run(cfg *appConfig, outDir string, o runOptions) error {
	only, dry, verbose := o.only, o.dry, o.verbose
	if o.skipFetch {
		// An ID no source has: nothing is fetched, everything else runs.
		only = map[string]struct{}{"(skip-fetch)": {}}
	}
	httpCfg := sources.HTTPClientConfig{
		UserAgent:      cfg.HTTP.UserAgent,
		TimeoutSeconds: cfg.HTTP.TimeoutSeconds,
	}
	now := time.Now().UTC()
	srcs, buildFailures := buildSources(cfg.Sources, httpCfg, only, now)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	parallel := cfg.HTTP.Parallel
	if parallel <= 0 {
		parallel = defaultParallel
	}
	results := fetchAll(ctx, srcs, parallel, verbose)

	maxAge := cfg.Retain.MaxItemAgeDays
	if maxAge <= 0 {
		maxAge = defaultMaxItemAgeDays
	}
	st := store.New(outDir, cfg.Retain.IndexMaxItems)
	seen, err := st.LoadSeenIDs(maxAge + 1)
	if err != nil {
		slog.Warn("load seen ids", "err", err)
	}

	out := process(ctx, results, pipelineOptions{
		Now:          now,
		Cutoff:       now.AddDate(0, 0, -maxAge),
		Seen:         seen,
		WatchVendors: cfg.Watch.Vendors,
		WatchTags:    cfg.Watch.Tags,
		EPSS:         epssUnlessSkipped(cfg, httpCfg, o.skipFetch),
	})
	out.Health = append(out.Health, buildFailures...)
	out.Errors += len(buildFailures)
	slog.Info("pipeline done", "fetched", out.Fetched, "new", len(out.Items), "source_errors", out.Errors)

	if dry {
		printDry(out)
		return nil
	}
	idx := indexOptions(cfg.Sources)
	tr := newTranslator(ctx, cfg.Translate, o.translate, httpCfg, outDir, now)
	var translate func([]normalize.Item) []normalize.Item
	if tr != nil {
		translate = tr.decorate
	}
	idx.Decorate = chainDecorators(backfillFacts, translate)
	if err := persist(st, out, now, cfg.Retain.DailyFilesKeep, idx, tr); err != nil {
		return err
	}
	return nil
}

// indexOptions derives index shaping from the full source list (not the
// -only subset), so a partial run never drops other sources from the index.
func indexOptions(cfgs []sources.Config) store.IndexOptions {
	opt := store.IndexOptions{Allowed: map[string]struct{}{}, PerSource: map[string]int{}}
	for _, c := range cfgs {
		opt.Allowed[c.ID] = struct{}{}
		if c.IndexLimit > 0 {
			opt.PerSource[c.ID] = c.IndexLimit
		}
	}
	return opt
}

func persist(st *store.Store, out pipelineResult, now time.Time, keepDays int, idx store.IndexOptions, tr *translator) error {
	if err := st.AppendDaily(out.Items); err != nil {
		return fmt.Errorf("append daily: %w", err)
	}
	if err := st.RebuildIndex(indexDaysBack, idx); err != nil {
		return fmt.Errorf("rebuild index: %w", err)
	}
	if tr != nil && tr.status != nil {
		out.Health = append(out.Health, *tr.status)
	}
	prev, err := st.LoadHealth()
	if err != nil {
		slog.Warn("load source health", "err", err)
	}
	if err := st.WriteHealth(store.MergeHealth(prev, out.Health, idx.Allowed), now); err != nil {
		return fmt.Errorf("write source health: %w", err)
	}
	if err := st.PurgeOlderThan(keepDays); err != nil {
		slog.Warn("purge failed", "err", err)
	}
	slog.Info("threat-radar collection complete", "new_items", len(out.Items), "errors", out.Errors)
	return nil
}

func printDry(out pipelineResult) {
	for _, it := range out.Items[:min(5, len(out.Items))] {
		fmt.Printf("%-16s %-8s %3d  epss=%.3f  %s\n", it.Source, it.Severity, it.Score, it.EPSS, it.Title)
	}
	for _, h := range out.Health {
		if !h.OK {
			fmt.Printf("FAILED %-16s %s\n", h.ID, h.Error)
		}
	}
	fmt.Printf("(dry-run: %d new items, no writes)\n", len(out.Items))
}

// buildSources constructs the adapters to run. Sources whose adapter cannot
// be built are returned as failed health records so they show up in the UI
// instead of silently vanishing.
func buildSources(cfgs []sources.Config, h sources.HTTPClientConfig, only map[string]struct{}, now time.Time) ([]sourceEntry, []store.SourceStatus) {
	out := make([]sourceEntry, 0, len(cfgs))
	var failed []store.SourceStatus
	for _, sc := range cfgs {
		if len(only) > 0 {
			if _, ok := only[sc.ID]; !ok {
				continue
			}
		}
		s, err := sources.Build(sc, h)
		if err != nil {
			slog.Warn("skipping source", "id", sc.ID, "err", err)
			failed = append(failed, store.SourceStatus{
				ID: sc.ID, Name: sc.Name, Category: sc.Category, URL: sc.URL,
				Error: store.TruncateError(err.Error()), CheckedAt: now,
			})
			continue
		}
		out = append(out, sourceEntry{cfg: sc, src: s})
	}
	return out, failed
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

func splitCSVSet(s string) map[string]struct{} {
	if s == "" {
		return nil
	}
	out := map[string]struct{}{}
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out[p] = struct{}{}
		}
	}
	return out
}
