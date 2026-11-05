package main

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/moke-cloud/SHIGOTOBA/threat-radar/collector/sources"
)

type sourceEntry struct {
	cfg sources.Config
	src sources.Source
}

// fetchResult is one source's outcome. Exactly one of Items / Err is set.
type fetchResult struct {
	Cfg      sources.Config
	Items    []sources.RawItem
	Err      error
	Duration time.Duration
}

// fetchAll runs every Fetch in parallel (bounded by parallel) and returns
// results in configuration order.
func fetchAll(ctx context.Context, srcs []sourceEntry, parallel int, verbose bool) []fetchResult {
	results := make([]fetchResult, len(srcs))
	sem := make(chan struct{}, parallel)
	var wg sync.WaitGroup
	for i, e := range srcs {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, e sourceEntry) {
			defer wg.Done()
			defer func() { <-sem }()
			start := time.Now()
			items, err := e.src.Fetch(ctx)
			results[i] = fetchResult{Cfg: e.cfg, Items: items, Err: err, Duration: time.Since(start)}
			ms := results[i].Duration.Milliseconds()
			switch {
			case err != nil:
				slog.Warn("fetch failed", "source", e.cfg.ID, "err", err, "ms", ms)
			case verbose:
				slog.Info("fetched", "source", e.cfg.ID, "items", len(items), "ms", ms)
			}
		}(i, e)
	}
	wg.Wait()
	return results
}
