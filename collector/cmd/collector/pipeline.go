package main

import (
	"context"
	"time"

	"github.com/moke-cloud/SHIGOTOBA/threat-radar/collector/enrich"
	"github.com/moke-cloud/SHIGOTOBA/threat-radar/collector/epss"
	"github.com/moke-cloud/SHIGOTOBA/threat-radar/collector/normalize"
	"github.com/moke-cloud/SHIGOTOBA/threat-radar/collector/sources"
	"github.com/moke-cloud/SHIGOTOBA/threat-radar/collector/store"
)

const epssStatusID = "first-epss"

// epssFunc looks up EPSS scores; nil disables the enrichment.
type epssFunc func(ctx context.Context, cves []string) (map[string]epss.Score, error)

type pipelineOptions struct {
	Now          time.Time
	Cutoff       time.Time
	Seen         map[string]struct{}
	WatchVendors []string
	WatchTags    []string
	EPSS         epssFunc
}

type pipelineResult struct {
	Items   []normalize.Item
	Health  []store.SourceStatus
	Fetched int
	Errors  int
}

// process turns raw fetch results into new, scored items plus per-source
// health records.
func process(ctx context.Context, results []fetchResult, opt pipelineOptions) pipelineResult {
	weights := make(map[string]float64, len(results))
	health := make([]store.SourceStatus, 0, len(results)+1)
	var all []normalize.Item
	res := pipelineResult{}
	for _, r := range results {
		weights[r.Cfg.ID] = r.Cfg.Weight
		health = append(health, statusOf(r, opt.Now))
		if r.Err != nil {
			res.Errors++
		}
		res.Fetched += len(r.Items)
		for _, raw := range r.Items {
			all = append(all, normalize.Normalize(raw, opt.Now))
		}
	}

	seen := opt.Seen
	if seen == nil {
		seen = map[string]struct{}{}
	}
	items := enrich.Dedupe(enrich.FilterRecent(all, opt.Cutoff), seen)

	if opt.EPSS != nil {
		scored, st := applyEPSS(ctx, items, opt)
		items = scored
		health = append(health, st)
	}

	kept := map[string]int{}
	for i := range items {
		enrich.Tag(&items[i], opt.WatchVendors)
		enrich.Score(&items[i], enrich.ScoreOptions{
			WatchVendors: opt.WatchVendors,
			WatchTags:    opt.WatchTags,
			Now:          opt.Now,
			SourceWeight: weights[items[i].Source],
		})
		kept[items[i].Source]++
	}
	for i := range health {
		health[i].Kept = kept[health[i].ID]
	}
	res.Items = items
	res.Health = health
	return res
}

func statusOf(r fetchResult, now time.Time) store.SourceStatus {
	st := store.SourceStatus{
		ID:        r.Cfg.ID,
		Name:      r.Cfg.Name,
		Category:  r.Cfg.Category,
		URL:       r.Cfg.URL,
		OK:        r.Err == nil,
		Fetched:   len(r.Items),
		CheckedAt: now,
	}
	if r.Err != nil {
		st.Error = store.TruncateError(r.Err.Error())
	}
	st.LastItemAt = newestPublished(r.Items, now)
	return st
}

// newestPublished ignores dates in the future, which some feeds emit.
func newestPublished(items []sources.RawItem, now time.Time) time.Time {
	var newest time.Time
	for _, it := range items {
		if it.Published.After(newest) && !it.Published.After(now) {
			newest = it.Published
		}
	}
	return newest
}

func applyEPSS(ctx context.Context, items []normalize.Item, opt pipelineOptions) ([]normalize.Item, store.SourceStatus) {
	cves := epss.CollectCVEs(items)
	st := store.SourceStatus{
		ID: epssStatusID, Name: "FIRST EPSS", Category: "enrichment",
		URL: epss.DefaultBaseURL, CheckedAt: opt.Now, Fetched: len(cves),
	}
	scores, err := opt.EPSS(ctx, cves)
	if err != nil {
		st.Error = store.TruncateError(err.Error())
	}
	st.OK = err == nil
	if st.OK && len(cves) > 0 {
		st.LastItemAt = opt.Now
	}
	return epss.Apply(items, scores), st
}

func epssLookup(cfg *appConfig, h sources.HTTPClientConfig) epssFunc {
	if !cfg.EPSS.Enabled {
		return nil
	}
	c := epss.Client{HTTP: sources.NewHTTPClient(h), UserAgent: h.UserAgent}
	return c.Lookup
}
