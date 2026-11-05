package main

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/moke-cloud/SHIGOTOBA/threat-radar/collector/epss"
	"github.com/moke-cloud/SHIGOTOBA/threat-radar/collector/normalize"
	"github.com/moke-cloud/SHIGOTOBA/threat-radar/collector/sources"
)

var now = time.Date(2026, 11, 5, 1, 0, 0, 0, time.UTC)

func raw(src, url string, age time.Duration, cves ...string) sources.RawItem {
	return sources.RawItem{Source: src, Title: url, URL: url, Published: now.Add(-age), CVEs: cves}
}

func sampleResults() []fetchResult {
	return []fetchResult{
		{Cfg: sources.Config{ID: "kev", Name: "KEV", Weight: 1.5}, Items: []sources.RawItem{
			raw("kev", "https://k/1", time.Hour, "CVE-2026-0001"),
			raw("kev", "https://k/old", 400*24*time.Hour, "CVE-2020-0001"),
		}},
		{Cfg: sources.Config{ID: "blog", Name: "Blog", Weight: 0.5}, Items: []sources.RawItem{
			raw("blog", "https://b/1", 2*time.Hour),
			raw("blog", "https://b/seen", 3*time.Hour),
			raw("blog", "https://b/future", -48*time.Hour),
		}},
		{Cfg: sources.Config{ID: "dead", Name: "Dead"}, Err: errors.New("status 403")},
	}
}

func baseOpts() pipelineOptions {
	return pipelineOptions{
		Now:    now,
		Cutoff: now.AddDate(0, 0, -30),
		Seen:   map[string]struct{}{normalize.StableID("blog", "https://b/seen"): {}},
	}
}

func TestProcessFiltersDedupesAndScores(t *testing.T) {
	res := process(context.Background(), sampleResults(), baseOpts())
	if res.Fetched != 5 || res.Errors != 1 {
		t.Fatalf("fetched=%d errors=%d", res.Fetched, res.Errors)
	}
	ids := map[string]normalize.Item{}
	for _, it := range res.Items {
		ids[it.URL] = it
	}
	if _, ok := ids["https://k/old"]; ok {
		t.Fatal("old KEV entry kept")
	}
	if _, ok := ids["https://b/seen"]; ok {
		t.Fatal("seen item kept")
	}
	if len(res.Items) != 3 {
		t.Fatalf("items=%d", len(res.Items))
	}
	if ids["https://k/1"].Score <= ids["https://b/1"].Score {
		t.Fatal("weight not applied")
	}
}

func TestProcessHealth(t *testing.T) {
	res := process(context.Background(), sampleResults(), baseOpts())
	if len(res.Health) != 3 {
		t.Fatalf("health=%d", len(res.Health))
	}
	kev, blog, dead := res.Health[0], res.Health[1], res.Health[2]
	if !kev.OK || kev.Fetched != 2 || kev.Kept != 1 || !kev.LastItemAt.Equal(now.Add(-time.Hour)) {
		t.Fatalf("kev %+v", kev)
	}
	if !blog.LastItemAt.Equal(now.Add(-2 * time.Hour)) {
		t.Fatalf("future date not ignored: %v", blog.LastItemAt)
	}
	if dead.OK || dead.Error != "status 403" {
		t.Fatalf("dead %+v", dead)
	}
}

func TestProcessEPSS(t *testing.T) {
	opt := baseOpts()
	var asked []string
	opt.EPSS = func(_ context.Context, cves []string) (map[string]epss.Score, error) {
		asked = cves
		return map[string]epss.Score{"CVE-2026-0001": {Probability: 0.6, Percentile: 0.99}}, nil
	}
	res := process(context.Background(), sampleResults(), opt)
	if len(asked) != 1 || asked[0] != "CVE-2026-0001" {
		t.Fatalf("asked %v", asked)
	}
	last := res.Health[len(res.Health)-1]
	if last.ID != epssStatusID || !last.OK {
		t.Fatalf("epss status %+v", last)
	}
	for _, it := range res.Items {
		if it.URL == "https://k/1" && it.EPSS != 0.6 {
			t.Fatalf("epss not applied: %+v", it)
		}
	}
}

func TestProcessEPSSFailureIsNotFatal(t *testing.T) {
	opt := baseOpts()
	opt.EPSS = func(context.Context, []string) (map[string]epss.Score, error) {
		return nil, errors.New("epss: status 429")
	}
	res := process(context.Background(), sampleResults(), opt)
	last := res.Health[len(res.Health)-1]
	if last.OK || last.Error == "" || len(res.Items) != 3 {
		t.Fatalf("status %+v items %d", last, len(res.Items))
	}
}

func TestSplitCSVSet(t *testing.T) {
	if splitCSVSet("") != nil {
		t.Fatal("empty should be nil")
	}
	got := splitCSVSet(" a, ,b ")
	if len(got) != 2 {
		t.Fatalf("got %v", got)
	}
}

func TestEPSSLookupDisabled(t *testing.T) {
	if epssLookup(&appConfig{}, sources.HTTPClientConfig{}) != nil {
		t.Fatal("want nil when disabled")
	}
	cfg := &appConfig{}
	cfg.EPSS.Enabled = true
	if epssLookup(cfg, sources.HTTPClientConfig{}) == nil {
		t.Fatal("want lookup when enabled")
	}
}

func TestBuildSourcesReportsBuildFailures(t *testing.T) {
	entries, failed := buildSources([]sources.Config{
		{ID: "ok", Type: "rss", URL: "https://example.com/feed"},
		{ID: "bad", Name: "Bad", Type: "nope"},
		{ID: "skip", Type: "rss"},
	}, sources.HTTPClientConfig{}, map[string]struct{}{"ok": {}, "bad": {}}, now)
	if len(entries) != 1 || len(failed) != 1 || failed[0].ID != "bad" || failed[0].OK || failed[0].Error == "" {
		t.Fatalf("entries=%d failed=%+v", len(entries), failed)
	}
}

func TestIndexOptions(t *testing.T) {
	opt := indexOptions([]sources.Config{{ID: "nvd", IndexLimit: 150}, {ID: "kev"}})
	if len(opt.Allowed) != 2 || opt.PerSource["nvd"] != 150 {
		t.Fatalf("opt %+v", opt)
	}
	if _, ok := opt.PerSource["kev"]; ok {
		t.Fatal("kev should be uncapped")
	}
}
