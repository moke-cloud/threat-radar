package main

import (
	"context"
	"log/slog"
	"net/url"
	"path/filepath"
	"time"

	"github.com/moke-cloud/SHIGOTOBA/threat-radar/collector/jatrans"
	"github.com/moke-cloud/SHIGOTOBA/threat-radar/collector/normalize"
	"github.com/moke-cloud/SHIGOTOBA/threat-radar/collector/sources"
	"github.com/moke-cloud/SHIGOTOBA/threat-radar/collector/store"
)

const (
	translateStatusID   = "local-llm-ja"
	translationsFile    = "translations.json"
	defaultMaxMinutes   = 30
	requestTimeoutFloor = 600 // seconds; a CPU-only batch can take minutes
)

type translateConfig struct {
	Enabled     bool   `yaml:"enabled"`
	Endpoint    string `yaml:"endpoint"`
	Model       string `yaml:"model"`
	BatchSize   int    `yaml:"batch_size"`
	MaxRequests int    `yaml:"max_requests"`
	MaxMinutes  int    `yaml:"max_minutes"`
}

// translator attaches Japanese text to index items. Each call loads the cache,
// translates what is missing (bounded per run), saves, and applies.
type translator struct {
	ctx    context.Context
	client *jatrans.Client // nil: apply cached translations only
	budget time.Duration
	path   string
	now    time.Time
	status *store.SourceStatus
}

// loopbackEndpoint accepts only a llama-server on this machine: feed text is
// never sent anywhere else.
func loopbackEndpoint(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "http" {
		return false
	}
	switch u.Hostname() {
	case "127.0.0.1", "localhost", "::1":
		return true
	}
	return false
}

func newTranslator(ctx context.Context, cfg translateConfig, h sources.HTTPClientConfig, outDir string, now time.Time) *translator {
	if !cfg.Enabled {
		return nil
	}
	t := &translator{
		ctx:  ctx,
		path: filepath.Join(outDir, translationsFile),
		now:  now,
		status: &store.SourceStatus{
			ID: translateStatusID, Name: "llama.cpp (日本語訳)", Category: "enrichment",
			URL: cfg.Model, CheckedAt: now,
		},
	}
	if !loopbackEndpoint(cfg.Endpoint) {
		t.status.Error = "translate.endpoint must be http://127.0.0.1 or localhost"
		return t
	}
	httpCfg := h
	httpCfg.TimeoutSeconds = max(h.TimeoutSeconds, requestTimeoutFloor)
	t.client = &jatrans.Client{
		Endpoint: cfg.Endpoint, Model: cfg.Model,
		HTTP: sources.NewHTTPClient(httpCfg), BatchSize: cfg.BatchSize, MaxRequests: cfg.MaxRequests,
	}
	minutes := cfg.MaxMinutes
	if minutes <= 0 {
		minutes = defaultMaxMinutes
	}
	t.budget = time.Duration(minutes) * time.Minute
	return t
}

func (t *translator) decorate(items []normalize.Item) []normalize.Item {
	cache, err := jatrans.Load(t.path)
	if err != nil {
		slog.Warn("load translations", "err", err)
	}
	if t.client != nil {
		missing := jatrans.Missing(items, cache)
		ctx, cancel := context.WithTimeout(t.ctx, t.budget)
		got, st := t.client.Translate(ctx, missing)
		cancel()
		cache = jatrans.Merge(cache, got)
		t.record(len(missing), st)
	}
	cache = jatrans.Prune(cache, items)
	if err := jatrans.Save(t.path, cache); err != nil {
		slog.Warn("save translations", "err", err)
	}
	return jatrans.Apply(items, cache)
}

func (t *translator) record(missing int, st jatrans.Stats) {
	t.status.Fetched = missing
	t.status.Kept = st.Translated
	// Running out of the time budget is expected; the rest waits for the next run.
	t.status.OK = st.Err == nil || jatrans.IsBudgetExhausted(st.Err)
	if !t.status.OK {
		t.status.Error = store.TruncateError(st.Err.Error())
	}
	if st.Translated > 0 || missing == 0 {
		t.status.LastItemAt = t.now
	}
	slog.Info("translation", "missing", missing, "requests", st.Requests,
		"translated", st.Translated, "rejected", st.Rejected, "unmatched", st.Unmatched, "deferred", st.Remaining, "err", st.Err)
}
