package main

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/moke-cloud/SHIGOTOBA/threat-radar/collector/jatrans"
	"github.com/moke-cloud/SHIGOTOBA/threat-radar/collector/normalize"
	"github.com/moke-cloud/SHIGOTOBA/threat-radar/collector/sources"
	"github.com/moke-cloud/SHIGOTOBA/threat-radar/collector/store"
)

const (
	translateStatusID = "github-models-ja"
	translationsFile  = "translations.json"
	// tokenEnv holds the workflow's GITHUB_TOKEN. Read only here, never logged.
	tokenEnv              = "GITHUB_TOKEN"
	allowedEndpointPrefix = "https://models.github.ai/"
)

type translateConfig struct {
	Enabled     bool   `yaml:"enabled"`
	Endpoint    string `yaml:"endpoint"`
	Model       string `yaml:"model"`
	BatchSize   int    `yaml:"batch_size"`
	MaxRequests int    `yaml:"max_requests"`
}

// translator attaches Japanese text to index items. Each call loads the cache,
// translates what is missing (bounded per run), saves, and applies.
type translator struct {
	ctx    context.Context
	client *jatrans.Client // nil: apply cached translations only
	path   string
	now    time.Time
	status *store.SourceStatus
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
			ID: translateStatusID, Name: "GitHub Models (日本語訳)", Category: "enrichment",
			URL: jatrans.DefaultEndpoint, CheckedAt: now,
		},
	}
	// The token must only ever go to GitHub Models.
	if cfg.Endpoint != "" && !strings.HasPrefix(cfg.Endpoint, allowedEndpointPrefix) {
		t.status.Error = "translate.endpoint must start with " + allowedEndpointPrefix
		return t
	}
	token := os.Getenv(tokenEnv)
	if token == "" {
		t.status.Error = tokenEnv + " not set: existing translations only"
		return t
	}
	httpCfg := h
	httpCfg.TimeoutSeconds = max(h.TimeoutSeconds, 90)
	t.client = &jatrans.Client{
		Endpoint: cfg.Endpoint, Token: token, Model: cfg.Model,
		HTTP: sources.NewHTTPClient(httpCfg), BatchSize: cfg.BatchSize, MaxRequests: cfg.MaxRequests,
	}
	return t
}

func (t *translator) decorate(items []normalize.Item) []normalize.Item {
	cache, err := jatrans.Load(t.path)
	if err != nil {
		slog.Warn("load translations", "err", err)
	}
	if t.client != nil {
		missing := jatrans.Missing(items, cache)
		got, st := t.client.Translate(t.ctx, missing)
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
	t.status.OK = st.Err == nil
	if st.Err != nil {
		t.status.Error = store.TruncateError(st.Err.Error())
	}
	if st.Translated > 0 || missing == 0 {
		t.status.LastItemAt = t.now
	}
	slog.Info("translation", "missing", missing, "requests", st.Requests,
		"translated", st.Translated, "rejected", st.Rejected, "deferred", st.Remaining, "err", st.Err)
}
