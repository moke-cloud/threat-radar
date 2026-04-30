// Package sources defines the adapter interface and shared types every source
// implementation must produce.
//
// Each source returns RawItems; normalize.Normalize then converts them into the
// canonical Item used by the rest of the pipeline.
package sources

import (
	"context"
	"net/http"
	"time"
)

// Config is one source definition from config.yaml.
type Config struct {
	ID       string         `yaml:"id"`
	Name     string         `yaml:"name"`
	Type     string         `yaml:"type"`
	URL      string         `yaml:"url"`
	Category string         `yaml:"category"`
	Weight   float64        `yaml:"weight"`
	Options  map[string]any `yaml:"options,omitempty"`
}

// HTTPClientConfig is the shared HTTP behaviour for every source.
type HTTPClientConfig struct {
	UserAgent      string
	TimeoutSeconds int
}

// NewHTTPClient builds a *http.Client with the configured timeout.
func NewHTTPClient(c HTTPClientConfig) *http.Client {
	t := time.Duration(c.TimeoutSeconds) * time.Second
	if t <= 0 {
		t = 30 * time.Second
	}
	return &http.Client{Timeout: t}
}

// RawItem is the lossy intermediate representation every adapter returns.
// normalize.Normalize converts it into the canonical Item.
type RawItem struct {
	Source     string    // adapter ID
	Category   string    // copied from Config.Category
	SourceName string    // human-readable name
	Weight     float64   // for downstream scoring
	Title      string
	URL        string
	Summary    string    // plain-text description (HTML-stripped)
	Published  time.Time // best-effort parse; zero if unknown
	Vendors    []string  // optional pre-tagged vendors
	CVEs       []string  // optional pre-tagged CVE IDs
	Hints      []string  // optional pre-tagged hints (e.g. "kev", "actively-exploited")
}

// Source is the contract every adapter implements.
type Source interface {
	ID() string
	Fetch(ctx context.Context) ([]RawItem, error)
}

// Build dispatches a Config to the right adapter based on Type.
//
// New types are registered by adding cases here.
func Build(c Config, http HTTPClientConfig) (Source, error) {
	switch c.Type {
	case "rss", "atom":
		return NewRSS(c, http), nil
	case "cisa-kev":
		return NewCISAKEV(c, http), nil
	case "nvd":
		return NewNVD(c, http), nil
	default:
		return nil, ErrUnknownType{c.Type}
	}
}

// ErrUnknownType is returned by Build when a Config.Type isn't recognised.
type ErrUnknownType struct{ Type string }

func (e ErrUnknownType) Error() string { return "unknown source type: " + e.Type }
