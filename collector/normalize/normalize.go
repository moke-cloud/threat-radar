// Package normalize converts the lossy RawItem structs returned by source
// adapters into the canonical Item record used by enrichment, deduplication,
// and persistence.
package normalize

import (
	"crypto/sha256"
	"encoding/hex"
	"net/url"
	"strings"
	"time"

	"github.com/moke-cloud/SHIGOTOBA/threat-radar/collector/sources"
)

// Item is the canonical schema written to NDJSON / index.json.
type Item struct {
	ID         string    `json:"id"`
	Source     string    `json:"source"`
	SourceName string    `json:"source_name"`
	Category   string    `json:"category"`
	Title      string    `json:"title"`
	URL        string    `json:"url"`
	Summary    string    `json:"summary"`
	Published  time.Time `json:"published"`
	Fetched    time.Time `json:"fetched"`
	Tags       []string  `json:"tags,omitempty"`
	Severity   string    `json:"severity,omitempty"`
	Score      int       `json:"score"`
	Vendors    []string  `json:"vendors,omitempty"`
	CVEs       []string  `json:"cves,omitempty"`
	// EPSS is FIRST's exploit-prediction probability (0-1) for the
	// highest-scoring CVE in the item; zero when unknown.
	EPSS           float64 `json:"epss,omitempty"`
	EPSSPercentile float64 `json:"epss_percentile,omitempty"`
	TitleJa        string  `json:"title_ja,omitempty"`
	SummaryJa      string  `json:"summary_ja,omitempty"`
}

// Normalize converts a raw item to a canonical Item. Tags / Severity / Score
// are populated by the enrich package; this layer only does field mapping and
// stable ID generation.
func Normalize(r sources.RawItem, fetched time.Time) Item {
	return Item{
		ID:         StableID(r.Source, r.URL),
		Source:     r.Source,
		SourceName: r.SourceName,
		Category:   r.Category,
		Title:      strings.TrimSpace(r.Title),
		URL:        SafeURL(r.URL),
		Summary:    strings.TrimSpace(r.Summary),
		Published:  r.Published,
		Fetched:    fetched,
		Vendors:    dedupLower(r.Vendors),
		CVEs:       dedupUpper(r.CVEs),
		Tags:       dedupLower(r.Hints),
	}
}

// SafeURL returns the trimmed link when it is an absolute http(s) URL with a
// host, and "" otherwise. Feed links are untrusted: a "javascript:" or
// "data:" link would run script when clicked on the dashboard.
func SafeURL(raw string) string {
	s := strings.TrimSpace(raw)
	u, err := url.Parse(s)
	if err != nil || u.Host == "" {
		return ""
	}
	switch strings.ToLower(u.Scheme) {
	case "http", "https":
		return s
	}
	return ""
}

// StableID produces a deterministic ID for an item so the same article from
// the same source always hashes to the same value across runs.
func StableID(source, url string) string {
	h := sha256.Sum256([]byte(source + "|" + url))
	return hex.EncodeToString(h[:16])
}

func dedupLower(ss []string) []string {
	if len(ss) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(ss))
	out := make([]string, 0, len(ss))
	for _, s := range ss {
		s = strings.ToLower(strings.TrimSpace(s))
		if s == "" {
			continue
		}
		if _, dup := seen[s]; dup {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func dedupUpper(ss []string) []string {
	if len(ss) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(ss))
	out := make([]string, 0, len(ss))
	for _, s := range ss {
		s = strings.ToUpper(strings.TrimSpace(s))
		if s == "" {
			continue
		}
		if _, dup := seen[s]; dup {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
