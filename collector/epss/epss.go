// Package epss looks up FIRST EPSS exploit-prediction scores for CVE IDs.
//
// API: https://api.first.org/data/v1/epss?cve=CVE-A,CVE-B (public, no key).
package epss

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/moke-cloud/SHIGOTOBA/threat-radar/collector/normalize"
)

// DefaultBaseURL is FIRST's public EPSS endpoint.
const DefaultBaseURL = "https://api.first.org/data/v1/epss"

const (
	defaultBatchSize = 100
	maxBodyBytes     = 4 << 20
)

// cveID matches a well-formed CVE identifier. IDs come from untrusted feeds,
// so anything else is dropped before it reaches the query string.
var cveID = regexp.MustCompile(`^CVE-\d{4}-\d{4,7}$`)

// Score is one CVE's EPSS probability (0-1) and percentile (0-1).
type Score struct {
	Probability float64
	Percentile  float64
}

// Client queries the EPSS API in batches.
type Client struct {
	BaseURL   string
	HTTP      *http.Client
	UserAgent string
	BatchSize int
}

type apiResponse struct {
	Data []struct {
		CVE        string `json:"cve"`
		EPSS       string `json:"epss"`
		Percentile string `json:"percentile"`
	} `json:"data"`
}

// Lookup returns scores for the valid, de-duplicated IDs in cves. CVEs that
// EPSS has not scored yet are simply absent from the result.
func (c Client) Lookup(ctx context.Context, cves []string) (map[string]Score, error) {
	ids := validIDs(cves)
	out := make(map[string]Score, len(ids))
	size := c.BatchSize
	if size <= 0 {
		size = defaultBatchSize
	}
	for start := 0; start < len(ids); start += size {
		end := min(start+size, len(ids))
		batch, err := c.fetch(ctx, ids[start:end])
		if err != nil {
			return out, err
		}
		for k, v := range batch {
			out[k] = v
		}
	}
	return out, nil
}

func (c Client) fetch(ctx context.Context, ids []string) (map[string]Score, error) {
	base := c.BaseURL
	if base == "" {
		base = DefaultBaseURL
	}
	q := url.Values{"cve": {strings.Join(ids, ",")}}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"?"+q.Encode(), nil)
	if err != nil {
		return nil, fmt.Errorf("epss: build request: %w", err)
	}
	if c.UserAgent != "" {
		req.Header.Set("User-Agent", c.UserAgent)
	}
	hc := c.HTTP
	if hc == nil {
		hc = http.DefaultClient
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("epss: request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("epss: status %d", resp.StatusCode)
	}
	var body apiResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxBodyBytes)).Decode(&body); err != nil {
		return nil, fmt.Errorf("epss: decode: %w", err)
	}
	out := make(map[string]Score, len(body.Data))
	for _, d := range body.Data {
		p, errP := strconv.ParseFloat(d.EPSS, 64)
		pct, errPct := strconv.ParseFloat(d.Percentile, 64)
		if errP != nil || errPct != nil {
			continue
		}
		out[strings.ToUpper(d.CVE)] = Score{Probability: p, Percentile: pct}
	}
	return out, nil
}

func validIDs(cves []string) []string {
	seen := make(map[string]struct{}, len(cves))
	out := make([]string, 0, len(cves))
	for _, c := range cves {
		id := strings.ToUpper(strings.TrimSpace(c))
		if !cveID.MatchString(id) {
			continue
		}
		if _, dup := seen[id]; dup {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// CollectCVEs returns every CVE ID referenced by items, de-duplicated.
func CollectCVEs(items []normalize.Item) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, it := range items {
		for _, c := range it.CVEs {
			if _, dup := seen[c]; !dup {
				seen[c] = struct{}{}
				out = append(out, c)
			}
		}
	}
	return out
}

// Apply returns a copy of items where each item carries the highest EPSS
// score among its CVEs. The input slice is not modified.
func Apply(items []normalize.Item, scores map[string]Score) []normalize.Item {
	out := make([]normalize.Item, len(items))
	for i, it := range items {
		best := Score{}
		for _, c := range it.CVEs {
			if s, ok := scores[c]; ok && s.Probability > best.Probability {
				best = s
			}
		}
		it.EPSS = best.Probability
		it.EPSSPercentile = best.Percentile
		out[i] = it
	}
	return out
}
