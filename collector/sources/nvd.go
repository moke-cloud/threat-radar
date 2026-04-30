package sources

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// NVD is the adapter for NIST's NVD CVE 2.0 REST API. Without an API key,
// requests are rate-limited to 5 per 30 seconds — sufficient for once-a-day
// collection. We only fetch the most recent N hours of changes.
//
// Reference: https://nvd.nist.gov/developers/vulnerabilities
type NVD struct {
	cfg    Config
	client *http.Client
	ua     string
}

// NewNVD constructs the NVD adapter.
func NewNVD(c Config, h HTTPClientConfig) *NVD {
	return &NVD{cfg: c, client: NewHTTPClient(h), ua: h.UserAgent}
}

// ID returns the source ID.
func (n *NVD) ID() string { return n.cfg.ID }

// nvdResponse mirrors the relevant subset of the NVD CVE 2.0 schema.
type nvdResponse struct {
	ResultsPerPage  int                `json:"resultsPerPage"`
	StartIndex      int                `json:"startIndex"`
	TotalResults    int                `json:"totalResults"`
	Format          string             `json:"format"`
	Version         string             `json:"version"`
	Timestamp       string             `json:"timestamp"`
	Vulnerabilities []nvdVulnWrap      `json:"vulnerabilities"`
}

type nvdVulnWrap struct {
	CVE nvdCVE `json:"cve"`
}

type nvdCVE struct {
	ID            string         `json:"id"`
	SourceIdentifier string      `json:"sourceIdentifier"`
	Published     string         `json:"published"`
	LastModified  string         `json:"lastModified"`
	VulnStatus    string         `json:"vulnStatus"`
	Descriptions  []nvdDesc      `json:"descriptions"`
	Metrics       nvdMetrics     `json:"metrics"`
	References    []nvdReference `json:"references"`
	Configurations []nvdConfig   `json:"configurations,omitempty"`
}

type nvdDesc struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

type nvdMetrics struct {
	V31 []nvdCVSSWrap `json:"cvssMetricV31"`
	V30 []nvdCVSSWrap `json:"cvssMetricV30"`
	V2  []nvdCVSSWrap `json:"cvssMetricV2"`
}

type nvdCVSSWrap struct {
	Source     string         `json:"source"`
	Type       string         `json:"type"`
	CvssData   nvdCVSS        `json:"cvssData"`
	BaseSeverity string       `json:"baseSeverity"`
}

type nvdCVSS struct {
	BaseScore    float64 `json:"baseScore"`
	BaseSeverity string  `json:"baseSeverity"`
	Vector       string  `json:"vectorString"`
}

type nvdReference struct {
	URL    string   `json:"url"`
	Source string   `json:"source"`
	Tags   []string `json:"tags"`
}

type nvdConfig struct {
	Nodes []nvdConfigNode `json:"nodes,omitempty"`
}

type nvdConfigNode struct {
	CPEMatch []nvdCPEMatch `json:"cpeMatch,omitempty"`
}

type nvdCPEMatch struct {
	Vulnerable bool   `json:"vulnerable"`
	Criteria   string `json:"criteria"`
}

// Fetch retrieves CVEs published or last-modified in the lookback window.
// The window is read from cfg.Options["lookback_hours"] (default 48).
func (n *NVD) Fetch(ctx context.Context) ([]RawItem, error) {
	lookback := 48
	if v, ok := n.cfg.Options["lookback_hours"]; ok {
		if i, ok := v.(int); ok && i > 0 {
			lookback = i
		}
	}
	end := time.Now().UTC()
	start := end.Add(-time.Duration(lookback) * time.Hour)
	// NVD requires ISO8601 with explicit UTC offset; the literal "+" must be
	// URL-encoded so it isn't read as a space in the query string.
	q := url.Values{}
	q.Set("lastModStartDate", start.Format("2006-01-02T15:04:05.000")+"+00:00")
	q.Set("lastModEndDate", end.Format("2006-01-02T15:04:05.000")+"+00:00")
	q.Set("resultsPerPage", "200")
	endpoint := n.cfg.URL + "?" + q.Encode()

	body, err := n.get(ctx, endpoint)
	if err != nil {
		return nil, err
	}
	var resp nvdResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("nvd: parse: %w", err)
	}

	out := make([]RawItem, 0, len(resp.Vulnerabilities))
	for _, w := range resp.Vulnerabilities {
		v := w.CVE
		desc := pickEnglishDesc(v.Descriptions)
		published, _ := time.Parse("2006-01-02T15:04:05.000", v.Published)
		score, sev := pickCVSS(v.Metrics)

		title := fmt.Sprintf("%s — %s", v.ID, truncateTo(desc, 100))
		if score > 0 {
			title = fmt.Sprintf("[CVSS %.1f %s] %s — %s",
				score, sev, v.ID, truncateTo(desc, 80))
		}

		hints := []string{}
		if score >= 9.0 {
			hints = append(hints, "critical-cvss")
		}
		if classifyByDescription(desc, &hints) {
			// hints already appended
		}

		vendors := pickVendors(v.Configurations)

		out = append(out, RawItem{
			Source:     n.cfg.ID,
			SourceName: n.cfg.Name,
			Category:   n.cfg.Category,
			Weight:     n.cfg.Weight,
			Title:      title,
			URL:        "https://nvd.nist.gov/vuln/detail/" + v.ID,
			Summary:    desc,
			Published:  published.UTC(),
			CVEs:       []string{v.ID},
			Vendors:    vendors,
			Hints:      hints,
		})
	}
	return out, nil
}

func (n *NVD) get(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	if n.ua != "" {
		req.Header.Set("User-Agent", n.ua)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := n.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("nvd: GET %s: status %d", url, resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 64*1024*1024))
}

func pickEnglishDesc(ds []nvdDesc) string {
	for _, d := range ds {
		if d.Lang == "en" {
			return d.Value
		}
	}
	if len(ds) > 0 {
		return ds[0].Value
	}
	return ""
}

func pickCVSS(m nvdMetrics) (float64, string) {
	for _, v := range m.V31 {
		if v.CvssData.BaseScore > 0 {
			sev := v.CvssData.BaseSeverity
			if sev == "" {
				sev = v.BaseSeverity
			}
			return v.CvssData.BaseScore, sev
		}
	}
	for _, v := range m.V30 {
		if v.CvssData.BaseScore > 0 {
			sev := v.CvssData.BaseSeverity
			if sev == "" {
				sev = v.BaseSeverity
			}
			return v.CvssData.BaseScore, sev
		}
	}
	for _, v := range m.V2 {
		if v.CvssData.BaseScore > 0 {
			return v.CvssData.BaseScore, v.BaseSeverity
		}
	}
	return 0, ""
}

func pickVendors(cfgs []nvdConfig) []string {
	seen := map[string]struct{}{}
	out := []string{}
	for _, c := range cfgs {
		for _, n := range c.Nodes {
			for _, m := range n.CPEMatch {
				if v := vendorFromCPE(m.Criteria); v != "" {
					if _, ok := seen[v]; !ok {
						seen[v] = struct{}{}
						out = append(out, v)
					}
				}
			}
		}
		if len(out) >= 4 {
			break
		}
	}
	return out
}

// vendorFromCPE extracts the vendor field from a CPE 2.3 string:
//   cpe:2.3:a:vendor:product:...
func vendorFromCPE(cpe string) string {
	parts := strings.Split(cpe, ":")
	if len(parts) >= 4 {
		return strings.ToLower(parts[3])
	}
	return ""
}

func truncateTo(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// classifyByDescription scans a CVE description for common attack-class words
// and appends matching hints. Returns true if any hint was added.
func classifyByDescription(desc string, hints *[]string) bool {
	d := strings.ToLower(desc)
	added := false
	matchers := []struct {
		needle string
		hint   string
	}{
		{"remote code execution", "rce"},
		{"arbitrary code", "rce"},
		{"command injection", "rce"},
		{"sql injection", "sqli"},
		{"cross-site scripting", "xss"},
		{"authentication bypass", "auth-bypass"},
		{"privilege escalation", "lpe"},
		{"path traversal", "path-traversal"},
		{"directory traversal", "path-traversal"},
		{"deserialization", "deserialization"},
		{"actively exploited", "actively-exploited"},
		{"in the wild", "actively-exploited"},
		{"zero-day", "0day"},
		{"0-day", "0day"},
		{"supply chain", "supply-chain"},
	}
	for _, m := range matchers {
		if strings.Contains(d, m.needle) {
			*hints = append(*hints, m.hint)
			added = true
		}
	}
	return added
}

// normalizeVendor lowercases and strips common decorations from a vendor name
// (KEV's "Microsoft Corporation" → "microsoft", "Cisco Systems Inc." → "cisco").
func normalizeVendor(v string) string {
	v = strings.ToLower(v)
	v = strings.TrimSpace(v)
	for _, suffix := range []string{
		" corporation", " corp", " inc.", " inc", " llc", " ltd", " gmbh",
		" systems", " software", " technologies", " communications",
	} {
		v = strings.TrimSuffix(v, suffix)
	}
	if i := strings.Index(v, " "); i != -1 {
		v = v[:i]
	}
	return v
}
