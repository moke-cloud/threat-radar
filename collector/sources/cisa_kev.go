package sources

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// CISAKEV is the adapter for the CISA Known Exploited Vulnerabilities feed.
// Format reference: https://www.cisa.gov/known-exploited-vulnerabilities
type CISAKEV struct {
	cfg    Config
	client *http.Client
	ua     string
}

// NewCISAKEV constructs the CISA KEV adapter.
func NewCISAKEV(c Config, h HTTPClientConfig) *CISAKEV {
	return &CISAKEV{cfg: c, client: NewHTTPClient(h), ua: h.UserAgent}
}

// ID returns the source ID.
func (c *CISAKEV) ID() string { return c.cfg.ID }

// kevFeed mirrors the JSON shape of the CISA KEV feed (subset).
type kevFeed struct {
	Title          string         `json:"title"`
	CatalogVersion string         `json:"catalogVersion"`
	DateReleased   string         `json:"dateReleased"`
	Count          int            `json:"count"`
	Vulnerabilities []kevVuln     `json:"vulnerabilities"`
}

type kevVuln struct {
	CveID                      string `json:"cveID"`
	VendorProject              string `json:"vendorProject"`
	Product                    string `json:"product"`
	VulnerabilityName          string `json:"vulnerabilityName"`
	DateAdded                  string `json:"dateAdded"`
	ShortDescription           string `json:"shortDescription"`
	RequiredAction             string `json:"requiredAction"`
	DueDate                    string `json:"dueDate"`
	KnownRansomwareCampaignUse string `json:"knownRansomwareCampaignUse"`
	Notes                      string `json:"notes"`
	CWEs                       []string `json:"cwes"`
}

// Fetch downloads the KEV JSON and converts each vulnerability into a RawItem.
func (c *CISAKEV) Fetch(ctx context.Context) ([]RawItem, error) {
	body, err := c.get(ctx, c.cfg.URL)
	if err != nil {
		return nil, err
	}
	var feed kevFeed
	if err := json.Unmarshal(body, &feed); err != nil {
		return nil, fmt.Errorf("kev: parse: %w", err)
	}
	out := make([]RawItem, 0, len(feed.Vulnerabilities))
	for _, v := range feed.Vulnerabilities {
		published := parseKEVDate(v.DateAdded)
		hints := []string{"kev", "actively-exploited"}
		if v.KnownRansomwareCampaignUse == "Known" {
			hints = append(hints, "ransomware")
		}
		title := fmt.Sprintf("[KEV] %s — %s %s: %s",
			v.CveID, v.VendorProject, v.Product, v.VulnerabilityName)
		summary := v.ShortDescription
		if v.RequiredAction != "" {
			summary += "\nRequired: " + v.RequiredAction
		}
		if v.DueDate != "" {
			summary += "\nDue: " + v.DueDate
		}
		out = append(out, RawItem{
			Source:     c.cfg.ID,
			SourceName: c.cfg.Name,
			Category:   c.cfg.Category,
			Weight:     c.cfg.Weight,
			Title:      title,
			URL:        "https://nvd.nist.gov/vuln/detail/" + v.CveID,
			Summary:    summary,
			Published:  published,
			Vendors:    []string{normalizeVendor(v.VendorProject)},
			CVEs:       []string{v.CveID},
			Hints:      hints,
		})
	}
	return out, nil
}

func (c *CISAKEV) get(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	if c.ua != "" {
		req.Header.Set("User-Agent", c.ua)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("kev: GET %s: status %d", url, resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 32*1024*1024))
}

// parseKEVDate parses CISA's YYYY-MM-DD format. Empty/garbage → zero time.
func parseKEVDate(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	if t, err := time.Parse("2006-01-02", s); err == nil {
		return t.UTC()
	}
	return time.Time{}
}
