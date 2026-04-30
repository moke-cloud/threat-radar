package store

import (
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/moke-cloud/SHIGOTOBA/threat-radar/collector/normalize"
)

// FeedOptions tweaks one of the generated RSS feeds.
type FeedOptions struct {
	Title       string
	Description string
	SiteLink    string
	OutPath     string // file path to write
	MaxItems    int    // hard cap on items emitted
	Filter      func(normalize.Item) bool // include item iff returns true (nil = include all)
}

// WriteFeed renders items as an RSS 2.0 file at opts.OutPath. Atom-style
// namespaces are skipped to keep the output compatible with the broadest
// possible reader set (Outlook in particular).
//
// Fields per item:
//   - title       — "[SEVERITY] original title" (so triage by Subject works)
//   - link        — original article URL
//   - guid        — stable Item.ID (isPermaLink="false" so readers don't try to fetch it)
//   - pubDate     — published time in RFC1123Z (Outlook-friendly)
//   - description — Item.Summary
//   - category    — severity + tags + vendors (multiple <category> elements)
func WriteFeed(items []normalize.Item, opts FeedOptions) error {
	if opts.OutPath == "" {
		return fmt.Errorf("feed: OutPath required")
	}
	if opts.MaxItems <= 0 {
		opts.MaxItems = 100
	}

	picked := items[:0:0]
	for _, it := range items {
		if opts.Filter != nil && !opts.Filter(it) {
			continue
		}
		picked = append(picked, it)
	}
	sort.SliceStable(picked, func(i, j int) bool {
		return picked[i].Published.After(picked[j].Published)
	})
	if len(picked) > opts.MaxItems {
		picked = picked[:opts.MaxItems]
	}

	rssItems := make([]rssItem, 0, len(picked))
	for _, it := range picked {
		categories := make([]string, 0, 1+len(it.Tags)+len(it.Vendors))
		if it.Severity != "" {
			categories = append(categories, it.Severity)
		}
		categories = append(categories, it.Tags...)
		categories = append(categories, it.Vendors...)

		rssItems = append(rssItems, rssItem{
			Title: fmt.Sprintf("[%s] %s",
				strings.ToUpper(severityCode(it.Severity)),
				it.Title),
			Link:        it.URL,
			GUID:        rssGUID{IsPermaLink: "false", Value: it.ID},
			PubDate:     pubDate(it.Published),
			Description: it.Summary,
			Source:      sourceLink{Text: it.SourceName, URL: opts.SiteLink},
			Categories:  categories,
		})
	}

	feed := rss{
		Version: "2.0",
		Channel: rssChannel{
			Title:         opts.Title,
			Link:          opts.SiteLink,
			Description:   opts.Description,
			Language:      "en",
			LastBuildDate: pubDate(time.Now().UTC()),
			Items:         rssItems,
		},
	}

	if err := os.MkdirAll(filepath.Dir(opts.OutPath), 0o755); err != nil {
		return fmt.Errorf("feed: mkdir: %w", err)
	}
	tmp := opts.OutPath + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return fmt.Errorf("feed: create: %w", err)
	}
	if _, err := f.WriteString(xml.Header); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("feed: write header: %w", err)
	}
	enc := xml.NewEncoder(f)
	enc.Indent("", "  ")
	if err := enc.Encode(feed); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("feed: encode: %w", err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, opts.OutPath)
}

// severityCode returns a short uppercase string for the Subject prefix.
func severityCode(s string) string {
	switch s {
	case "critical":
		return "CRIT"
	case "high":
		return "HIGH"
	case "medium":
		return "MED"
	case "low":
		return "LOW"
	}
	return "INFO"
}

func pubDate(t time.Time) string {
	if t.IsZero() {
		t = time.Now().UTC()
	}
	return t.UTC().Format(time.RFC1123Z)
}

// --- RSS 2.0 wire format ---

type rss struct {
	XMLName xml.Name   `xml:"rss"`
	Version string     `xml:"version,attr"`
	Channel rssChannel `xml:"channel"`
}

type rssChannel struct {
	Title         string    `xml:"title"`
	Link          string    `xml:"link"`
	Description   string    `xml:"description"`
	Language      string    `xml:"language"`
	LastBuildDate string    `xml:"lastBuildDate"`
	Items         []rssItem `xml:"item"`
}

type rssItem struct {
	Title       string     `xml:"title"`
	Link        string     `xml:"link"`
	GUID        rssGUID    `xml:"guid"`
	PubDate     string     `xml:"pubDate"`
	Description string     `xml:"description"`
	Source      sourceLink `xml:"source"`
	Categories  []string   `xml:"category"`
}

type rssGUID struct {
	IsPermaLink string `xml:"isPermaLink,attr"`
	Value       string `xml:",chardata"`
}

type sourceLink struct {
	URL  string `xml:"url,attr"`
	Text string `xml:",chardata"`
}
