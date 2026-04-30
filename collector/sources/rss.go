package sources

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// RSS is the generic adapter for RSS 2.0 / Atom 1.0 / RDF feeds.
//
// It tries each format in turn (RSS, Atom, RDF) and returns the first one
// that produces items.
type RSS struct {
	cfg    Config
	client *http.Client
	ua     string
}

// NewRSS constructs the generic RSS/Atom/RDF adapter.
func NewRSS(c Config, h HTTPClientConfig) *RSS {
	return &RSS{cfg: c, client: NewHTTPClient(h), ua: h.UserAgent}
}

// ID returns the source ID.
func (r *RSS) ID() string { return r.cfg.ID }

// Fetch downloads and parses the feed.
func (r *RSS) Fetch(ctx context.Context) ([]RawItem, error) {
	body, err := r.get(ctx, r.cfg.URL)
	if err != nil {
		return nil, err
	}

	// Try each format. Whichever yields items wins.
	if items := tryRSS(body); len(items) > 0 {
		return r.toRawItems(items), nil
	}
	if items := tryAtom(body); len(items) > 0 {
		return r.toRawItems(items), nil
	}
	if items := tryRDF(body); len(items) > 0 {
		return r.toRawItems(items), nil
	}
	return nil, errors.New("rss: no items recognised in feed")
}

func (r *RSS) get(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	if r.ua != "" {
		req.Header.Set("User-Agent", r.ua)
	}
	req.Header.Set("Accept", "application/rss+xml,application/atom+xml,application/xml,text/xml,*/*")
	resp, err := r.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("rss: GET %s: status %d", url, resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 16*1024*1024))
}

// genericItem is what we extract from any of the three formats.
type genericItem struct {
	Title     string
	Link      string
	Summary   string
	Published time.Time
}

// --- RSS 2.0 ---

type rss2 struct {
	Channel rss2Channel `xml:"channel"`
}
type rss2Channel struct {
	Items []rss2Item `xml:"item"`
}
type rss2Item struct {
	Title       string `xml:"title"`
	Link        string `xml:"link"`
	Description string `xml:"description"`
	PubDate     string `xml:"pubDate"`
	Content     string `xml:"http://purl.org/rss/1.0/modules/content/ encoded"`
}

func tryRSS(b []byte) []genericItem {
	var f rss2
	dec := xml.NewDecoder(strings.NewReader(string(b)))
	dec.Strict = false
	dec.CharsetReader = xmlCharsetReader
	if err := dec.Decode(&f); err != nil || f.Channel.Items == nil {
		return nil
	}
	out := make([]genericItem, 0, len(f.Channel.Items))
	for _, it := range f.Channel.Items {
		summary := stripHTML(it.Description)
		if summary == "" {
			summary = stripHTML(it.Content)
		}
		out = append(out, genericItem{
			Title:     stripHTML(it.Title),
			Link:      strings.TrimSpace(it.Link),
			Summary:   summary,
			Published: parseDate(it.PubDate),
		})
	}
	return out
}

// --- Atom 1.0 ---

type atomFeed struct {
	XMLName xml.Name   `xml:"http://www.w3.org/2005/Atom feed"`
	Entries []atomItem `xml:"entry"`
}
type atomItem struct {
	Title     string     `xml:"title"`
	Links     []atomLink `xml:"link"`
	Summary   string     `xml:"summary"`
	Content   string     `xml:"content"`
	Published string     `xml:"published"`
	Updated   string     `xml:"updated"`
}
type atomLink struct {
	Href string `xml:"href,attr"`
	Rel  string `xml:"rel,attr"`
}

func tryAtom(b []byte) []genericItem {
	var f atomFeed
	dec := xml.NewDecoder(strings.NewReader(string(b)))
	dec.Strict = false
	dec.CharsetReader = xmlCharsetReader
	if err := dec.Decode(&f); err != nil || len(f.Entries) == 0 {
		return nil
	}
	out := make([]genericItem, 0, len(f.Entries))
	for _, e := range f.Entries {
		link := ""
		for _, l := range e.Links {
			if l.Rel == "" || l.Rel == "alternate" {
				link = l.Href
				break
			}
		}
		date := e.Published
		if date == "" {
			date = e.Updated
		}
		summary := stripHTML(e.Summary)
		if summary == "" {
			summary = stripHTML(e.Content)
		}
		out = append(out, genericItem{
			Title:     stripHTML(e.Title),
			Link:      strings.TrimSpace(link),
			Summary:   summary,
			Published: parseDate(date),
		})
	}
	return out
}

// --- RDF / RSS 1.0 ---

type rdfFeed struct {
	Items []rdfItem `xml:"http://purl.org/rss/1.0/ item"`
}
type rdfItem struct {
	Title       string `xml:"http://purl.org/rss/1.0/ title"`
	Link        string `xml:"http://purl.org/rss/1.0/ link"`
	Description string `xml:"http://purl.org/rss/1.0/ description"`
	Date        string `xml:"http://purl.org/dc/elements/1.1/ date"`
}

func tryRDF(b []byte) []genericItem {
	var f rdfFeed
	dec := xml.NewDecoder(strings.NewReader(string(b)))
	dec.Strict = false
	dec.CharsetReader = xmlCharsetReader
	if err := dec.Decode(&f); err != nil || len(f.Items) == 0 {
		return nil
	}
	out := make([]genericItem, 0, len(f.Items))
	for _, it := range f.Items {
		out = append(out, genericItem{
			Title:     stripHTML(it.Title),
			Link:      strings.TrimSpace(it.Link),
			Summary:   stripHTML(it.Description),
			Published: parseDate(it.Date),
		})
	}
	return out
}

// --- Helpers ---

func (r *RSS) toRawItems(g []genericItem) []RawItem {
	out := make([]RawItem, 0, len(g))
	for _, it := range g {
		if it.Title == "" || it.Link == "" {
			continue
		}
		summary := it.Summary
		if len(summary) > 600 {
			summary = summary[:600] + "..."
		}
		out = append(out, RawItem{
			Source:     r.cfg.ID,
			SourceName: r.cfg.Name,
			Category:   r.cfg.Category,
			Weight:     r.cfg.Weight,
			Title:      it.Title,
			URL:        it.Link,
			Summary:    summary,
			Published:  it.Published,
		})
	}
	return out
}

var (
	htmlTagRE = regexp.MustCompile(`<[^>]*>`)
	wsRE      = regexp.MustCompile(`\s+`)
)

// stripHTML removes tags and collapses whitespace. It is intentionally simple —
// we only need readable summaries, not perfect HTML parsing.
func stripHTML(s string) string {
	s = htmlTagRE.ReplaceAllString(s, "")
	s = htmlEntityReplacer.Replace(s)
	s = wsRE.ReplaceAllString(s, " ")
	return strings.TrimSpace(s)
}

var htmlEntityReplacer = strings.NewReplacer(
	"&amp;", "&", "&lt;", "<", "&gt;", ">",
	"&quot;", `"`, "&apos;", "'", "&#39;", "'",
	"&nbsp;", " ", "&mdash;", "—", "&ndash;", "–",
	"&hellip;", "…", "&laquo;", "«", "&raquo;", "»",
)

// parseDate tries every plausible feed date format and returns zero time on failure.
func parseDate(s string) time.Time {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}
	}
	for _, layout := range []string{
		time.RFC1123Z, time.RFC1123,
		time.RFC3339, time.RFC3339Nano,
		"2006-01-02T15:04:05Z",
		"2006-01-02T15:04:05-07:00",
		"Mon, 2 Jan 2006 15:04:05 -0700",
		"Mon, 02 Jan 2006 15:04:05 -0700",
		"Mon, 02 Jan 2006 15:04:05 MST",
		"2006-01-02 15:04:05",
		"2006-01-02",
	} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC()
		}
	}
	return time.Time{}
}

// xmlCharsetReader returns the input unchanged when it is already UTF-8, and
// otherwise asks the standard library to handle the encoding. We don't depend
// on golang.org/x/text/encoding here because nearly every modern feed is UTF-8.
func xmlCharsetReader(charset string, input io.Reader) (io.Reader, error) {
	switch strings.ToLower(charset) {
	case "utf-8", "utf8", "":
		return input, nil
	}
	// Best-effort: pass through. xml.Decoder will report any real failure.
	return input, nil
}
