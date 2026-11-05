package sources

import (
	"bytes"
	"testing"
)

func TestStripInvalidXMLBytesRemovesControlChars(t *testing.T) {
	in := []byte("<a>ok\x0bbad\x00\x1fend\t\n\r</a>")
	got := stripInvalidXMLBytes(in)
	want := []byte("<a>okbadend\t\n\r</a>")
	if !bytes.Equal(got, want) {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestStripInvalidXMLBytesKeepsMultibyte(t *testing.T) {
	in := []byte("<a>注意喚起 \x82\xa0</a>") // UTF-8 plus Shift_JIS-like bytes
	if got := stripInvalidXMLBytes(in); !bytes.Equal(got, in) {
		t.Fatalf("multibyte bytes changed: %q", got)
	}
}

func TestStripInvalidXMLBytesDoesNotMutateInput(t *testing.T) {
	in := []byte("a\x0bb")
	_ = stripInvalidXMLBytes(in)
	if string(in) != "a\x0bb" {
		t.Fatalf("input mutated: %q", in)
	}
}

const rssWithVT = `<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0"><channel>
<item><title><![CDATA[First]]></title><link>https://example.com/1</link><pubDate>Wed, 04 Nov 2026 16:25:55 GMT</pubDate></item>
<item><title><![CDATA[Broken` + "\x0b" + ` title]]></title><link>https://example.com/2</link><pubDate>Wed, 04 Nov 2026 14:01:55 GMT</pubDate></item>
<item><title>Third</title><link>https://example.com/3</link><pubDate>Mon, 02 Nov 2026 11:04:08 GMT</pubDate></item>
</channel></rss>`

func TestParseFeedSurvivesControlChar(t *testing.T) {
	items := parseFeed([]byte(rssWithVT))
	if len(items) != 3 {
		t.Fatalf("want 3 items, got %d", len(items))
	}
	if items[1].Title != "Broken title" {
		t.Fatalf("title = %q", items[1].Title)
	}
	if items[2].Published.IsZero() {
		t.Fatal("pubDate not parsed")
	}
}

const atomFeedSample = `<?xml version="1.0" encoding="utf-8"?>
<feed xmlns="http://www.w3.org/2005/Atom">
<entry><title>A</title><link rel="alternate" href="https://example.com/a"/><published>2026-11-01T00:00:00Z</published><summary>s</summary></entry>
</feed>`

func TestParseFeedAtom(t *testing.T) {
	items := parseFeed([]byte(atomFeedSample))
	if len(items) != 1 || items[0].Link != "https://example.com/a" {
		t.Fatalf("atom parse failed: %+v", items)
	}
}

func TestParseFeedGarbage(t *testing.T) {
	if items := parseFeed([]byte("<html><body>not a feed</body></html>")); len(items) != 0 {
		t.Fatalf("want 0 items, got %d", len(items))
	}
}
