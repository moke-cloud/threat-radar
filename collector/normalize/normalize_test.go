package normalize

import (
	"testing"
	"time"

	"github.com/moke-cloud/SHIGOTOBA/threat-radar/collector/sources"
)

func TestSafeURL(t *testing.T) {
	cases := map[string]string{
		"https://example.com/a":   "https://example.com/a",
		" http://example.com/b ":  "http://example.com/b",
		"HTTPS://EXAMPLE.com/c":   "HTTPS://EXAMPLE.com/c",
		"javascript:alert(1)":     "",
		"JaVaScRiPt:alert(1)":     "",
		"data:text/html,<script>": "",
		"//evil.example/x":        "",
		"/relative/path":          "",
		"":                        "",
		"https://":                "",
		"java\tscript:alert(1)":   "",
	}
	for in, want := range cases {
		if got := SafeURL(in); got != want {
			t.Errorf("SafeURL(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNormalizeBlanksUnsafeURL(t *testing.T) {
	it := Normalize(sources.RawItem{Source: "x", Title: "t", URL: "javascript:alert(1)"}, time.Now())
	if it.URL != "" {
		t.Fatalf("url = %q", it.URL)
	}
}
