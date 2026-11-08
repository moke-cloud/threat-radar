// Package jatrans adds Japanese titles / summaries to items with a local
// LLM served by llama.cpp's OpenAI-compatible llama-server (no API key, the
// text never leaves the machine running the collector).
//
// Translations are kept in data/translations.json keyed by item ID plus a
// hash of the source text, and applied whenever the index is rebuilt. Items
// already in Japanese are skipped.
package jatrans

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"regexp"
	"unicode"

	"github.com/moke-cloud/SHIGOTOBA/threat-radar/collector/normalize"
)

// Entry is one cached translation.
type Entry struct {
	Hash    string `json:"hash"`
	Title   string `json:"title,omitempty"`
	Summary string `json:"summary,omitempty"`
}

// Cache maps item ID to its translation.
type Cache map[string]Entry

// SummaryMax caps how much of a summary is sent (and shown) per item.
const SummaryMax = 450

func isJapaneseRune(r rune) bool {
	return unicode.In(r, unicode.Hiragana, unicode.Katakana, unicode.Han)
}

func hasJapanese(s string) bool {
	for _, r := range s {
		if isJapaneseRune(r) {
			return true
		}
	}
	return false
}

// NeedsTranslation reports whether the item has text and none of it is Japanese.
func NeedsTranslation(it normalize.Item) bool {
	text := it.Title + it.Summary
	return text != "" && !hasJapanese(text)
}

// SourceHash identifies the text a translation was made from.
func SourceHash(it normalize.Item) string {
	sum := sha256.Sum256([]byte(it.Title + "\x00" + it.Summary))
	return hex.EncodeToString(sum[:8])
}

// Missing returns the items that need a (new) translation, in input order.
func Missing(items []normalize.Item, c Cache) []normalize.Item {
	var out []normalize.Item
	for _, it := range items {
		if !NeedsTranslation(it) {
			continue
		}
		if e, ok := c[it.ID]; ok && e.Hash == SourceHash(it) {
			continue
		}
		out = append(out, it)
	}
	return out
}

// Apply returns a copy of items with TitleJa / SummaryJa filled from c.
func Apply(items []normalize.Item, c Cache) []normalize.Item {
	out := make([]normalize.Item, len(items))
	for i, it := range items {
		if e, ok := c[it.ID]; ok && e.Hash == SourceHash(it) && NeedsTranslation(it) {
			it.TitleJa = e.Title
			it.SummaryJa = e.Summary
		}
		out[i] = it
	}
	return out
}

// Merge returns a new cache with add layered over c.
func Merge(c, add Cache) Cache {
	out := make(Cache, len(c)+len(add))
	for k, v := range c {
		out[k] = v
	}
	for k, v := range add {
		out[k] = v
	}
	return out
}

// Prune keeps only entries for the given items.
func Prune(c Cache, items []normalize.Item) Cache {
	out := Cache{}
	for _, it := range items {
		if e, ok := c[it.ID]; ok {
			out[it.ID] = e
		}
	}
	return out
}

// Load reads a cache file; a missing file is an empty cache.
func Load(path string) (Cache, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return Cache{}, nil
	}
	if err != nil {
		return Cache{}, err
	}
	var c Cache
	if err := json.Unmarshal(data, &c); err != nil {
		return Cache{}, err
	}
	if c == nil {
		c = Cache{}
	}
	return c, nil
}

// Save writes the cache atomically.
func Save(path string, c Cache) error {
	data, err := json.MarshalIndent(c, "", " ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// prefixRE matches leading identifiers that must stay verbatim:
// "[CVSS 9.1 CRITICAL] CVE-2026-1234 — ", "[KEV] CVE-… — ", "ZDI-26-833: ".
var prefixRE = regexp.MustCompile(`^(?:\[[^\]]{1,40}\]\s*)?(?:(?:CVE-\d{4}-\d{4,}|ZDI-\d{2}-\d+|GHSA-[\w-]+)(?:\s*[—:–-]\s*|\s+))?`)

// SplitProtected separates a verbatim prefix from the translatable text.
func SplitProtected(s string) (keep, text string) {
	keep = prefixRE.FindString(s)
	return keep, s[len(keep):]
}

var cveRE = regexp.MustCompile(`CVE-\d{4}-\d{4,7}`)

// validTranslation rejects output that is not Japanese, drops a CVE ID that
// the source had, or is far longer than the source (runaway / injected text).
func validTranslation(src, ja string) bool {
	if src == "" {
		return ja == ""
	}
	if !hasJapanese(ja) {
		return false
	}
	for _, id := range cveRE.FindAllString(src, -1) {
		if !regexp.MustCompile(regexp.QuoteMeta(id) + `\b`).MatchString(ja) {
			return false
		}
	}
	limit := len([]rune(src))*2 + 80
	return len([]rune(ja)) <= limit
}

// clip shortens s to at most max runes, preferring a word boundary.
func clip(s string, max int) string {
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	cut := r[:max]
	for i := len(cut) - 1; i > max*6/10; i-- {
		if cut[i] == ' ' {
			return string(cut[:i]) + "…"
		}
	}
	return string(cut) + "…"
}

// sanitize strips control characters (except newline) from model output.
func sanitize(s string) string {
	out := make([]rune, 0, len(s))
	for _, r := range s {
		if r == '\n' || !unicode.IsControl(r) {
			out = append(out, r)
		}
	}
	return string(out)
}
