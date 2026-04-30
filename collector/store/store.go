// Package store writes Items to the on-disk layout consumed by the static UI.
//
// Layout:
//
//	data/items/YYYY-MM-DD.ndjson   — newline-delimited Items written today
//	data/index.json                — most recent N items merged across all days
//	data/critical.json             — severity in {critical, high} for the alert wall
//	data/stats.json                — counts by source / severity / day
package store

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/moke-cloud/SHIGOTOBA/threat-radar/collector/normalize"
)

// Store writes Items to <root>/items/, <root>/index.json, etc.
type Store struct {
	Root         string
	IndexMaxItems int
}

// New constructs a Store rooted at the given directory.
func New(root string, indexMaxItems int) *Store {
	if indexMaxItems <= 0 {
		indexMaxItems = 500
	}
	return &Store{Root: root, IndexMaxItems: indexMaxItems}
}

// LoadSeenIDs reads the past N days of NDJSON files and returns a set of
// already-seen item IDs. Used by enrich.Dedupe.
func (s *Store) LoadSeenIDs(days int) (map[string]struct{}, error) {
	seen := map[string]struct{}{}
	for i := 0; i < days; i++ {
		day := time.Now().UTC().AddDate(0, 0, -i).Format("2006-01-02")
		path := filepath.Join(s.Root, "items", day+".ndjson")
		f, err := os.Open(path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return seen, err
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 64*1024), 4*1024*1024)
		for sc.Scan() {
			line := sc.Bytes()
			var it normalize.Item
			if err := json.Unmarshal(line, &it); err != nil {
				continue
			}
			seen[it.ID] = struct{}{}
		}
		_ = f.Close()
	}
	return seen, nil
}

// AppendDaily appends today's items to data/items/YYYY-MM-DD.ndjson.
func (s *Store) AppendDaily(items []normalize.Item) error {
	if len(items) == 0 {
		return nil
	}
	day := time.Now().UTC().Format("2006-01-02")
	dir := filepath.Join(s.Root, "items")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	path := filepath.Join(dir, day+".ndjson")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	w := bufio.NewWriter(f)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	for _, it := range items {
		if err := enc.Encode(it); err != nil {
			return err
		}
	}
	return w.Flush()
}

// RebuildIndex reads the past M days of NDJSON, merges them with the new items,
// sorts by published-date desc and writes data/index.json (capped at
// IndexMaxItems) plus data/critical.json (severity in {critical, high}).
func (s *Store) RebuildIndex(daysBack int) error {
	if daysBack <= 0 {
		daysBack = 14
	}
	all := []normalize.Item{}
	for i := 0; i < daysBack; i++ {
		day := time.Now().UTC().AddDate(0, 0, -i).Format("2006-01-02")
		path := filepath.Join(s.Root, "items", day+".ndjson")
		f, err := os.Open(path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return err
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 64*1024), 4*1024*1024)
		for sc.Scan() {
			var it normalize.Item
			if err := json.Unmarshal(sc.Bytes(), &it); err != nil {
				continue
			}
			all = append(all, it)
		}
		_ = f.Close()
	}

	// Most recent first by published-date (zero published goes to end).
	sort.SliceStable(all, func(i, j int) bool {
		ai, aj := all[i].Published, all[j].Published
		if ai.IsZero() {
			return false
		}
		if aj.IsZero() {
			return true
		}
		return ai.After(aj)
	})

	if len(all) > s.IndexMaxItems {
		all = all[:s.IndexMaxItems]
	}
	if err := s.writeJSON("index.json", all); err != nil {
		return err
	}

	critical := make([]normalize.Item, 0, 64)
	for _, it := range all {
		if it.Severity == "critical" || it.Severity == "high" {
			critical = append(critical, it)
		}
	}
	if err := s.writeJSON("critical.json", critical); err != nil {
		return err
	}

	stats := buildStats(all)
	if err := s.writeJSON("stats.json", stats); err != nil {
		return err
	}
	return nil
}

// PurgeOlderThan deletes data/items/YYYY-MM-DD.ndjson older than `days`.
func (s *Store) PurgeOlderThan(days int) error {
	if days <= 0 {
		return nil
	}
	dir := filepath.Join(s.Root, "items")
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	cutoff := time.Now().UTC().AddDate(0, 0, -days)
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".ndjson") {
			continue
		}
		dayStr := strings.TrimSuffix(name, ".ndjson")
		t, err := time.Parse("2006-01-02", dayStr)
		if err != nil {
			continue
		}
		if t.Before(cutoff) {
			_ = os.Remove(filepath.Join(dir, name))
		}
	}
	return nil
}

// Stats is the aggregate written to data/stats.json.
type Stats struct {
	GeneratedAt   string         `json:"generated_at"`
	TotalItems    int            `json:"total_items"`
	BySeverity    map[string]int `json:"by_severity"`
	BySource      map[string]int `json:"by_source"`
	ByCategory    map[string]int `json:"by_category"`
	TopVendors    []KV           `json:"top_vendors"`
	TopTags       []KV           `json:"top_tags"`
	Last24hCount  int            `json:"last_24h_count"`
	CriticalLast7d int           `json:"critical_last_7d"`
}

// KV is a key/count pair used in top-N stats.
type KV struct {
	Key   string `json:"key"`
	Count int    `json:"count"`
}

func buildStats(all []normalize.Item) Stats {
	now := time.Now().UTC()
	s := Stats{
		GeneratedAt: now.Format(time.RFC3339),
		TotalItems:  len(all),
		BySeverity:  map[string]int{},
		BySource:    map[string]int{},
		ByCategory:  map[string]int{},
	}
	vendors := map[string]int{}
	tags := map[string]int{}
	for _, it := range all {
		s.BySeverity[it.Severity]++
		s.BySource[it.Source]++
		s.ByCategory[it.Category]++
		for _, v := range it.Vendors {
			vendors[v]++
		}
		for _, t := range it.Tags {
			tags[t]++
		}
		if !it.Published.IsZero() && now.Sub(it.Published) <= 24*time.Hour {
			s.Last24hCount++
		}
		if it.Severity == "critical" && !it.Published.IsZero() && now.Sub(it.Published) <= 7*24*time.Hour {
			s.CriticalLast7d++
		}
	}
	s.TopVendors = topN(vendors, 10)
	s.TopTags = topN(tags, 15)
	return s
}

func topN(m map[string]int, n int) []KV {
	out := make([]KV, 0, len(m))
	for k, v := range m {
		out = append(out, KV{Key: k, Count: v})
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Key < out[j].Key
	})
	if len(out) > n {
		out = out[:n]
	}
	return out
}

func (s *Store) writeJSON(name string, body any) error {
	if err := os.MkdirAll(s.Root, 0o755); err != nil {
		return err
	}
	tmp := filepath.Join(s.Root, name+".tmp")
	final := filepath.Join(s.Root, name)
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(body); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, final); err != nil {
		return fmt.Errorf("rename %s → %s: %w", tmp, final, err)
	}
	return nil
}
