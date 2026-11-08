package store

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/moke-cloud/SHIGOTOBA/threat-radar/collector/normalize"
)

func items(src string, n int) []normalize.Item {
	out := make([]normalize.Item, n)
	for i := range out {
		out[i] = normalize.Item{ID: src + string(rune('a'+i)), Source: src}
	}
	return out
}

func TestSelectIndexPerSourceLimitAndAllowed(t *testing.T) {
	in := append(append(items("nvd", 5), items("kev", 3)...), items("gone", 2)...)
	opt := IndexOptions{
		Allowed:   map[string]struct{}{"nvd": {}, "kev": {}},
		PerSource: map[string]int{"nvd": 2},
	}
	got := SelectIndex(in, 10, opt)
	counts := map[string]int{}
	for _, it := range got {
		counts[it.Source]++
	}
	if counts["nvd"] != 2 || counts["kev"] != 3 || counts["gone"] != 0 {
		t.Fatalf("counts %v", counts)
	}
}

func TestSelectIndexMaxAndNilOptions(t *testing.T) {
	got := SelectIndex(items("a", 5), 3, IndexOptions{})
	if len(got) != 3 {
		t.Fatalf("len=%d", len(got))
	}
}

func TestRebuildIndexAppliesOptions(t *testing.T) {
	dir := t.TempDir()
	s := New(dir, 10)
	now := time.Now().UTC()
	all := append(items("nvd", 4), items("old", 2)...)
	for i := range all {
		all[i].Published = now.Add(-time.Duration(i) * time.Minute)
	}
	if err := s.AppendDaily(all); err != nil {
		t.Fatal(err)
	}
	opt := IndexOptions{Allowed: map[string]struct{}{"nvd": {}}, PerSource: map[string]int{"nvd": 3}}
	if err := s.RebuildIndex(2, opt); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(dir, "index.json"))
	if err != nil {
		t.Fatal(err)
	}
	var got []normalize.Item
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("index len=%d", len(got))
	}
}

func TestSelectIndexDropsDuplicateIDs(t *testing.T) {
	in := []normalize.Item{
		{ID: "x", Source: "zdi", Title: "newer copy"},
		{ID: "x", Source: "zdi", Title: "older copy"},
		{ID: "y", Source: "zdi"},
	}
	got := SelectIndex(in, 10, IndexOptions{PerSource: map[string]int{"zdi": 2}})
	if len(got) != 2 || got[0].Title != "newer copy" || got[1].ID != "y" {
		t.Fatalf("got %+v", got)
	}
}
