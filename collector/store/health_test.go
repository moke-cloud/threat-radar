package store

import (
	"strings"
	"testing"
	"time"
)

var t0 = time.Date(2026, 11, 5, 1, 0, 0, 0, time.UTC)

func TestMergeHealthCarriesLastOKOnFailure(t *testing.T) {
	prev := []SourceStatus{{ID: "a", OK: true, LastOKAt: t0.Add(-24 * time.Hour), LastItemAt: t0.Add(-48 * time.Hour)}}
	cur := []SourceStatus{{ID: "a", OK: false, Error: "status 403", CheckedAt: t0}}
	got := MergeHealth(prev, cur, set("a"))
	if got[0].LastOKAt != prev[0].LastOKAt || got[0].LastItemAt != prev[0].LastItemAt || got[0].OK {
		t.Fatalf("got %+v", got[0])
	}
	if cur[0].LastOKAt.IsZero() == false {
		t.Fatal("input mutated")
	}
}

func TestMergeHealthSuccessSetsLastOK(t *testing.T) {
	prev := []SourceStatus{{ID: "a", LastItemAt: t0.Add(-72 * time.Hour)}}
	cur := []SourceStatus{{ID: "a", OK: true, CheckedAt: t0, LastItemAt: t0.Add(-1 * time.Hour)}}
	got := MergeHealth(prev, cur, set("a"))
	if got[0].LastOKAt != t0 || got[0].LastItemAt != t0.Add(-1*time.Hour) {
		t.Fatalf("got %+v", got[0])
	}
}

func TestMergeHealthKeepsNewerLastItem(t *testing.T) {
	prev := []SourceStatus{{ID: "a", LastItemAt: t0}}
	cur := []SourceStatus{{ID: "a", OK: true, CheckedAt: t0, LastItemAt: t0.Add(-time.Hour)}}
	if got := MergeHealth(prev, cur, set("a")); got[0].LastItemAt != t0 {
		t.Fatalf("got %v", got[0].LastItemAt)
	}
}

func TestMergeHealthDropsRemovedSources(t *testing.T) {
	prev := []SourceStatus{{ID: "gone"}}
	cur := []SourceStatus{{ID: "a", OK: true, CheckedAt: t0}}
	if got := MergeHealth(prev, cur, set("a")); len(got) != 1 || got[0].ID != "a" {
		t.Fatalf("got %+v", got)
	}
}

func TestMergeHealthKeepsConfiguredButNotRun(t *testing.T) {
	prev := []SourceStatus{{ID: "b", OK: true, LastOKAt: t0}}
	cur := []SourceStatus{{ID: "a", OK: true, CheckedAt: t0}}
	got := MergeHealth(prev, cur, set("a", "b"))
	if len(got) != 2 || got[1].ID != "b" || !got[1].OK {
		t.Fatalf("got %+v", got)
	}
}

func set(ids ...string) map[string]struct{} {
	m := map[string]struct{}{}
	for _, id := range ids {
		m[id] = struct{}{}
	}
	return m
}

func TestTruncateError(t *testing.T) {
	long := strings.Repeat("x", 500)
	if got := TruncateError(long); len([]rune(got)) != maxErrorRunes+1 {
		t.Fatalf("len=%d", len([]rune(got)))
	}
	if TruncateError("short") != "short" {
		t.Fatal("short changed")
	}
}

func TestHealthRoundTrip(t *testing.T) {
	s := New(t.TempDir(), 10)
	if got, err := s.LoadHealth(); err != nil || got != nil {
		t.Fatalf("empty load: %v %v", got, err)
	}
	in := []SourceStatus{{ID: "a", Name: "A", OK: true, Fetched: 3, CheckedAt: t0, LastOKAt: t0}}
	if err := s.WriteHealth(in, t0); err != nil {
		t.Fatal(err)
	}
	got, err := s.LoadHealth()
	if err != nil || len(got) != 1 || got[0].Fetched != 3 || !got[0].LastOKAt.Equal(t0) {
		t.Fatalf("got %+v err %v", got, err)
	}
}
