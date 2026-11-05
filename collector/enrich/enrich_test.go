package enrich

import (
	"testing"
	"time"

	"github.com/moke-cloud/SHIGOTOBA/threat-radar/collector/normalize"
)

var now = time.Date(2026, 11, 5, 0, 0, 0, 0, time.UTC)

func TestFilterRecentDropsOldKeepsUndated(t *testing.T) {
	in := []normalize.Item{
		{ID: "new", Published: now.Add(-24 * time.Hour)},
		{ID: "old", Published: now.AddDate(0, 0, -40)},
		{ID: "undated"},
	}
	got := FilterRecent(in, now.AddDate(0, 0, -30))
	if len(got) != 2 || got[0].ID != "new" || got[1].ID != "undated" {
		t.Fatalf("got %+v", got)
	}
	if len(in) != 3 {
		t.Fatal("input slice changed")
	}
}

func TestScoreUsesSourceWeight(t *testing.T) {
	low := normalize.Item{Source: "x", Published: now}
	high := normalize.Item{Source: "x", Published: now}
	Score(&low, ScoreOptions{Now: now, SourceWeight: 0.5})
	Score(&high, ScoreOptions{Now: now, SourceWeight: 1.5})
	if low.Score != 15 || high.Score != 45 {
		t.Fatalf("low=%d high=%d", low.Score, high.Score)
	}
}

func TestScoreDefaultsWeightWhenUnset(t *testing.T) {
	it := normalize.Item{Source: "x", Published: now}
	Score(&it, ScoreOptions{Now: now})
	if it.Score != 21 {
		t.Fatalf("score=%d", it.Score)
	}
}

func TestScoreEPSSBoost(t *testing.T) {
	cases := []struct {
		epss float64
		want int
	}{{0, 30}, {0.05, 30}, {0.1, 38}, {0.5, 45}, {0.97, 45}}
	for _, c := range cases {
		it := normalize.Item{Source: "x", Published: now, EPSS: c.epss}
		Score(&it, ScoreOptions{Now: now, SourceWeight: 1.0})
		if it.Score != c.want {
			t.Errorf("epss=%v score=%d want %d", c.epss, it.Score, c.want)
		}
	}
}

func TestScoreKEVIsCritical(t *testing.T) {
	it := normalize.Item{Source: "cisa-kev", Published: now, Tags: []string{"kev", "rce"}}
	Score(&it, ScoreOptions{Now: now, SourceWeight: 1.5})
	if it.Severity != "critical" {
		t.Fatalf("severity=%s score=%d", it.Severity, it.Score)
	}
}

func TestScoreAgeDecayAndClamp(t *testing.T) {
	it := normalize.Item{Source: "x", Published: now.AddDate(0, 0, -10)}
	Score(&it, ScoreOptions{Now: now, SourceWeight: 0.3})
	if it.Score != 0 || it.Severity != "info" {
		t.Fatalf("score=%d sev=%s", it.Score, it.Severity)
	}
}

func TestDedupeSkipsSeenAndRepeats(t *testing.T) {
	in := []normalize.Item{{ID: "a"}, {ID: "b"}, {ID: "a"}}
	got := Dedupe(in, map[string]struct{}{"b": {}})
	if len(got) != 1 || got[0].ID != "a" {
		t.Fatalf("got %+v", got)
	}
}
