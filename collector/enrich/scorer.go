package enrich

import (
	"strings"
	"time"

	"github.com/moke-cloud/SHIGOTOBA/threat-radar/collector/normalize"
)

// ScoreOptions tunes the deterministic scorer.
type ScoreOptions struct {
	WatchVendors []string
	WatchTags    []string
	Now          time.Time // override for tests; defaults to time.Now() if zero
}

// Score computes a 0-100 threat score and assigns the severity label.
//
// The score blends:
//
//   - The source's configured weight (1.0 → +30, 1.5 → +45)
//   - Hints from the source adapter (kev / actively-exploited / 0day)
//   - Heuristic tags (rce / auth-bypass / supply-chain)
//   - CVSS extracted from KEV / NVD pre-tagged hints
//   - Watch-list matches (vendor or tag)
//   - Age decay (older than 7 days subtracts 15)
func Score(it *normalize.Item, opt ScoreOptions) {
	score := 0
	if hasAny(it.Tags, []string{"critical-cvss"}) {
		score += 15
	}

	score += scoreFromSourceID(it.Source)

	if hasAny(it.Tags, []string{"actively-exploited", "kev", "0day"}) {
		score += 30
	}
	if hasAny(it.Tags, []string{"rce", "auth-bypass", "supply-chain"}) {
		score += 20
	}
	if hasAny(it.Tags, []string{"ransomware", "breach"}) {
		score += 15
	}
	if hasAny(it.Tags, []string{"sqli", "xss", "lpe", "path-traversal"}) {
		score += 8
	}

	for _, v := range it.Vendors {
		if containsLower(opt.WatchVendors, v) {
			score += 10
			break
		}
	}
	for _, t := range it.Tags {
		if containsLower(opt.WatchTags, t) {
			score += 10
			break
		}
	}

	now := opt.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if !it.Published.IsZero() && now.Sub(it.Published) > 7*24*time.Hour {
		if !hasAny(it.Tags, []string{"actively-exploited", "kev"}) {
			score -= 15
		}
	}

	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}
	it.Score = score

	switch {
	case score >= 80:
		it.Severity = "critical"
	case score >= 60:
		it.Severity = "high"
	case score >= 30:
		it.Severity = "medium"
	case score >= 10:
		it.Severity = "low"
	default:
		it.Severity = "info"
	}
}

// scoreFromSourceID maps known source IDs to a base contribution. Falls back
// to 21 (≈ weight 0.7) for unrecognised sources.
func scoreFromSourceID(sourceID string) int {
	switch sourceID {
	case "cisa-kev":
		return 45
	case "cisa-advisories", "msrc", "jpcert-at", "ipa-alert":
		return 36
	case "nvd-recent", "krebs", "sans-isc", "project-zero":
		return 30
	case "bleeping", "google-security":
		return 27
	case "thehackernews", "schneier", "jpcert-wr":
		return 18
	}
	return 21
}

func hasAny(haystack, needles []string) bool {
	for _, n := range needles {
		for _, h := range haystack {
			if h == n {
				return true
			}
		}
	}
	return false
}

func containsLower(list []string, target string) bool {
	t := strings.ToLower(target)
	for _, x := range list {
		if strings.ToLower(x) == t {
			return true
		}
	}
	return false
}
