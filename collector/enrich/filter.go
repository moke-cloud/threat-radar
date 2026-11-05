package enrich

import (
	"time"

	"github.com/moke-cloud/SHIGOTOBA/threat-radar/collector/normalize"
)

// FilterRecent returns a new slice holding the items published at or after
// cutoff. Items without a publish date are kept, since their age is unknown.
// Feeds such as the full CISA KEV catalog or long blog archives otherwise
// re-emit years-old entries every run.
func FilterRecent(items []normalize.Item, cutoff time.Time) []normalize.Item {
	out := make([]normalize.Item, 0, len(items))
	for _, it := range items {
		if !it.Published.IsZero() && it.Published.Before(cutoff) {
			continue
		}
		out = append(out, it)
	}
	return out
}
