package enrich

import (
	"github.com/moke-cloud/SHIGOTOBA/threat-radar/collector/normalize"
)

// Dedupe removes items whose ID already appears in seen. The slice is
// rewritten in place; the returned slice has the duplicates dropped.
//
// Callers typically populate `seen` from the previous-day NDJSON before
// running the new collection so that retries / overlapping fetches do not
// produce duplicate entries in index.json.
func Dedupe(items []normalize.Item, seen map[string]struct{}) []normalize.Item {
	out := items[:0]
	for _, it := range items {
		if _, dup := seen[it.ID]; dup {
			continue
		}
		seen[it.ID] = struct{}{}
		out = append(out, it)
	}
	return out
}
