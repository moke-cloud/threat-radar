package store

import "github.com/moke-cloud/SHIGOTOBA/threat-radar/collector/normalize"

// IndexOptions shapes data/index.json.
type IndexOptions struct {
	// Allowed lists the configured source IDs. Items from sources removed
	// from config.yaml drop out of the index at once. Nil keeps everything.
	Allowed map[string]struct{}
	// PerSource caps how many items one source may contribute, so a
	// high-volume feed such as NVD cannot crowd out the rest.
	PerSource map[string]int
}

// SelectIndex walks sorted (newest first) and returns a new slice of at most
// max items that respects opt. Duplicate IDs keep only the first copy.
func SelectIndex(sorted []normalize.Item, max int, opt IndexOptions) []normalize.Item {
	out := make([]normalize.Item, 0, min(max, len(sorted)))
	used := map[string]int{}
	ids := map[string]struct{}{}
	for _, it := range sorted {
		if len(out) >= max {
			break
		}
		// An item re-collected on a later day (e.g. before the seen window
		// covered it) must not appear twice; the first, newest copy wins.
		if _, dup := ids[it.ID]; dup {
			continue
		}
		if opt.Allowed != nil {
			if _, ok := opt.Allowed[it.Source]; !ok {
				continue
			}
		}
		if limit, ok := opt.PerSource[it.Source]; ok && limit > 0 && used[it.Source] >= limit {
			continue
		}
		ids[it.ID] = struct{}{}
		used[it.Source]++
		out = append(out, it)
	}
	return out
}
