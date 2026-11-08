package main

import (
	"github.com/moke-cloud/SHIGOTOBA/threat-radar/collector/normalize"
	"github.com/moke-cloud/SHIGOTOBA/threat-radar/collector/sources"
)

// backfillFacts fills structured fields for items stored before they were
// collected. ZDI facts derive from the title / summary alone, so they can be
// recomputed for any stored item. It returns a new slice.
func backfillFacts(items []normalize.Item) []normalize.Item {
	out := make([]normalize.Item, len(items))
	for i, it := range items {
		if it.Product == "" && it.Attack == nil && len(it.CWEs) == 0 {
			if f := sources.ZDIFacts(it.Title, it.Summary); f.Product != "" {
				it.Product, it.Impact, it.CWEs, it.Attack = f.Product, f.Impact, f.CWEs, f.Attack
			}
		}
		out[i] = it
	}
	return out
}

// chainDecorators applies fns in order; nil entries are skipped.
func chainDecorators(fns ...func([]normalize.Item) []normalize.Item) func([]normalize.Item) []normalize.Item {
	return func(items []normalize.Item) []normalize.Item {
		for _, fn := range fns {
			if fn != nil {
				items = fn(items)
			}
		}
		return items
	}
}

// epssUnlessSkipped disables the EPSS lookup on -skip-fetch runs: there are
// no new CVEs, and a no-op lookup would mark the EPSS row freshly healthy.
func epssUnlessSkipped(cfg *appConfig, h sources.HTTPClientConfig, skipFetch bool) epssFunc {
	if skipFetch {
		return nil
	}
	return epssLookup(cfg, h)
}
