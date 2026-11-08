// ThreatRadar — pure filter / facet / URL-state helpers.
// Loaded in the browser as window.__filters and in Node tests via require().

(function (root) {
  const GROUPS = ["severity", "category", "source", "tag", "vendor"];
  const EMPTY_FILTERS = Object.freeze({ severity: "", category: "", source: "", tag: "", vendor: "" });
  const SORTS = ["published", "score", "epss"];

  // Older collector runs could write the same item twice; keep the first.
  function dedupeById(items) {
    const seen = new Set();
    const out = [];
    for (const it of items || []) {
      if (!it || seen.has(it.id)) continue;
      seen.add(it.id);
      out.push(it);
    }
    return out;
  }

  function haystack(it) {
    return [
      it.title, it.summary, it.source, it.source_name,
      ...(it.cves || []), ...(it.tags || []), ...(it.vendors || []),
    ].join(" ").toLowerCase();
  }

  function terms(search) {
    return String(search || "").toLowerCase().split(/\s+/).filter(Boolean);
  }

  function groupMatch(it, kind, value) {
    if (!value) return true;
    switch (kind) {
      case "severity": return (it.severity || "info") === value;
      case "category": return it.category === value;
      case "source":   return it.source === value;
      case "tag":      return (it.tags || []).includes(value);
      case "vendor":   return (it.vendors || []).includes(value);
      default:         return true;
    }
  }

  // q = { filters, search, starredOnly, starred:Set }. skip = group to ignore.
  function matches(it, q, skip) {
    if (q.starredOnly && !(q.starred && q.starred.has(it.id))) return false;
    for (const kind of GROUPS) {
      if (kind !== skip && !groupMatch(it, kind, q.filters[kind])) return false;
    }
    const ts = terms(q.search);
    if (ts.length) {
      const hay = haystack(it);
      if (!ts.every((t) => hay.includes(t))) return false;
    }
    return true;
  }

  function applyFilters(items, q) {
    return items.filter((it) => matches(it, q, null));
  }

  function valuesOf(it, kind) {
    switch (kind) {
      case "severity": return [it.severity || "info"];
      case "category": return [it.category];
      case "source":   return [it.source];
      case "tag":      return it.tags || [];
      case "vendor":   return it.vendors || [];
      default:         return [];
    }
  }

  // Counts per group as if that group's own selection were cleared, so the
  // numbers say how many results a click would give.
  function facetCounts(items, q) {
    const out = {};
    for (const kind of GROUPS) {
      const counts = {};
      for (const it of items) {
        if (!matches(it, q, kind)) continue;
        for (const v of valuesOf(it, kind)) {
          if (v) counts[v] = (counts[v] || 0) + 1;
        }
      }
      out[kind] = counts;
    }
    return out;
  }

  function toQuery(q) {
    const p = new URLSearchParams();
    for (const kind of GROUPS) if (q.filters[kind]) p.set(kind, q.filters[kind]);
    if (q.search) p.set("q", q.search);
    if (q.sort && q.sort !== "published") p.set("sort", q.sort);
    if (q.starredOnly) p.set("starred", "1");
    const s = p.toString();
    return s ? "?" + s : "";
  }

  const MAX_PARAM = 200;
  function fromQuery(search) {
    const p = new URLSearchParams(search || "");
    const filters = { ...EMPTY_FILTERS };
    for (const kind of GROUPS) filters[kind] = (p.get(kind) || "").slice(0, MAX_PARAM);
    const sort = SORTS.includes(p.get("sort")) ? p.get("sort") : "published";
    return {
      filters,
      search: (p.get("q") || "").slice(0, MAX_PARAM),
      sort,
      starredOnly: p.get("starred") === "1",
    };
  }

  const api = { GROUPS, EMPTY_FILTERS, dedupeById, matches, applyFilters, facetCounts, toQuery, fromQuery };
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  else root.__filters = api;
})(typeof window !== "undefined" ? window : globalThis);
