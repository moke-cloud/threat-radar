// Run: node --test web/test/*.test.js
const test = require("node:test");
const assert = require("node:assert/strict");
const F = require("../assets/filters.js");

const items = [
  { id: "a", source: "zdi", source_name: "Zero Day Initiative", category: "vuln", severity: "high",
    title: "Valkey RCE", summary: "remote code execution", tags: ["rce", "linux"], vendors: ["linux"], cves: ["CVE-2026-1"] },
  { id: "b", source: "nvd-recent", source_name: "NVD", category: "vuln", severity: "critical",
    title: "Exchange flaw", summary: "", tags: ["microsoft", "kev"], vendors: ["microsoft"], cves: ["CVE-2026-2"] },
  { id: "c", source: "piyolog", source_name: "piyolog", category: "news", severity: "info",
    title: "まとめ", summary: "不正アクセス", tags: [], vendors: [] },
];
const none = { ...F.EMPTY_FILTERS };

test("dedupeById keeps the first occurrence only", () => {
  const out = F.dedupeById([items[0], { ...items[0], title: "dup" }, items[1]]);
  assert.deepEqual(out.map((x) => x.title), ["Valkey RCE", "Exchange flaw"]);
});

test("matches: every filter group narrows", () => {
  const q = { filters: { ...none, source: "zdi" }, search: "", starredOnly: false, starred: new Set() };
  assert.deepEqual(F.applyFilters(items, q).map((x) => x.id), ["a"]);
});

test("matches: info severity is filterable", () => {
  const q = { filters: { ...none, severity: "info" }, search: "", starredOnly: false, starred: new Set() };
  assert.deepEqual(F.applyFilters(items, q).map((x) => x.id), ["c"]);
});

test("search hits source name, tags and vendors, not only title", () => {
  const base = { filters: none, starredOnly: false, starred: new Set() };
  assert.deepEqual(F.applyFilters(items, { ...base, search: "zero day" }).map((x) => x.id), ["a"]);
  assert.deepEqual(F.applyFilters(items, { ...base, search: "kev" }).map((x) => x.id), ["b"]);
  assert.deepEqual(F.applyFilters(items, { ...base, search: "不正" }).map((x) => x.id), ["c"]);
});

test("search terms are ANDed", () => {
  const base = { filters: none, starredOnly: false, starred: new Set() };
  assert.deepEqual(F.applyFilters(items, { ...base, search: "rce linux" }).map((x) => x.id), ["a"]);
  assert.deepEqual(F.applyFilters(items, { ...base, search: "rce microsoft" }), []);
});

test("starredOnly keeps starred items", () => {
  const q = { filters: none, search: "", starredOnly: true, starred: new Set(["b"]) };
  assert.deepEqual(F.applyFilters(items, q).map((x) => x.id), ["b"]);
});

test("facetCounts ignore the facet's own selection but apply the others", () => {
  const q = { filters: { ...none, category: "vuln", source: "zdi" }, search: "", starredOnly: false, starred: new Set() };
  const c = F.facetCounts(items, q);
  // source counts: category=vuln applied, source selection ignored
  assert.deepEqual(c.source, { zdi: 1, "nvd-recent": 1 });
  // category counts: source=zdi applied, category selection ignored
  assert.deepEqual(c.category, { vuln: 1 });
  assert.deepEqual(c.tag, { rce: 1, linux: 1 });
});

test("query string round-trips and drops unknown or empty keys", () => {
  const q = { filters: { ...none, severity: "high", tag: "0day" }, search: "CVE-2026 x", sort: "epss", starredOnly: true };
  const s = F.toQuery(q);
  const back = F.fromQuery(s);
  assert.equal(back.filters.severity, "high");
  assert.equal(back.filters.tag, "0day");
  assert.equal(back.filters.source, "");
  assert.equal(back.search, "CVE-2026 x");
  assert.equal(back.sort, "epss");
  assert.equal(back.starredOnly, true);
  assert.equal(F.fromQuery("?evil=1&sort=bogus").sort, "published");
});
