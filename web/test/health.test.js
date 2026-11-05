// Run: node --test web/test
const test = require("node:test");
const assert = require("node:assert/strict");
const H = require("../assets/health.js");

const now = Date.parse("2026-11-05T01:00:00Z");
const day = 24 * 60 * 60 * 1000;
const iso = (ms) => new Date(ms).toISOString();

test("classify: failing source is error", () => {
  assert.equal(H.classify({ ok: false, error: "status 403" }, now), "error");
});

test("classify: ok with recent item is ok", () => {
  assert.equal(H.classify({ ok: true, fetched: 3, last_item_at: iso(now - 2 * day) }, now), "ok");
});

test("classify: ok but newest item older than threshold is stale", () => {
  assert.equal(H.classify({ ok: true, fetched: 3, last_item_at: iso(now - 60 * day) }, now), "stale");
});

test("classify: ok with zero items is empty", () => {
  assert.equal(H.classify({ ok: true, fetched: 0 }, now), "empty");
});

test("classify: undated items count as ok", () => {
  assert.equal(H.classify({ ok: true, fetched: 5, last_item_at: "0001-01-01T00:00:00Z" }, now), "ok");
});

test("summarize counts problems and sorts them first", () => {
  const report = { sources: [
    { id: "a", name: "A", ok: true, fetched: 1, last_item_at: iso(now) },
    { id: "b", name: "B", ok: false, error: "x" },
    { id: "c", name: "C", ok: true, fetched: 1, last_item_at: iso(now - 90 * day) },
  ] };
  const s = H.summarize(report, now);
  assert.equal(s.total, 3);
  assert.equal(s.problems, 2);
  assert.deepEqual(s.rows.map((r) => r.id), ["b", "c", "a"]);
});

test("summarize counts only error and stale as problems", () => {
  const report = { sources: [
    { id: "epss", name: "EPSS", ok: true, fetched: 0 },
    { id: "a", name: "A", ok: true, fetched: 1, last_item_at: iso(now) },
  ] };
  const s = H.summarize(report, now);
  assert.equal(s.problems, 0);
  assert.equal(s.rows[0].status, "empty");
});

test("safeHref allows only absolute http(s) URLs", () => {
  assert.equal(H.safeHref("https://example.com/a"), "https://example.com/a");
  assert.equal(H.safeHref("HTTP://example.com"), "HTTP://example.com");
  assert.equal(H.safeHref("javascript:alert(1)"), "");
  assert.equal(H.safeHref(" JavaScript:alert(1)"), "");
  assert.equal(H.safeHref("data:text/html,x"), "");
  assert.equal(H.safeHref("//evil.example"), "");
  assert.equal(H.safeHref(undefined), "");
});

test("summarize tolerates missing report", () => {
  const s = H.summarize(null, now);
  assert.equal(s.total, 0);
  assert.deepEqual(s.rows, []);
});

test("crossSourceIndex maps CVE to distinct sources", () => {
  const idx = H.crossSourceIndex([
    { source: "kev", cves: ["CVE-1"] },
    { source: "nvd", cves: ["CVE-1", "CVE-2"] },
    { source: "nvd", cves: ["CVE-1"] },
  ]);
  assert.deepEqual([...idx.get("CVE-1")].sort(), ["kev", "nvd"]);
  assert.equal(idx.get("CVE-2").size, 1);
});

test("formatEPSS renders percent with one decimal", () => {
  assert.equal(H.formatEPSS(0.28658), "28.7%");
  assert.equal(H.formatEPSS(0.00042), "0.0%");
  assert.equal(H.formatEPSS(undefined), "");
});
