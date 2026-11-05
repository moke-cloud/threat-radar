// ThreatRadar — pure helpers for source health and cross-source CVE lookup.
// Loaded in the browser as window.__sourceHealth and in Node tests via require().

(function (root) {
  const DAY_MS = 24 * 60 * 60 * 1000;
  // A feed whose newest item is older than this is flagged as possibly dead.
  const STALE_DAYS = 45;
  const ORDER = { error: 0, stale: 1, empty: 2, ok: 3 };

  function timeOrZero(s) {
    const t = Date.parse(s || "");
    // Go's zero time (0001-01-01) means "unknown".
    return Number.isFinite(t) && t > 0 ? t : 0;
  }

  function classify(src, now) {
    if (!src || !src.ok) return "error";
    if (!src.fetched) return "empty";
    const last = timeOrZero(src.last_item_at);
    if (last && now - last > STALE_DAYS * DAY_MS) return "stale";
    return "ok";
  }

  function summarize(report, now) {
    const sources = (report && Array.isArray(report.sources)) ? report.sources : [];
    const rows = sources
      .map((s) => ({ ...s, status: classify(s, now), lastItem: timeOrZero(s.last_item_at) }))
      .sort((a, b) => (ORDER[a.status] - ORDER[b.status]) ||
                      String(a.name || a.id).localeCompare(String(b.name || b.id)));
    // "empty" is informational: a quiet feed or a day without new CVEs.
    const problems = rows.filter((r) => r.status === "error" || r.status === "stale").length;
    return { total: rows.length, problems, rows };
  }

  function crossSourceIndex(items) {
    const idx = new Map();
    for (const it of items || []) {
      for (const c of it.cves || []) {
        if (!idx.has(c)) idx.set(c, new Set());
        idx.get(c).add(it.source);
      }
    }
    return idx;
  }

  // Feed links are untrusted. Only absolute http(s) URLs become links.
  function safeHref(url) {
    const s = String(url ?? "").trim();
    return /^https?:\/\/[^\s/]/i.test(s) ? s : "";
  }

  function formatEPSS(p) {
    if (typeof p !== "number" || !Number.isFinite(p)) return "";
    return (p * 100).toFixed(1) + "%";
  }

  const api = { classify, summarize, crossSourceIndex, formatEPSS, safeHref, STALE_DAYS };
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  else root.__sourceHealth = api;
})(typeof window !== "undefined" ? window : globalThis);
