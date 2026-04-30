// ThreatRadar — vanilla JS dashboard.
//
// Loads data/index.json (relative to this file's parent directory), then renders:
//   - critical wall (severity ∈ {critical, high}, last 7 days)
//   - today section (last 24h)
//   - "all items" feed with sort + filters + search
//
// Persisted state (localStorage):
//   tr_lang        — "ja" | "en"
//   tr_theme       — "dark" | "light"
//   tr_starred     — JSON array of item IDs

(function () {
  const $  = (s, r=document) => r.querySelector(s);
  const $$ = (s, r=document) => Array.from(r.querySelectorAll(s));
  const i18n = window.__i18n;

  const state = {
    items: [],
    filters: { severity: "", category: "", source: "", tag: "", vendor: "" },
    search: "",
    sort: "published",
    starred: new Set(JSON.parse(localStorage.getItem("tr_starred") || "[]")),
  };

  // ---------- Data load ----------------------------------------------------

  // GH Pages layout: data/ inside the served root (workflow stages it there).
  // Local dev: data/ may be one level up. Try both before giving up.
  async function fetchIndex() {
    let lastErr;
    for (const path of ["data/index.json", "../data/index.json"]) {
      try {
        const r = await fetch(path, { cache: "no-store" });
        if (r.ok) return await r.json();
        lastErr = new Error("HTTP " + r.status);
      } catch (err) {
        lastErr = err;
      }
    }
    throw lastErr || new Error("data/index.json not found");
  }

  async function load() {
    try {
      state.items = await fetchIndex();
      renderQuickStats();
      buildFilterChips();
      render();
    } catch (err) {
      $("#all-feed").innerHTML = `<div class="empty">${i18n.t("state.fetch_failed")}: ${escapeHTML(String(err))}</div>`;
    }
  }

  // ---------- Rendering ----------------------------------------------------

  function render() {
    const filtered = applyFilters(state.items);
    const sorted = sortItems(filtered, state.sort);

    // Critical wall: severity in critical/high, last 7d, top 6 by score
    const sevenDaysAgo = Date.now() - 7 * 24 * 60 * 60 * 1000;
    const wall = state.items
      .filter((it) => (it.severity === "critical" || it.severity === "high") &&
                      new Date(it.published).getTime() >= sevenDaysAgo)
      .sort((a, b) => (b.score - a.score) || (timeOf(b) - timeOf(a)))
      .slice(0, 6);
    if (wall.length) {
      $("#critical-wall").classList.remove("hidden");
      $("#critical-items").innerHTML = wall.map(itemCardHTML).join("");
    } else {
      $("#critical-wall").classList.add("hidden");
    }

    // Today (last 24h, sorted by score)
    const since24h = Date.now() - 24 * 60 * 60 * 1000;
    const today = state.items
      .filter((it) => new Date(it.published).getTime() >= since24h)
      .sort((a, b) => (b.score - a.score) || (timeOf(b) - timeOf(a)));
    if (today.length) {
      $("#today-section").classList.remove("hidden");
      $("#today-feed").innerHTML = today.map(itemCardHTML).join("");
      $("#today-count").textContent = `(${today.length})`;
    } else {
      $("#today-section").classList.add("hidden");
    }

    // All
    $("#all-count").textContent = `(${sorted.length})`;
    if (!sorted.length) {
      $("#all-feed").innerHTML = `<div class="empty">${i18n.t("state.empty")}</div>`;
    } else {
      $("#all-feed").innerHTML = sorted.map(itemCardHTML).join("");
    }

    bindItemEvents();

    // Last updated
    if (state.items.length) {
      const newest = sorted[0] || state.items[0];
      const dt = new Date(newest.fetched || newest.published);
      $("#last-updated").textContent = "updated " + formatDateShort(dt);
    }
  }

  function itemCardHTML(it) {
    const sev = it.severity || "info";
    const cls = "item sev-" + sev + (state.starred.has(it.id) ? " starred" : "");
    const tags = (it.tags || []).slice(0, 6).map((t) =>
      `<span class="tag ${escapeAttr(t)}">${escapeHTML(t)}</span>`).join("");
    const cves = (it.cves || []).slice(0, 3).map((c) =>
      `<span class="tag cve">${escapeHTML(c)}</span>`).join("");
    const summary = it.summary
      ? `<div class="item-summary">${escapeHTML(it.summary)}</div>`
      : "";
    const star = state.starred.has(it.id) ? "★" : "☆";
    return `
      <article class="${cls}" data-id="${escapeAttr(it.id)}">
        <div class="sev-bar"></div>
        <div class="item-body">
          <div class="item-meta">
            <span class="source">${escapeHTML(it.source_name || it.source)}</span>
            <span class="pub">${escapeHTML(formatDateShort(new Date(it.published)))}</span>
          </div>
          <h3 class="item-title">
            <a href="${escapeAttr(it.url)}" target="_blank" rel="noopener noreferrer">${escapeHTML(it.title)}</a>
          </h3>
          ${summary}
          <div class="item-tags">${cves}${tags}</div>
        </div>
        <div class="item-aside">
          <span class="score-pill ${sev}">${it.score}</span>
          <div class="item-actions">
            <button class="btn-icon" data-action="copy" title="${escapeAttr(i18n.t("action.copy"))}">⧉</button>
            <button class="btn-icon btn-star ${state.starred.has(it.id) ? "starred" : ""}" data-action="star" title="${escapeAttr(i18n.t("action.star"))}">${star}</button>
          </div>
        </div>
      </article>`;
  }

  function bindItemEvents() {
    $$("[data-action=star]").forEach((b) => {
      b.addEventListener("click", (e) => {
        e.preventDefault();
        e.stopPropagation();
        const card = b.closest("[data-id]");
        const id = card.dataset.id;
        if (state.starred.has(id)) state.starred.delete(id);
        else state.starred.add(id);
        localStorage.setItem("tr_starred", JSON.stringify([...state.starred]));
        render();
      });
    });
    $$("[data-action=copy]").forEach((b) => {
      b.addEventListener("click", async (e) => {
        e.preventDefault();
        e.stopPropagation();
        const card = b.closest("[data-id]");
        const id = card.dataset.id;
        const it = state.items.find((x) => x.id === id);
        if (!it) return;
        // Format optimised for paste-into-translator: title, blank line,
        // summary, blank line, source URL. Easy to drop in DeepL / Google
        // Translate / a chat box.
        const text = [
          it.title,
          "",
          it.summary || "",
          "",
          "Source: " + it.url,
        ].join("\n");
        try {
          await navigator.clipboard.writeText(text);
          flashCopied(b);
        } catch (err) {
          // Fallback: select-and-copy via temporary textarea (older browsers).
          const ta = document.createElement("textarea");
          ta.value = text;
          ta.style.position = "fixed";
          ta.style.opacity = "0";
          document.body.appendChild(ta);
          ta.select();
          try { document.execCommand("copy"); flashCopied(b); }
          catch { toast("copy failed", "error"); }
          document.body.removeChild(ta);
        }
      });
    });
  }

  function flashCopied(btn) {
    const original = btn.textContent;
    btn.textContent = "✓";
    btn.classList.add("ok");
    setTimeout(() => {
      btn.textContent = original;
      btn.classList.remove("ok");
    }, 900);
    toast(i18n.t("toast.copied"), "ok");
  }

  let toastTimer = null;
  function toast(msg, kind = "ok") {
    const t = $("#toast");
    if (!t) return;
    t.textContent = msg;
    t.className = "toast " + kind;
    if (toastTimer) clearTimeout(toastTimer);
    toastTimer = setTimeout(() => t.classList.add("hidden"), 1800);
  }

  // ---------- Filters / search / sort -------------------------------------

  function applyFilters(items) {
    const f = state.filters;
    const q = state.search.trim().toLowerCase();
    return items.filter((it) => {
      if (f.severity && it.severity !== f.severity) return false;
      if (f.category && it.category !== f.category) return false;
      if (f.source && it.source !== f.source) return false;
      if (f.tag && !(it.tags || []).includes(f.tag)) return false;
      if (f.vendor && !(it.vendors || []).includes(f.vendor)) return false;
      if (q) {
        const hay = (it.title + " " + (it.summary || "") + " " + (it.cves || []).join(" ")).toLowerCase();
        if (!hay.includes(q)) return false;
      }
      return true;
    });
  }

  function sortItems(items, mode) {
    const copy = items.slice();
    if (mode === "score") {
      copy.sort((a, b) => (b.score - a.score) || (timeOf(b) - timeOf(a)));
    } else {
      copy.sort((a, b) => (timeOf(b) - timeOf(a)) || (b.score - a.score));
    }
    return copy;
  }

  function buildFilterChips() {
    const counts = {
      category: tally(state.items, (it) => it.category),
      source:   tally(state.items, (it) => it.source),
      tag:      tally(state.items, (it) => (it.tags || [])),
      vendor:   tally(state.items, (it) => (it.vendors || [])),
    };
    renderChipGroup("#filter-category", counts.category, "category", 0);
    renderChipGroup("#filter-source",   counts.source,   "source",   0);
    renderChipGroup("#filter-tag",      counts.tag,      "tag",      18);
    renderChipGroup("#filter-vendor",   counts.vendor,   "vendor",   18);
  }

  function renderChipGroup(sel, counts, kind, topN) {
    const root = $(sel);
    if (!root) return;
    let entries = Object.entries(counts).sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
    if (topN > 0) entries = entries.slice(0, topN);
    const all = `<button class="chip active" data-filter="${kind}" data-value="">all</button>`;
    root.innerHTML = all + entries.map(([k, v]) =>
      `<button class="chip" data-filter="${kind}" data-value="${escapeAttr(k)}">${escapeHTML(k)}<span class="count">${v}</span></button>`
    ).join("");
    root.addEventListener("click", (e) => {
      const b = e.target.closest(".chip");
      if (!b) return;
      const kind = b.dataset.filter;
      $$(`.chip[data-filter="${kind}"]`).forEach((x) => x.classList.remove("active"));
      b.classList.add("active");
      state.filters[kind] = b.dataset.value;
      render();
    }, { once: false });
  }

  function tally(items, fn) {
    const out = {};
    for (const it of items) {
      const v = fn(it);
      const arr = Array.isArray(v) ? v : [v];
      for (const x of arr) {
        if (!x) continue;
        out[x] = (out[x] || 0) + 1;
      }
    }
    return out;
  }

  function renderQuickStats() {
    const total = state.items.length;
    const since24h = Date.now() - 24 * 60 * 60 * 1000;
    const today = state.items.filter((it) => new Date(it.published).getTime() >= since24h).length;
    const crit  = state.items.filter((it) => it.severity === "critical").length;
    const html = [
      `<span><strong>${total}</strong>${i18n.t("stats.total")}</span>`,
      `<span><strong>${today}</strong>${i18n.t("stats.last24h")}</span>`,
      `<span class="sev-critical"><strong>${crit}</strong>${i18n.t("stats.critical")}</span>`,
    ].join("");
    $("#quick-stats").innerHTML = html;
  }

  // ---------- RSS export --------------------------------------------------

  function buildRSSDataURI() {
    const items = applyFilters(state.items).slice(0, 50);
    const xmlEscape = (s) => String(s ?? "")
      .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;").replace(/'/g, "&apos;");
    const parts = [
      '<?xml version="1.0" encoding="UTF-8"?>',
      '<rss version="2.0"><channel>',
      '<title>ThreatRadar (filtered)</title>',
      '<link>about:blank</link>',
      '<description>Filtered feed from ThreatRadar dashboard</description>',
    ];
    for (const it of items) {
      parts.push(
        '<item>',
        `<title>${xmlEscape(it.title)}</title>`,
        `<link>${xmlEscape(it.url)}</link>`,
        `<guid isPermaLink="false">${xmlEscape(it.id)}</guid>`,
        `<pubDate>${new Date(it.published).toUTCString()}</pubDate>`,
        `<description>${xmlEscape(it.summary || "")}</description>`,
        '</item>',
      );
    }
    parts.push('</channel></rss>');
    const blob = new Blob([parts.join("")], { type: "application/rss+xml" });
    return URL.createObjectURL(blob);
  }

  // ---------- Helpers ------------------------------------------------------

  function timeOf(it) { return new Date(it.published).getTime() || 0; }
  function escapeHTML(s) {
    return String(s ?? "")
      .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
  }
  function escapeAttr(s) { return escapeHTML(s); }
  function pad(n) { return String(n).padStart(2, "0"); }
  function formatDateShort(d) {
    if (isNaN(d.getTime())) return "—";
    return `${d.getFullYear()}-${pad(d.getMonth()+1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`;
  }

  // ---------- Boot ---------------------------------------------------------

  function init() {
    // Theme
    const theme = localStorage.getItem("tr_theme") || "dark";
    document.documentElement.dataset.theme = theme;

    i18n.setLang(i18n.getLang());
    $("#toggle-lang").textContent = i18n.getLang() === "ja" ? "EN" : "JA";

    $("#toggle-lang").addEventListener("click", () => {
      const next = i18n.getLang() === "ja" ? "en" : "ja";
      i18n.setLang(next);
      $("#toggle-lang").textContent = next === "ja" ? "EN" : "JA";
      render();
      renderQuickStats();
    });

    $("#toggle-theme").addEventListener("click", () => {
      const cur = document.documentElement.dataset.theme;
      const next = cur === "dark" ? "light" : "dark";
      document.documentElement.dataset.theme = next;
      localStorage.setItem("tr_theme", next);
    });

    $("#search").addEventListener("input", debounce(() => {
      state.search = $("#search").value;
      render();
    }, 200));

    $("#sort-by").addEventListener("change", () => {
      state.sort = $("#sort-by").value;
      render();
    });

    $("#reset-filters").addEventListener("click", () => {
      state.filters = { severity: "", category: "", source: "", tag: "", vendor: "" };
      state.search = "";
      $("#search").value = "";
      $$(".chip[data-value='']").forEach((b) => b.classList.add("active"));
      $$(".chip:not([data-value=''])").forEach((b) => b.classList.remove("active"));
      buildFilterChips();
      render();
    });

    // Severity chips bind manually since they're in HTML, not generated
    $("#filter-severity").addEventListener("click", (e) => {
      const b = e.target.closest(".chip");
      if (!b) return;
      $$(`#filter-severity .chip`).forEach((x) => x.classList.remove("active"));
      b.classList.add("active");
      state.filters.severity = b.dataset.value;
      render();
    });

    $("#btn-rss").addEventListener("click", (e) => {
      e.preventDefault();
      const url = buildRSSDataURI();
      const a = document.createElement("a");
      a.href = url;
      a.download = "threat-radar.xml";
      a.click();
      setTimeout(() => URL.revokeObjectURL(url), 5000);
    });

    load();
  }

  function debounce(fn, ms) {
    let t;
    return function () {
      clearTimeout(t);
      t = setTimeout(() => fn.apply(this, arguments), ms);
    };
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
