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
  const H = window.__sourceHealth;
  const EMPTY_FILTERS = Object.freeze({ severity: "", category: "", source: "", tag: "", vendor: "" });

  const state = {
    items: [],
    health: null,
    cveSources: new Map(),
    starredOnly: false,
    filters: { ...EMPTY_FILTERS },
    search: "",
    sort: "published",
    starred: new Set(JSON.parse(localStorage.getItem("tr_starred") || "[]")),
  };

  // ---------- Data load ----------------------------------------------------

  // GH Pages layout: data/ inside the served root (workflow stages it there).
  // Local dev: data/ may be one level up. Try both before giving up.
  async function fetchData(name) {
    let lastErr;
    for (const path of ["data/" + name, "../data/" + name]) {
      try {
        const r = await fetch(path, { cache: "no-store" });
        if (r.ok) return await r.json();
        lastErr = new Error("HTTP " + r.status);
      } catch (err) {
        lastErr = err;
      }
    }
    throw lastErr || new Error("data/" + name + " not found");
  }

  async function load() {
    try {
      const [items, health] = await Promise.all([
        fetchData("index.json"),
        // sources.json is optional: older deployments do not have it.
        fetchData("sources.json").catch(() => null),
      ]);
      state.items = items;
      state.health = health;
      state.cveSources = H.crossSourceIndex(items);
      renderQuickStats();
      renderHealth();
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

    renderLastUpdated(sorted);
  }

  function renderLastUpdated(sorted) {
    let dt = null;
    if (state.health && state.health.generated_at) {
      dt = new Date(state.health.generated_at);
    } else if (state.items.length) {
      const newest = sorted[0] || state.items[0];
      dt = new Date(newest.fetched || newest.published);
    }
    if (dt) $("#last-updated").textContent = i18n.t("stats.updated") + " " + formatDateShort(dt);
  }

  function itemCardHTML(it) {
    const sev = it.severity || "info";
    const cls = "item sev-" + escapeAttr(sev) + (state.starred.has(it.id) ? " starred" : "");
    const tags = (it.tags || []).slice(0, 6).map((t) =>
      `<span class="tag ${escapeAttr(t)}">${escapeHTML(t)}</span>`).join("");
    const cves = (it.cves || []).slice(0, 3).map((c) =>
      `<span class="tag cve">${escapeHTML(c)}</span>`).join("");
    const summary = it.summary
      ? `<div class="item-summary">${escapeHTML(it.summary)}</div>`
      : "";
    const epss = epssHTML(it);
    const corroboration = corroborationHTML(it);
    const star = state.starred.has(it.id) ? "★" : "☆";
    return `
      <article class="${cls}" data-id="${escapeAttr(it.id)}">
        <div class="sev-bar"></div>
        <div class="item-body">
          <div class="item-meta">
            <span class="source">${escapeHTML(it.source_name || it.source)}</span>
            <span class="pub">${escapeHTML(formatDateShort(new Date(it.published)))}</span>
            ${corroboration}
          </div>
          <h3 class="item-title">${titleHTML(it)}</h3>
          ${summary}
          <div class="item-tags">${cves}${tags}</div>
        </div>
        <div class="item-aside">
          <span class="score-pill ${escapeAttr(sev)}">${escapeHTML(it.score)}</span>
          ${epss}
          <div class="item-actions">
            <button class="btn-icon" data-action="copy" title="${escapeAttr(i18n.t("action.copy"))}">⧉</button>
            <button class="btn-icon btn-star ${state.starred.has(it.id) ? "starred" : ""}" data-action="star" title="${escapeAttr(i18n.t("action.star"))}">${star}</button>
          </div>
        </div>
      </article>`;
  }

  function titleHTML(it) {
    const href = H.safeHref(it.url);
    if (!href) return escapeHTML(it.title);
    return `<a href="${escapeAttr(href)}" target="_blank" rel="noopener noreferrer">${escapeHTML(it.title)}</a>`;
  }

  // EPSS >= 0.1 is flagged; >= 0.5 means FIRST predicts likely exploitation.
  function epssHTML(it) {
    if (!it.epss) return "";
    const level = it.epss >= 0.5 ? "high" : it.epss >= 0.1 ? "elevated" : "";
    const title = i18n.t("epss.title") + " / percentile " + H.formatEPSS(it.epss_percentile);
    return `<span class="epss-pill ${level}" title="${escapeAttr(title)}">EPSS ${escapeHTML(H.formatEPSS(it.epss))}</span>`;
  }

  // How many distinct sources mention any of this item's CVEs.
  function corroborationHTML(it) {
    let best = null;
    for (const c of it.cves || []) {
      const set = state.cveSources.get(c);
      if (set && set.size > 1 && (!best || set.size > best.size)) best = { cve: c, size: set.size, set };
    }
    if (!best) return "";
    const names = [...best.set].join(", ");
    const label = i18n.t("corroboration").replace("{n}", best.size);
    return `<button class="corroboration" data-action="cve" data-cve="${escapeAttr(best.cve)}" title="${escapeAttr(names)}">${escapeHTML(label)}</button>`;
  }

  function renderHealth() {
    const box = $("#source-health");
    if (!box) return;
    const sum = H.summarize(state.health, Date.now());
    if (!sum.total) {
      box.classList.add("hidden");
      return;
    }
    box.classList.remove("hidden");
    box.classList.toggle("has-problems", sum.problems > 0);
    $("#health-summary").textContent = sum.problems
      ? i18n.t("health.problems").replace("{n}", sum.problems).replace("{total}", sum.total)
      : i18n.t("health.all_ok").replace("{total}", sum.total);
    $("#health-list").innerHTML = sum.rows.map(healthRowHTML).join("");
  }

  function healthRowHTML(r) {
    const last = r.lastItem ? formatDateShort(new Date(r.lastItem)).slice(0, 10) : "-";
    const detail = r.status === "error" ? (r.error || "") : `${i18n.t("health.last_item")} ${last}`;
    return `
      <li class="health-row ${r.status}">
        <span class="health-dot" aria-hidden="true"></span>
        <span class="health-name">${escapeHTML(r.name || r.id)}</span>
        <span class="health-state">${escapeHTML(i18n.t("health." + r.status))}</span>
        <span class="health-detail">${escapeHTML(detail)}</span>
      </li>`;
  }

  function bindItemEvents() {
    $$("[data-action=cve]").forEach((b) => {
      b.addEventListener("click", (e) => {
        e.preventDefault();
        state.search = b.dataset.cve;
        $("#search").value = b.dataset.cve;
        render();
        $("#all-feed").scrollIntoView({ behavior: "smooth", block: "start" });
      });
    });
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
      if (state.starredOnly && !state.starred.has(it.id)) return false;
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
    if (mode === "epss") {
      copy.sort((a, b) => ((b.epss || 0) - (a.epss || 0)) || (b.score - a.score));
    } else if (mode === "score") {
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
  }

  // One delegated listener per chip group, bound once at init, so rebuilding
  // the chips on reset no longer stacks duplicate listeners.
  function bindChipGroup(sel) {
    $(sel).addEventListener("click", (e) => {
      const b = e.target.closest(".chip");
      if (!b) return;
      const kind = b.dataset.filter;
      $$(`.chip[data-filter="${kind}"]`).forEach((x) => x.classList.remove("active"));
      b.classList.add("active");
      state.filters[kind] = b.dataset.value;
      render();
    });
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
      renderHealth();
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

    ["#filter-severity", "#filter-category", "#filter-source", "#filter-tag", "#filter-vendor"]
      .forEach(bindChipGroup);

    $("#starred-only").addEventListener("click", () => {
      state.starredOnly = !state.starredOnly;
      setStarredButton();
      render();
    });

    $("#reset-filters").addEventListener("click", () => {
      state.filters = { ...EMPTY_FILTERS };
      state.starredOnly = false;
      setStarredButton();
      state.search = "";
      $("#search").value = "";
      $$(".chip[data-value='']").forEach((b) => b.classList.add("active"));
      $$(".chip:not([data-value=''])").forEach((b) => b.classList.remove("active"));
      buildFilterChips();
      render();
    });

    load();
  }

  function setStarredButton() {
    const b = $("#starred-only");
    b.classList.toggle("active", state.starredOnly);
    b.setAttribute("aria-pressed", String(state.starredOnly));
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
