// ThreatRadar — vanilla JS dashboard.
//
// Loads data/index.json, then renders three sections that all honour the
// current filters / search:
//   - critical wall (severity ∈ {critical, high}, last 7 days, top 6)
//   - last 24 hours
//   - all items (sortable)
//
// Filter state lives in the URL query (shareable, survives reload).
// Per-browser state (localStorage): tr_lang, tr_theme, tr_starred, tr_auto_ja.

(function () {
  const $  = (s, r=document) => r.querySelector(s);
  const $$ = (s, r=document) => Array.from(r.querySelectorAll(s));
  const i18n = window.__i18n;
  const H = window.__sourceHealth;
  const F = window.__filters;
  const TR = window.__translate;
  const store = safeStorage();
  const svc = TR.createService(store);

  const DAY_MS = 24 * 60 * 60 * 1000;
  const SEVERITIES = ["critical", "high", "medium", "low", "info"];
  const CHIP_LIMIT = { tag: 40, vendor: 40 };

  const fromURL = F.fromQuery(location.search);
  const state = {
    items: [],
    health: null,
    cveSources: new Map(),
    filters: { ...fromURL.filters },
    search: fromURL.search,
    sort: fromURL.sort,
    starredOnly: fromURL.starredOnly,
    starred: new Set(readJSON("tr_starred", [])),
    autoJa: store.getItem("tr_auto_ja") === "1",
    override: new Map(), // id -> "ja" | "orig" (per-card toggle)
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
      state.items = F.dedupeById(Array.isArray(items) ? items : []);
      state.health = health;
      state.cveSources = H.crossSourceIndex(state.items);
      renderQuickStats();
      renderHealth();
      render();
    } catch (err) {
      $("#all-feed").innerHTML = `<div class="empty">${escapeHTML(i18n.t("state.fetch_failed"))}: ${escapeHTML(String(err))}<br>${escapeHTML(i18n.t("state.retry"))}</div>`;
    }
  }

  // ---------- Rendering ----------------------------------------------------

  function query() {
    return { filters: state.filters, search: state.search, starredOnly: state.starredOnly, starred: state.starred, sort: state.sort };
  }

  function render() {
    const q = query();
    const filtered = F.applyFilters(state.items, q);
    const now = Date.now();
    const byScore = (a, b) => (b.score - a.score) || (timeOf(b) - timeOf(a));

    const wall = filtered
      .filter((it) => (it.severity === "critical" || it.severity === "high") && timeOf(it) >= now - 7 * DAY_MS)
      .sort(byScore)
      .slice(0, 6);
    toggleSection("#critical-wall", wall.length > 0);
    $("#critical-items").innerHTML = wall.map(itemCardHTML).join("");

    const today = filtered.filter((it) => timeOf(it) >= now - DAY_MS).sort(byScore);
    toggleSection("#today-section", today.length > 0);
    $("#today-feed").innerHTML = today.map(itemCardHTML).join("");
    $("#today-count").textContent = `(${today.length})`;

    const sorted = sortItems(filtered, state.sort);
    $("#all-count").textContent = `(${sorted.length})`;
    $("#all-feed").innerHTML = sorted.length
      ? sorted.map(itemCardHTML).join("")
      : `<div class="empty">${escapeHTML(i18n.t("state.empty"))}</div>`;

    renderChips(F.facetCounts(state.items, q));
    syncControls();
    syncURL();
    renderLastUpdated();
    observeForTranslation();
  }

  function toggleSection(sel, show) { $(sel).classList.toggle("hidden", !show); }

  function renderLastUpdated() {
    let dt = null;
    if (state.health && state.health.generated_at) dt = new Date(state.health.generated_at);
    else if (state.items.length) dt = new Date(state.items[0].fetched || state.items[0].published);
    if (dt) $("#last-updated").textContent = i18n.t("stats.updated") + " " + formatDate(dt);
  }

  function itemCardHTML(it) {
    const sev = it.severity || "info";
    const starred = state.starred.has(it.id);
    const tr = shownTranslation(it);
    const title = tr && tr.title ? tr.title : it.title;
    const summaryText = tr && tr.summary ? tr.summary : it.summary;
    const tags = (it.tags || []).slice(0, 6).map((t) =>
      `<span class="tag ${escapeAttr(t)}" translate="no">${escapeHTML(t)}</span>`).join("");
    const cves = (it.cves || []).slice(0, 3).map((c) =>
      `<span class="tag cve" translate="no">${escapeHTML(c)}</span>`).join("");
    const summary = summaryText
      ? `<div class="item-summary"${tr ? ` title="${escapeAttr(it.summary || "")}"` : ""}>${escapeHTML(summaryText)}</div>`
      : "";
    const mt = tr ? `<span class="mt-label">${escapeHTML(i18n.t("mt.label"))}</span>` : "";
    return `
      <article class="item sev-${escapeAttr(sev)}${starred ? " starred" : ""}" data-id="${escapeAttr(it.id)}">
        <div class="sev-bar" aria-hidden="true"></div>
        <div class="item-body">
          <div class="item-meta">
            <span class="source" translate="no">${escapeHTML(it.source_name || it.source)}</span>
            <time class="pub" datetime="${escapeAttr(it.published)}">${escapeHTML(formatDate(new Date(it.published)))}</time>
            ${corroborationHTML(it)}
            ${mt}
          </div>
          <h3 class="item-title"${tr ? ` title="${escapeAttr(it.title)}"` : ""}>${titleHTML(it, title)}</h3>
          ${summary}
          <div class="item-tags">${cves}${tags}</div>
        </div>
        <div class="item-aside">
          <span class="score-pill ${escapeAttr(sev)}" title="${escapeAttr(i18n.t("score.title"))}">${escapeHTML(it.score)}</span>
          ${epssHTML(it)}
          <div class="item-actions">
            ${translateButtonHTML(it, tr)}
            <button class="btn-icon" data-action="copy" aria-label="${escapeAttr(i18n.t("action.copy"))}" title="${escapeAttr(i18n.t("action.copy"))}">⧉</button>
            <button class="btn-icon btn-star${starred ? " starred" : ""}" data-action="star" aria-pressed="${starred}" aria-label="${escapeAttr(i18n.t("action.star"))}" title="${escapeAttr(i18n.t("action.star"))}">${starred ? "★" : "☆"}</button>
          </div>
        </div>
      </article>`;
  }

  function titleHTML(it, text) {
    const href = H.safeHref(it.url);
    if (!href) return escapeHTML(text);
    return `<a href="${escapeAttr(href)}" target="_blank" rel="noopener noreferrer">${escapeHTML(text)}</a>`;
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

  // ---------- Translation --------------------------------------------------

  function wantsJa(it) {
    const o = state.override.get(it.id);
    return o ? o === "ja" : state.autoJa;
  }

  function shownTranslation(it) {
    if (!TR.needsTranslation(it) || !wantsJa(it)) return null;
    return svc.cached(it) || null;
  }

  function translateButtonHTML(it, tr) {
    if (!TR.needsTranslation(it)) return "";
    if (!svc.supported()) {
      const url = TR.googleTranslateURL([it.title, it.summary].filter(Boolean).join("\n\n"));
      return `<a class="btn-icon btn-tr" href="${escapeAttr(url)}" target="_blank" rel="noopener noreferrer" aria-label="${escapeAttr(i18n.t("action.translate_ext"))}" title="${escapeAttr(i18n.t("action.translate_ext"))}">訳</a>`;
    }
    const label = tr ? i18n.t("action.original") : i18n.t("action.translate");
    return `<button class="btn-icon btn-tr${tr ? " on" : ""}" data-action="translate" aria-pressed="${Boolean(tr)}" aria-label="${escapeAttr(label)}" title="${escapeAttr(label)}">${tr ? "原" : "訳"}</button>`;
  }

  async function translateCard(id, viaUser) {
    const it = state.items.find((x) => x.id === id);
    if (!it) return;
    try {
      if (viaUser && !svc.ready()) await svc.ensure(onDownloadProgress);
      await svc.translateItem(it);
      patchCard(it);
    } catch (err) {
      if (viaUser) toast(i18n.t("toast.translate_failed") + ": " + String(err.message || err), "error");
    }
  }

  function onDownloadProgress(loaded) {
    toast(i18n.t("toast.model_download").replace("{p}", Math.round((loaded || 0) * 100)), "ok");
  }

  // Replace only the cards for one item (it can appear in several sections).
  function patchCard(it) {
    const html = itemCardHTML(it);
    $$(`[data-id="${CSS.escape(it.id)}"]`).forEach((el) => {
      const tpl = document.createElement("template");
      tpl.innerHTML = html.trim();
      el.replaceWith(tpl.content.firstElementChild);
    });
  }

  let observer = null;
  function observeForTranslation() {
    if (observer) observer.disconnect();
    if (!state.autoJa || !svc.ready() || typeof IntersectionObserver === "undefined") return;
    observer = new IntersectionObserver((entries) => {
      for (const e of entries) {
        if (!e.isIntersecting) continue;
        observer.unobserve(e.target);
        translateCard(e.target.dataset.id, false);
      }
    }, { rootMargin: "200px 0px" });
    const byId = new Map(state.items.map((it) => [it.id, it]));
    $$("article.item[data-id]").forEach((el) => {
      const it = byId.get(el.dataset.id);
      if (it && TR.needsTranslation(it) && wantsJa(it) && !svc.cached(it)) observer.observe(el);
    });
  }

  async function setAutoJa(on) {
    if (on && !svc.supported()) {
      toast(i18n.t("toast.translate_unsupported"), "error");
      return;
    }
    if (on && !svc.ready()) {
      try { await svc.ensure(onDownloadProgress); }
      catch (err) {
        toast(i18n.t("toast.translate_failed") + ": " + String(err.message || err), "error");
        return;
      }
    }
    state.autoJa = on;
    state.override.clear();
    store.setItem("tr_auto_ja", on ? "1" : "0");
    render();
  }

  // ---------- Health -------------------------------------------------------

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
    const last = r.lastItem ? formatDay(new Date(r.lastItem)) : "-";
    const detail = r.status === "error" ? (r.error || "") : `${i18n.t("health.last_item")} ${last}`;
    return `
      <li class="health-row ${r.status}">
        <span class="health-dot" aria-hidden="true"></span>
        <span class="health-name" translate="no">${escapeHTML(r.name || r.id)}</span>
        <span class="health-state">${escapeHTML(i18n.t("health." + r.status))}</span>
        <span class="health-detail">${escapeHTML(detail)}</span>
      </li>`;
  }

  // ---------- Item actions (delegated, bound once) -------------------------

  function onFeedClick(e) {
    const b = e.target.closest("[data-action]");
    if (!b || b.tagName === "A") return;
    e.preventDefault();
    const card = b.closest("[data-id]");
    const id = card && card.dataset.id;
    switch (b.dataset.action) {
      case "cve":
        state.search = b.dataset.cve;
        render();
        $("#all-feed").scrollIntoView({ behavior: prefersReducedMotion() ? "auto" : "smooth", block: "start" });
        break;
      case "star":
        toggleStar(id);
        break;
      case "copy":
        copyItem(id, b);
        break;
      case "translate":
        onTranslateClick(id, e);
        break;
    }
  }

  function onTranslateClick(id, e) {
    const it = state.items.find((x) => x.id === id);
    if (!it) return;
    const showing = Boolean(shownTranslation(it));
    state.override.set(id, showing ? "orig" : "ja");
    const section = sectionOf(e.target);
    const refocus = () => {
      const btn = $(`#${section} [data-id="${CSS.escape(id)}"] [data-action=translate]`);
      if (btn) btn.focus({ preventScroll: true });
    };
    if (showing || svc.cached(it)) { patchCard(it); refocus(); }
    else translateCard(id, true).then(refocus);
  }

  function sectionOf(el) {
    const host = el.closest("#critical-items, #today-feed, #all-feed");
    return host ? host.id : "all-feed";
  }

  // Star without re-rendering everything, so focus and scroll stay put.
  function toggleStar(id) {
    if (state.starred.has(id)) state.starred.delete(id);
    else state.starred.add(id);
    store.setItem("tr_starred", JSON.stringify([...state.starred]));
    if (state.starredOnly) { render(); return; }
    const on = state.starred.has(id);
    $$(`[data-id="${CSS.escape(id)}"]`).forEach((card) => {
      card.classList.toggle("starred", on);
      const b = $("[data-action=star]", card);
      b.classList.toggle("starred", on);
      b.setAttribute("aria-pressed", String(on));
      b.textContent = on ? "★" : "☆";
    });
  }

  async function copyItem(id, btn) {
    const it = state.items.find((x) => x.id === id);
    if (!it) return;
    // Paste-into-translator format: title, summary, source URL.
    const text = [it.title, "", it.summary || "", "", "Source: " + it.url].join("\n");
    try {
      await navigator.clipboard.writeText(text);
      flashCopied(btn);
    } catch {
      const ta = document.createElement("textarea");
      ta.value = text;
      ta.style.position = "fixed";
      ta.style.opacity = "0";
      document.body.appendChild(ta);
      ta.select();
      try { document.execCommand("copy"); flashCopied(btn); }
      catch { toast(i18n.t("toast.copy_failed"), "error"); }
      document.body.removeChild(ta);
    }
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
    toastTimer = setTimeout(() => t.classList.add("hidden"), kind === "error" ? 4000 : 1800);
  }

  // ---------- Filters / chips / sort ---------------------------------------

  function sortItems(items, mode) {
    const copy = items.slice();
    if (mode === "epss") copy.sort((a, b) => ((b.epss || 0) - (a.epss || 0)) || (b.score - a.score));
    else if (mode === "score") copy.sort((a, b) => (b.score - a.score) || (timeOf(b) - timeOf(a)));
    else copy.sort((a, b) => (timeOf(b) - timeOf(a)) || (b.score - a.score));
    return copy;
  }

  // Chips are rebuilt every render from facet counts, so the numbers always
  // say what a click would give and the selected chip stays visible.
  function renderChips(counts) {
    renderChipGroup("#filter-severity", "severity", SEVERITIES.map((s) => [s, counts.severity[s] || 0]));
    renderChipGroup("#filter-category", "category", sortedEntries(counts.category));
    renderChipGroup("#filter-source", "source", sortedEntries(counts.source), sourceLabel);
    // Vendor names already have their own group.
    const vendorSet = new Set(state.items.flatMap((it) => it.vendors || []));
    const tags = sortedEntries(counts.tag).filter(([k]) => !vendorSet.has(k) || k === state.filters.tag);
    renderChipGroup("#filter-tag", "tag", tags.slice(0, CHIP_LIMIT.tag));
    renderChipGroup("#filter-vendor", "vendor", sortedEntries(counts.vendor).slice(0, CHIP_LIMIT.vendor));
  }

  function sortedEntries(obj) {
    return Object.entries(obj).sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
  }

  function renderChipGroup(sel, kind, entries, labelFn) {
    const root = $(sel);
    if (!root) return;
    const current = state.filters[kind];
    if (current && !entries.some(([k]) => k === current)) entries = [[current, 0], ...entries];
    const chip = (value, label, count) => {
      const active = value === current;
      const sevCls = kind === "severity" && value ? ` sev-${escapeAttr(value)}` : "";
      const dim = value && count === 0 && !active ? " zero" : "";
      const n = value ? `<span class="count">${count}</span>` : "";
      return `<button class="chip${sevCls}${active ? " active" : ""}${dim}" data-filter="${kind}" data-value="${escapeAttr(value)}" aria-pressed="${active}">${escapeHTML(label)}${n}</button>`;
    };
    root.innerHTML = chip("", i18n.t("filter.all"), 0) +
      entries.map(([k, v]) => chip(k, labelFn ? labelFn(k) : k, v)).join("");
  }

  function sourceLabel(id) {
    const it = state.items.find((x) => x.source === id);
    return (it && it.source_name) || id;
  }

  function onChipClick(e) {
    const b = e.target.closest(".chip[data-filter]");
    if (!b) return;
    const kind = b.dataset.filter;
    // Clicking the active chip again clears that group.
    state.filters = { ...state.filters, [kind]: state.filters[kind] === b.dataset.value ? "" : b.dataset.value };
    render();
    const again = $(`.chip[data-filter="${kind}"][data-value="${CSS.escape(b.dataset.value)}"]`);
    if (again) again.focus();
  }

  function syncControls() {
    const s = $("#search");
    if (s.value !== state.search) s.value = state.search;
    $("#sort-by").value = state.sort;
    const sb = $("#starred-only");
    sb.classList.toggle("active", state.starredOnly);
    sb.setAttribute("aria-pressed", String(state.starredOnly));
    const ja = $("#auto-ja");
    ja.classList.toggle("active", state.autoJa);
    ja.setAttribute("aria-pressed", String(state.autoJa));
    const n = F.GROUPS.filter((k) => state.filters[k]).length + (state.starredOnly ? 1 : 0);
    $("#reset-filters").disabled = !(n || state.search);
    $("#toggle-filters").dataset.count = String(n);
  }

  function syncURL() {
    const qs = F.toQuery(query());
    if (qs !== location.search) history.replaceState(null, "", location.pathname + qs + location.hash);
  }

  function renderQuickStats() {
    const now = Date.now();
    const total = state.items.length;
    const today = state.items.filter((it) => timeOf(it) >= now - DAY_MS).length;
    const crit  = state.items.filter((it) => it.severity === "critical").length;
    $("#quick-stats").innerHTML = [
      `<span><strong>${total}</strong>${escapeHTML(i18n.t("stats.total"))}</span>`,
      `<span><strong>${today}</strong>${escapeHTML(i18n.t("stats.last24h"))}</span>`,
      `<span class="sev-critical"><strong>${crit}</strong>${escapeHTML(i18n.t("stats.critical"))}</span>`,
    ].join("");
  }

  // ---------- Helpers ------------------------------------------------------

  function timeOf(it) { return new Date(it.published).getTime() || 0; }
  function escapeHTML(s) {
    return String(s ?? "")
      .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
  }
  function escapeAttr(s) { return escapeHTML(s); }
  function locale() { return i18n.getLang() === "ja" ? "ja-JP" : "en-GB"; }
  function formatDate(d) {
    if (isNaN(d.getTime())) return "—";
    return new Intl.DateTimeFormat(locale(), { year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit" }).format(d);
  }
  function formatDay(d) {
    if (isNaN(d.getTime())) return "-";
    return new Intl.DateTimeFormat(locale(), { year: "numeric", month: "2-digit", day: "2-digit" }).format(d);
  }
  function prefersReducedMotion() {
    return window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  }
  function readJSON(key, fallback) {
    try {
      const v = JSON.parse(store.getItem(key) || "null");
      return Array.isArray(fallback) ? (Array.isArray(v) ? v : fallback) : (v ?? fallback);
    } catch { return fallback; }
  }
  // Storage can be blocked (privacy mode, policy). Fall back to a no-op so the
  // page still renders; stars and settings then last only for this visit.
  function safeStorage() {
    const mem = new Map();
    const fallback = {
      getItem: (k) => (mem.has(k) ? mem.get(k) : null),
      setItem: (k, v) => { mem.set(k, String(v)); },
    };
    try {
      const ls = window.localStorage;
      const probe = "__tr_probe";
      ls.setItem(probe, "1");
      ls.removeItem(probe);
      return {
        getItem: (k) => { try { return ls.getItem(k); } catch { return fallback.getItem(k); } },
        setItem: (k, v) => { try { ls.setItem(k, v); } catch { fallback.setItem(k, v); } },
      };
    } catch {
      return fallback;
    }
  }
  function debounce(fn, ms) {
    let t;
    return function () {
      clearTimeout(t);
      t = setTimeout(() => fn.apply(this, arguments), ms);
    };
  }

  // ---------- Boot ---------------------------------------------------------

  function applyTheme(theme) {
    document.documentElement.dataset.theme = theme;
    const meta = $('meta[name="theme-color"]');
    if (meta) meta.setAttribute("content", theme === "dark" ? "#0a0d12" : "#f5f7fb");
  }

  function init() {
    applyTheme(store.getItem("tr_theme") || "dark");
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
      const next = document.documentElement.dataset.theme === "dark" ? "light" : "dark";
      applyTheme(next);
      store.setItem("tr_theme", next);
    });

    $("#search").addEventListener("input", debounce(() => {
      state.search = $("#search").value;
      render();
    }, 200));

    $("#sort-by").addEventListener("change", () => {
      state.sort = $("#sort-by").value;
      render();
    });

    $("#sidebar").addEventListener("click", onChipClick);
    $("#toggle-filters").addEventListener("click", () => {
      const open = $("#sidebar").classList.toggle("open");
      $("#toggle-filters").setAttribute("aria-expanded", String(open));
    });
    $("main").addEventListener("click", onFeedClick);

    $("#starred-only").addEventListener("click", () => {
      state.starredOnly = !state.starredOnly;
      render();
    });

    $("#auto-ja").addEventListener("click", () => setAutoJa(!state.autoJa));
    if (!svc.supported()) {
      $("#auto-ja").disabled = true;
      $("#auto-ja").title = i18n.t("toast.translate_unsupported");
    }

    $("#reset-filters").addEventListener("click", () => {
      state.filters = { ...F.EMPTY_FILTERS };
      state.starredOnly = false;
      state.search = "";
      render();
    });

    // If the model is already on disk no user gesture is needed.
    if (state.autoJa && svc.supported()) {
      svc.availability().then((a) => {
        if (a === "available") return svc.ensure().then(() => render());
      }).catch(() => {});
    }

    load();
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init);
  else init();
})();
