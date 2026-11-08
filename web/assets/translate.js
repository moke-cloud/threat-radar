// ThreatRadar — Japanese rendering of English titles / summaries.
//
// Uses the browser's built-in, on-device Translator API (Chrome 138+ desktop).
// No API key, nothing leaves the machine. Results are cached in localStorage
// so each item is translated once per browser. Browsers without the API get a
// Google Translate link instead (opened only when the user clicks it).
//
// Loaded in the browser as window.__translate and in Node tests via require().

(function (root) {
  const CACHE_KEY = "tr_ja_cache_v3";
  const CACHE_CAP = 800;
  const SUMMARY_MAX = 600;
  const JA_RE = /[぀-ヿ㐀-鿿]/;
  const PAIR = { sourceLanguage: "en", targetLanguage: "ja" };

  function isJapanese(s) { return JA_RE.test(String(s || "")); }

  function needsTranslation(it) {
    const text = (it.title || "") + (it.summary || "");
    return text.trim() !== "" && !isJapanese(text);
  }

  // Leading identifiers ("[CVSS 9.1 CRITICAL] CVE-2026-1 — ", "ZDI-26-833: ")
  // are kept verbatim; the translator mangles them otherwise.
  const PREFIX_RE = /^(?:\[[^\]]{1,40}\]\s*)?(?:(?:CVE-\d{4}-\d{4,}|ZDI-\d{2}-\d+|GHSA-[\w-]+)(?:\s*[—:–-]\s*|\s+))?/;
  function splitProtected(s) {
    const str = String(s || "");
    const keep = (str.match(PREFIX_RE) || [""])[0];
    return { keep, text: str.slice(keep.length) };
  }

  async function translateKeeping(t, s) {
    const { keep, text } = splitProtected(s);
    return keep + (text ? await t.translate(text) : "");
  }

  function clip(s, max) {
    const str = String(s || "");
    if (str.length <= max) return str;
    const cut = str.slice(0, max);
    const sp = cut.lastIndexOf(" ");
    return (sp > max * 0.6 ? cut.slice(0, sp) : cut) + "…";
  }

  // Small LRU on top of Map insertion order.
  function createCache(cap, initial) {
    const m = new Map(initial || []);
    while (m.size > cap) m.delete(m.keys().next().value);
    return {
      get(k) {
        if (!m.has(k)) return undefined;
        const v = m.get(k);
        m.delete(k); m.set(k, v);
        return v;
      },
      set(k, v) {
        m.delete(k); m.set(k, v);
        while (m.size > cap) m.delete(m.keys().next().value);
      },
      has(k) { return m.has(k); },
      entries() { return [...m.entries()]; },
    };
  }

  function googleTranslateURL(text) {
    const u = new URL("https://translate.google.com/");
    u.searchParams.set("sl", "auto");
    u.searchParams.set("tl", "ja");
    u.searchParams.set("op", "translate");
    u.searchParams.set("text", clip(text, 1500));
    return u.toString();
  }

  // Cache key includes a hash of the source text, so an item whose title or
  // summary changes under the same ID is translated again.
  function cacheKey(it) {
    const src = (it.title || "") + "\u0000" + (it.summary || "");
    let h = 0x811c9dc5;
    for (let i = 0; i < src.length; i++) {
      h ^= src.charCodeAt(i);
      h = Math.imul(h, 0x01000193) >>> 0;
    }
    return it.id + ":" + h.toString(36);
  }

  // ---------- Browser-only part ------------------------------------------

  function createService(storage) {
    let cache = createCache(CACHE_CAP, loadCache(storage));
    let translator = null;
    let creating = null;
    let queue = Promise.resolve();
    let saveTimer = null;

    function api() { return typeof root.Translator === "function" || typeof root.Translator === "object" ? root.Translator : null; }
    function supported() { return api() !== null; }

    // "unavailable" | "downloadable" | "downloading" | "available"
    async function availability() {
      const T = api();
      if (!T) return "unavailable";
      try { return await T.availability(PAIR); } catch { return "unavailable"; }
    }

    // Must be called from a user gesture the first time (model download).
    function ensure(onProgress) {
      if (translator) return Promise.resolve(translator);
      if (creating) return creating;
      const T = api();
      if (!T) return Promise.reject(new Error("Translator API not supported"));
      creating = T.create({
        ...PAIR,
        monitor(m) {
          m.addEventListener("downloadprogress", (e) => onProgress && onProgress(e.loaded));
        },
      }).then((t) => { translator = t; return t; })
        .finally(() => { creating = null; });
      return creating;
    }

    function ready() { return translator !== null; }

    function cached(it) {
      const v = cache.get(cacheKey(it));
      return v && typeof v.title === "string" && typeof v.summary === "string" ? v : undefined;
    }

    // Translations run one at a time; the on-device model is single-threaded.
    function translateItem(it) {
      const key = cacheKey(it);
      const hit = cached(it);
      if (hit) return Promise.resolve(hit);
      const job = queue.then(async () => {
        const t = await ensure();
        const again = cached(it);
        if (again) return again;
        const title = it.title ? await translateKeeping(t, it.title) : "";
        const summary = it.summary ? await translateKeeping(t, clip(it.summary, SUMMARY_MAX)) : "";
        const out = { title, summary };
        cache.set(key, out);
        scheduleSave();
        return out;
      });
      queue = job.catch(() => {});
      return job;
    }

    function scheduleSave() {
      if (saveTimer) return;
      saveTimer = setTimeout(() => {
        saveTimer = null;
        try { storage.setItem(CACHE_KEY, JSON.stringify(cache.entries())); }
        catch { cache = createCache(Math.floor(CACHE_CAP / 2), cache.entries().slice(-CACHE_CAP / 2)); }
      }, 1000);
    }

    return { supported, availability, ensure, ready, cached, translateItem };
  }

  function loadCache(storage) {
    try {
      const raw = storage && storage.getItem(CACHE_KEY);
      const arr = raw ? JSON.parse(raw) : [];
      return Array.isArray(arr) ? arr.filter((e) => Array.isArray(e) && e.length === 2) : [];
    } catch {
      return [];
    }
  }

  const exported = { isJapanese, splitProtected, cacheKey, needsTranslation, clip, createCache, googleTranslateURL, createService };
  if (typeof module !== "undefined" && module.exports) module.exports = exported;
  else root.__translate = exported;
})(typeof window !== "undefined" ? window : globalThis);
