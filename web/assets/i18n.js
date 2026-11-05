window.__i18n = (function () {
  const dict = {
    ja: {
      "filter.severity": "重要度",
      "filter.category": "カテゴリ",
      "filter.source": "ソース",
      "filter.tag": "タグ",
      "filter.vendor": "ベンダー",
      "wall.title": "Critical & High — 直近 7 日",
      "today.title": "直近 24 時間",
      "all.title": "全件",
      "sort.published": "公開日 (新しい順)",
      "sort.score": "スコア (高い順)",
      "action.reset": "フィルタをリセット",
      "action.star": "スター",
      "action.copy": "コピー (タイトル+概要+URL)",
      "toast.copied": "コピーしました",
      "state.loading": "読み込み中…",
      "state.empty": "該当なし",
      "state.fetch_failed": "データ取得に失敗しました",
      "stats.last24h": "24h",
      "stats.critical": "critical",
      "stats.total": "total",
      "stats.updated": "更新",
      "filter.view": "表示",
      "action.starred_only": "スターのみ",
      "sort.epss": "EPSS (高い順)",
      "epss.title": "FIRST EPSS: 30 日以内に悪用される確率の予測",
      "corroboration": "{n} ソース",
      "health.title": "ソースの状態",
      "health.problems": "{total} 件中 {n} 件に問題",
      "health.all_ok": "{total} 件すべて正常",
      "health.last_item": "最新記事",
      "health.ok": "正常",
      "health.error": "取得失敗",
      "health.stale": "更新停止?",
      "health.empty": "0 件",
    },
    en: {
      "filter.severity": "severity",
      "filter.category": "category",
      "filter.source": "source",
      "filter.tag": "tag",
      "filter.vendor": "vendor",
      "wall.title": "Critical & high — last 7 days",
      "today.title": "Last 24 hours",
      "all.title": "All items",
      "sort.published": "published (newest)",
      "sort.score": "score (highest)",
      "action.reset": "reset filters",
      "action.star": "star",
      "action.copy": "copy (title + summary + URL)",
      "toast.copied": "copied",
      "state.loading": "loading…",
      "state.empty": "no matches",
      "state.fetch_failed": "failed to fetch data",
      "stats.last24h": "24h",
      "stats.critical": "critical",
      "stats.total": "total",
      "stats.updated": "updated",
      "filter.view": "view",
      "action.starred_only": "starred only",
      "sort.epss": "EPSS (highest)",
      "epss.title": "FIRST EPSS: predicted probability of exploitation in the next 30 days",
      "corroboration": "{n} sources",
      "health.title": "source status",
      "health.problems": "{n} of {total} need attention",
      "health.all_ok": "all {total} healthy",
      "health.last_item": "latest item",
      "health.ok": "ok",
      "health.error": "fetch failed",
      "health.stale": "stale?",
      "health.empty": "empty",
    },
  };
  let current = localStorage.getItem("tr_lang") || "ja";
  function t(key) {
    return (dict[current] && dict[current][key]) || dict.ja[key] || key;
  }
  function setLang(c) {
    current = c === "en" ? "en" : "ja";
    localStorage.setItem("tr_lang", current);
    document.documentElement.lang = current;
    document.querySelectorAll("[data-i18n]").forEach((el) => {
      el.textContent = t(el.dataset.i18n);
    });
    document.querySelectorAll("[data-i18n-attr]").forEach((el) => {
      const [attr, key] = el.dataset.i18nAttr.split(":");
      el.setAttribute(attr, t(key));
    });
  }
  function getLang() { return current; }
  return { t, setLang, getLang };
})();
