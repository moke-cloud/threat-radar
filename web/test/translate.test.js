// Run: node --test web/test/*.test.js
const test = require("node:test");
const assert = require("node:assert/strict");
const T = require("../assets/translate.js");

test("isJapanese detects kana / kanji", () => {
  assert.equal(T.isJapanese("ECサイトで個人情報が流出"), true);
  assert.equal(T.isJapanese("Remote code execution in Valkey"), false);
  assert.equal(T.isJapanese(""), false);
});

test("needsTranslation: English title or summary, never Japanese items", () => {
  assert.equal(T.needsTranslation({ title: "Valkey RCE", summary: "x" }), true);
  assert.equal(T.needsTranslation({ title: "まとめ", summary: "不正アクセス" }), false);
  assert.equal(T.needsTranslation({ title: "", summary: "" }), false);
});

test("clip trims long summaries at a word boundary", () => {
  const long = "word ".repeat(400);
  const out = T.clip(long, 100);
  assert.ok(out.length <= 101);
  assert.ok(out.endsWith("…"));
  assert.equal(T.clip("short", 100), "short");
});

test("LRU cache evicts oldest entries beyond the cap", () => {
  const c = T.createCache(2);
  c.set("a", 1); c.set("b", 2); c.get("a"); c.set("c", 3);
  assert.equal(c.get("b"), undefined);
  assert.equal(c.get("a"), 1);
  assert.equal(c.get("c"), 3);
  assert.deepEqual(T.createCache(2, c.entries()).entries().length, 2);
});

test("googleTranslateURL encodes text and targets Japanese", () => {
  const u = new URL(T.googleTranslateURL("a&b c"));
  assert.equal(u.hostname, "translate.google.com");
  assert.equal(u.searchParams.get("tl"), "ja");
  assert.equal(u.searchParams.get("text"), "a&b c");
});

test("splitProtected keeps CVSS / CVE prefixes out of translation", () => {
  assert.deepEqual(T.splitProtected("[CVSS 9.1 CRITICAL] CVE-2026-12345 — A flaw in X"),
    { keep: "[CVSS 9.1 CRITICAL] CVE-2026-12345 — ", text: "A flaw in X" });
  assert.deepEqual(T.splitProtected("ZDI-26-833: Valkey RCE"), { keep: "ZDI-26-833: ", text: "Valkey RCE" });
  assert.deepEqual(T.splitProtected("Plain title"), { keep: "", text: "Plain title" });
});

test("cacheKey changes when the source text changes", () => {
  const a = T.cacheKey({ id: "x", title: "t", summary: "s" });
  assert.equal(a, T.cacheKey({ id: "x", title: "t", summary: "s" }));
  assert.notEqual(a, T.cacheKey({ id: "x", title: "t2", summary: "s" }));
});
