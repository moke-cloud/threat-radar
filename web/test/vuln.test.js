// Run: node --test web/test/*.test.js
const test = require("node:test");
const assert = require("node:assert/strict");
const V = require("../assets/vuln.js");

test("cweName gives Japanese / English names and falls back to the ID", () => {
  assert.equal(V.cweName("CWE-787", "ja"), "境界外書き込み");
  assert.equal(V.cweName("CWE-787", "en"), "Out-of-bounds Write");
  assert.equal(V.cweName("CWE-99999", "ja"), "CWE-99999");
  assert.equal(V.cweName("", "ja"), "");
});

test("attackChips marks network / no-auth as strong", () => {
  const chips = V.attackChips({ av: "N", pr: "N", ui: "N" }, "ja");
  assert.deepEqual(chips.map((c) => c.label), ["ネットワーク経由", "認証不要", "操作不要"]);
  assert.deepEqual(chips.map((c) => c.strong), [true, true, false]);
  const local = V.attackChips({ av: "L", pr: "L", ui: "R" }, "en");
  assert.deepEqual(local.map((c) => c.label), ["local", "low privileges", "user interaction"]);
  assert.ok(local.every((c) => !c.strong));
  assert.deepEqual(V.attackChips(null, "ja"), []);
  assert.deepEqual(V.attackChips({ av: "X", pr: "?" }, "ja"), []);
  assert.deepEqual(V.attackChips({ av: "N", pr: "", ui: "R" }, "ja").map((c) => c.label), ["ネットワーク経由", "ユーザー操作が必要"]);
});

test("cvssFromTitle reads the score prefix", () => {
  assert.equal(V.cvssFromTitle("[CVSS 9.8 CRITICAL] CVE-2026-1 — x"), 9.8);
  assert.equal(V.cvssFromTitle("ZDI-26-1: x"), null);
});

test("vulnHeadline combines product and weakness, with fallbacks", () => {
  const nvd = { category: "vuln", product: "imgproxy", cwe: ["CWE-190"], cves: ["CVE-2026-123614"] };
  assert.deepEqual(V.vulnHeadline(nvd, "ja"), { subject: "imgproxy", kind: "整数オーバーフロー", cve: "CVE-2026-123614" });

  const zdi = { category: "vuln", product: "Valkey", cwe: ["CWE-122"], impact: "rce" };
  assert.equal(V.vulnHeadline(zdi, "ja").kind, "ヒープベースのバッファオーバーフロー（リモートコード実行）");

  const noProduct = { category: "vuln", cwe: ["CWE-79"], cves: ["CVE-2026-5"] };
  assert.equal(V.vulnHeadline(noProduct, "ja").subject, "CVE-2026-5");

  const tagOnly = { category: "vuln", tags: ["rce"], product: "Foo" };
  assert.equal(V.vulnHeadline(tagOnly, "ja").kind, "リモートコード実行");

  assert.equal(V.vulnHeadline({ category: "news", product: "x" }, "ja"), null);
  assert.equal(V.vulnHeadline({ category: "vuln" }, "ja"), null);
});
