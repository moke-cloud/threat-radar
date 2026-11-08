// ThreatRadar — vulnerability cards built from structured fields (CWE,
// CVSS attack conditions, product) instead of translated prose.
// Loaded in the browser as window.__vuln and in Node tests via require().
//
// Japanese CWE names follow the wording used by IPA / JVN where one exists.

(function (root) {
  const CWE = {
    "CWE-20": ["不適切な入力確認", "Improper Input Validation"],
    "CWE-22": ["パス・トラバーサル", "Path Traversal"],
    "CWE-59": ["リンク解釈の問題", "Link Following"],
    "CWE-73": ["外部からのファイルパスの操作", "External Control of File Name or Path"],
    "CWE-74": ["インジェクション", "Injection"],
    "CWE-77": ["コマンドインジェクション", "Command Injection"],
    "CWE-78": ["OS コマンドインジェクション", "OS Command Injection"],
    "CWE-79": ["クロスサイトスクリプティング", "Cross-site Scripting"],
    "CWE-88": ["引数インジェクション", "Argument Injection"],
    "CWE-89": ["SQL インジェクション", "SQL Injection"],
    "CWE-90": ["LDAP インジェクション", "LDAP Injection"],
    "CWE-91": ["XML インジェクション", "XML Injection"],
    "CWE-94": ["コードインジェクション", "Code Injection"],
    "CWE-98": ["PHP ファイルインクルージョン", "PHP File Inclusion"],
    "CWE-113": ["HTTP レスポンス分割", "HTTP Response Splitting"],
    "CWE-119": ["バッファエラー", "Memory Buffer Error"],
    "CWE-120": ["バッファオーバーフロー", "Buffer Overflow"],
    "CWE-121": ["スタックベースのバッファオーバーフロー", "Stack-based Buffer Overflow"],
    "CWE-122": ["ヒープベースのバッファオーバーフロー", "Heap-based Buffer Overflow"],
    "CWE-125": ["境界外読み取り", "Out-of-bounds Read"],
    "CWE-134": ["書式文字列の問題", "Format String"],
    "CWE-190": ["整数オーバーフロー", "Integer Overflow"],
    "CWE-191": ["整数アンダーフロー", "Integer Underflow"],
    "CWE-197": ["数値の切り捨てエラー", "Numeric Truncation Error"],
    "CWE-200": ["情報漏えい", "Information Exposure"],
    "CWE-201": ["送信データへの機密情報の混入", "Insertion of Sensitive Information Into Sent Data"],
    "CWE-209": ["エラーメッセージからの情報漏えい", "Information Exposure via Error Message"],
    "CWE-250": ["不要な特権での実行", "Execution with Unnecessary Privileges"],
    "CWE-256": ["パスワードの平文保存", "Plaintext Storage of a Password"],
    "CWE-259": ["ハードコードされたパスワード", "Hard-coded Password"],
    "CWE-269": ["不適切な権限管理", "Improper Privilege Management"],
    "CWE-276": ["不適切なデフォルトパーミッション", "Incorrect Default Permissions"],
    "CWE-284": ["不適切なアクセス制御", "Improper Access Control"],
    "CWE-285": ["不適切な認可", "Improper Authorization"],
    "CWE-287": ["不適切な認証", "Improper Authentication"],
    "CWE-288": ["代替経路による認証回避", "Authentication Bypass by Alternate Path"],
    "CWE-290": ["なりすましによる認証回避", "Authentication Bypass by Spoofing"],
    "CWE-294": ["キャプチャ・リプレイによる認証回避", "Authentication Bypass by Capture-replay"],
    "CWE-295": ["不適切な証明書検証", "Improper Certificate Validation"],
    "CWE-306": ["重要な機能に対する認証の欠如", "Missing Authentication for Critical Function"],
    "CWE-307": ["認証試行回数の制限不備", "Improper Restriction of Excessive Authentication Attempts"],
    "CWE-311": ["重要なデータの暗号化の欠如", "Missing Encryption of Sensitive Data"],
    "CWE-312": ["重要な情報の平文保存", "Cleartext Storage of Sensitive Information"],
    "CWE-321": ["ハードコードされた暗号鍵", "Hard-coded Cryptographic Key"],
    "CWE-319": ["重要な情報の平文送信", "Cleartext Transmission of Sensitive Information"],
    "CWE-327": ["危殆化した暗号アルゴリズムの使用", "Use of a Broken or Risky Cryptographic Algorithm"],
    "CWE-338": ["暗号論的に弱い擬似乱数生成器の使用", "Use of Cryptographically Weak PRNG"],
    "CWE-345": ["データの真正性の検証不備", "Insufficient Verification of Data Authenticity"],
    "CWE-347": ["暗号署名の不適切な検証", "Improper Verification of Cryptographic Signature"],
    "CWE-352": ["クロスサイトリクエストフォージェリ", "Cross-Site Request Forgery"],
    "CWE-362": ["競合状態", "Race Condition"],
    "CWE-367": ["TOCTOU 競合状態", "TOCTOU Race Condition"],
    "CWE-384": ["セッション固定", "Session Fixation"],
    "CWE-400": ["リソースの枯渇", "Uncontrolled Resource Consumption"],
    "CWE-415": ["二重解放", "Double Free"],
    "CWE-416": ["解放済みメモリの使用", "Use After Free"],
    "CWE-427": ["制御されていない検索パスの要素", "Uncontrolled Search Path Element"],
    "CWE-434": ["危険なタイプのファイルのアップロード", "Unrestricted File Upload"],
    "CWE-457": ["未初期化変数の使用", "Use of Uninitialized Variable"],
    "CWE-476": ["NULL ポインタ参照", "NULL Pointer Dereference"],
    "CWE-489": ["デバッグコードの残存", "Active Debug Code"],
    "CWE-502": ["信頼できないデータのデシリアライゼーション", "Deserialization of Untrusted Data"],
    "CWE-521": ["脆弱なパスワード要件", "Weak Password Requirements"],
    "CWE-522": ["不十分な認証情報の保護", "Insufficiently Protected Credentials"],
    "CWE-532": ["ログファイルへの機密情報の出力", "Sensitive Information in Log File"],
    "CWE-552": ["外部からアクセス可能なファイルやディレクトリ", "Files Accessible to External Parties"],
    "CWE-601": ["オープンリダイレクト", "Open Redirect"],
    "CWE-611": ["XML 外部実体参照（XXE）", "XML External Entity Reference"],
    "CWE-613": ["不十分なセッションの有効期限", "Insufficient Session Expiration"],
    "CWE-617": ["到達可能なアサーション", "Reachable Assertion"],
    "CWE-639": ["ユーザ制御の鍵による認可回避（IDOR）", "Authorization Bypass Through User-Controlled Key"],
    "CWE-640": ["パスワード回復の不備", "Weak Password Recovery Mechanism"],
    "CWE-668": ["誤った領域へのリソースの公開", "Exposure of Resource to Wrong Sphere"],
    "CWE-674": ["制御されていない再帰", "Uncontrolled Recursion"],
    "CWE-693": ["保護メカニズムの不備", "Protection Mechanism Failure"],
    "CWE-732": ["重要なリソースに対する不適切なパーミッション", "Incorrect Permission Assignment for Critical Resource"],
    "CWE-749": ["危険なメソッドの公開", "Exposed Dangerous Method"],
    "CWE-755": ["例外的な状態の不適切な処理", "Improper Handling of Exceptional Conditions"],
    "CWE-770": ["制限のないリソースの割り当て", "Allocation of Resources Without Limits"],
    "CWE-787": ["境界外書き込み", "Out-of-bounds Write"],
    "CWE-798": ["ハードコードされた認証情報", "Hard-coded Credentials"],
    "CWE-829": ["信頼されない制御領域からの機能の取り込み", "Inclusion of Functionality from Untrusted Control Sphere"],
    "CWE-835": ["無限ループ", "Infinite Loop"],
    "CWE-843": ["型の取り違え", "Type Confusion"],
    "CWE-862": ["認可の欠如", "Missing Authorization"],
    "CWE-863": ["不適切な認可", "Incorrect Authorization"],
    "CWE-908": ["未初期化リソースの使用", "Use of Uninitialized Resource"],
    "CWE-912": ["隠し機能", "Hidden Functionality"],
    "CWE-915": ["動的に決定されるオブジェクト属性の不適切な制御", "Improperly Controlled Modification of Dynamically-Determined Object Attributes"],
    "CWE-918": ["サーバサイドリクエストフォージェリ（SSRF）", "Server-Side Request Forgery"],
    "CWE-922": ["機密情報の安全でない保存", "Insecure Storage of Sensitive Information"],
    "CWE-1021": ["UI レイヤーの不適切な制限（クリックジャッキング）", "Improper Restriction of Rendered UI Layers"],
    "CWE-1236": ["CSV インジェクション", "CSV Injection"],
    "CWE-1321": ["プロトタイプ汚染", "Prototype Pollution"],
    "CWE-1333": ["非効率な正規表現（ReDoS）", "Inefficient Regular Expression Complexity"],
    "CWE-1336": ["サーバサイドテンプレートインジェクション", "Server-Side Template Injection"],
  };

  const IMPACT = {
    "rce": ["リモートコード実行", "remote code execution"],
    "lpe": ["権限昇格", "privilege escalation"],
    "info": ["情報漏えい", "information disclosure"],
    "dos": ["サービス運用妨害", "denial of service"],
    "auth-bypass": ["認証回避", "authentication bypass"],
    "feature-bypass": ["セキュリティ機能の回避", "security feature bypass"],
    "ssrf": ["SSRF", "SSRF"],
    "xss": ["クロスサイトスクリプティング", "cross-site scripting"],
    "file-delete": ["任意のファイル削除", "arbitrary file deletion"],
    "file-write": ["任意のファイル書き込み", "arbitrary file write"],
    "file-read": ["任意のファイル読み取り", "arbitrary file read"],
    "path-traversal": ["パス・トラバーサル", "path traversal"],
    "sqli": ["SQL インジェクション", "SQL injection"],
    "command-injection": ["コマンドインジェクション", "command injection"],
  };

  // Tags the tagger derives from free text, used when nothing better exists.
  const TAG_IMPACT = ["rce", "auth-bypass", "lpe", "sqli", "xss", "path-traversal"];

  const ATTACK = {
    av: {
      N: ["ネットワーク経由", "network", true],
      A: ["隣接ネットワーク", "adjacent network", false],
      L: ["ローカル", "local", false],
      P: ["物理アクセス", "physical", false],
    },
    pr: {
      N: ["認証不要", "no authentication", true],
      L: ["一般権限が必要", "low privileges", false],
      H: ["管理者権限が必要", "high privileges", false],
    },
    ui: {
      N: ["操作不要", "no user interaction", false],
      R: ["ユーザー操作が必要", "user interaction", false],
    },
  };

  const idx = (lang) => (lang === "en" ? 1 : 0);

  function cweName(id, lang) {
    if (!id) return "";
    const e = CWE[id];
    return e ? e[idx(lang)] : id;
  }

  function impactName(key, lang) {
    const e = IMPACT[key];
    return e ? e[idx(lang)] : "";
  }

  function attackChips(a, lang) {
    // PR may be unknown (ZDI omits it when user interaction is required).
    if (!a || !ATTACK.av[a.av]) return [];
    const out = [];
    for (const k of ["av", "pr", "ui"]) {
      const e = ATTACK[k][a[k]];
      if (e) out.push({ label: e[idx(lang)], strong: e[2] });
    }
    return out;
  }

  function cvssFromTitle(title) {
    const m = /^\[CVSS (\d{1,2}(?:\.\d)?) /.exec(String(title || ""));
    return m ? Number(m[1]) : null;
  }

  // { subject, kind, cve } or null when the item is not a vulnerability
  // record or carries nothing to build a card from.
  function vulnHeadline(it, lang) {
    if (!it || it.category !== "vuln") return null;
    const cwe = (it.cwe || []).find((c) => CWE[c]) || (it.cwe || [])[0] || "";
    const weakness = cweName(cwe, lang);
    let impact = impactName(it.impact, lang);
    if (!weakness && !impact) {
      const tag = TAG_IMPACT.find((t) => (it.tags || []).includes(t));
      impact = tag ? impactName(tag, lang) : "";
    }
    let kind = weakness || impact;
    if (weakness && impact && impact !== weakness) {
      kind = lang === "en" ? `${weakness} (${impact})` : `${weakness}（${impact}）`;
    }
    const cve = (it.cves || [])[0] || "";
    const subject = it.product || cve;
    if (!kind || !subject) return null;
    return { subject, kind, cve };
  }

  const api = { cweName, impactName, attackChips, cvssFromTitle, vulnHeadline };
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  else root.__vuln = api;
})(typeof window !== "undefined" ? window : globalThis);
