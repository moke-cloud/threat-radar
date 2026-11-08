# Architecture

ThreatRadar は **3 つのレイヤー**で構成されています。

```
+-------------------+     cron     +---------------------+    rebuild   +-----------------+
|  Source Adapters  | ───────────▶ |  Collector + Enrich | ───────────▶ |  Static Web UI  |
|  (RSS/JSON/Atom)  |   毎日21:30   |    (Go binary)      |   commit     |  (HTML+JS+CSS)  |
+-------------------+      UTC     +---------------------+   to repo    +-----------------+
                                              │                                  │
                                              ▼                                  ▼
                                       data/items/*.ndjson             gh-pages or main/web
                                       data/index.json                 (公開対象)
                                       data/critical.json
                                       data/stats.json
```

すべて静的ファイルベース。サーバーもデータベースも持たない。

---

## レイヤー 1: ソースアダプター

`collector/sources/`

各ソース (CISA KEV / NVD / RSS フィード等) を 1 ファイル 1 アダプターで実装。

```go
type Source interface {
    ID() string                // "cisa-kev"
    Name() string              // "CISA Known Exploited Vulnerabilities"
    Category() string          // "vuln" | "advisory" | "news" | "research"
    Fetch(ctx context.Context) ([]RawItem, error)
}
```

- **RSS 系** (大多数) は `sources/rss.go` の汎用 fetcher で 1 行設定で追加可。
- **特殊形式** (CISA KEV の JSON, NVD の JSON, GitHub Advisories の REST) は専用ファイル。
- すべて HTTP タイムアウト 30 秒 / リトライ 1 回 / User-Agent `ThreatRadar/<ver>`。

### Raw → Item 正規化

`collector/normalize/normalize.go` が `RawItem` を共通の `Item` スキーマに変換:

```go
type Item struct {
    ID         string    `json:"id"`           // sha256(source+url) で安定
    Source     string    `json:"source"`       // adapter ID
    Category   string    `json:"category"`     // vuln / advisory / news / research / analysis
    Title      string    `json:"title"`
    URL        string    `json:"url"`
    Summary    string    `json:"summary"`
    Published  time.Time `json:"published"`
    Fetched    time.Time `json:"fetched"`
    Tags       []string  `json:"tags"`         // ["rce", "actively-exploited", "msft"]
    Severity   string    `json:"severity"`     // critical/high/medium/low/info
    Score      int       `json:"score"`        // 0-100
    Vendors    []string  `json:"vendors,omitempty"`
    CVEs       []string  `json:"cves,omitempty"`
    // (項目本文の翻訳はブラウザ内蔵 Translator API で行う — 収集側は持たない)
    Raw        string    `json:"raw,omitempty"`         // デバッグ用 (本番は省略)
}
```

`ID` を `sha256(source+url)` にすることで、同じアイテムが翌日の収集でも同一 ID になり、重複排除が決定論的になる。

---

## レイヤー 2: 収集 + 強化

`collector/cmd/collector/main.go` がオーケストレーターで、以下を順次実行:

1. **並列 fetch**: 全ソースを `errgroup` で並列に叩く (デフォルト並列度 8)
2. **Normalize**: 各 RawItem を Item に変換
3. **Tag**: `enrich/tagger.go` がタイトル + サマリから RegExp でタグを付与 (CVE ID, ベンダー名, 攻撃クラス)
4. **Score**: `enrich/scorer.go` が決定論的に severity を判定
5. **Dedup**: `enrich/deduper.go` が既存 NDJSON との ID 重複を除外
6. **(任意) LLM enrichment**: 不採用 — API キー管理コストを避ける。日本語化は閲覧側のブラウザ内蔵翻訳 (web/assets/translate.js) で行う
7. **Persist**: `store/store.go` が NDJSON / index.json / critical.json / stats.json を書き出し

### スコアリング詳細

`enrich/scorer.go` のロジック:

```
base_score = source.weight * 30           # ソース固有の基礎点
+ 30  if tag in ["actively-exploited", "kev", "0day"]
+ 20  if tag in ["rce", "auth-bypass", "supply-chain"]
+ 15  if cvss >= 9.0
+ 10  if cvss >= 7.0
+ 10  if matches watch.vendors
+ 10  if matches watch.tags
- 15  if old (published > 7 days ago)

cap [0, 100]
```

severity ラベル:
- `score >= 80` → critical
- `score >= 60` → high
- `score >= 30` → medium
- `score >= 10` → low
- `else`        → info

### タグ付け詳細

`enrich/tagger.go` は以下のパターンで自動付与:

- CVE ID: `CVE-\d{4}-\d{4,7}` → `cves[]`
- ベンダー: 既知リスト (microsoft / cisco / fortinet / ...) → `vendors[]`, `tag`
- 攻撃クラス: "remote code execution", "authentication bypass", "SQL injection" 等のキーワード → `tag`
- 状態語: "actively exploited", "in the wild", "ransomware", "0day", "supply chain" → `tag`
- ソース固有: KEV 由来のものは自動的に `kev` タグ

---

## レイヤー 3: 静的フロントエンド

`web/index.html` 単一ファイル + 数 KB の `app.js` / `styles.css`。
**ビルドステップなし。Tailwind なし。** 軽くて GitHub Pages で即動く構成を優先。

起動シーケンス:

1. `index.html` 読み込み
2. `app.js` が `data/index.json` を `fetch()` で取得 (相対パス)
3. アイテム一覧をレンダリング (仮想スクロールではなく単純 DOM。500 件なら問題なし)
4. URL ハッシュ (`#tag=rce&severity=critical`) を解釈してフィルタ適用
5. ローカルストレージから既読/スター情報を復元

機能:

- 検索 (タイトル・要約・CVE・ソース名・タグ・ベンダー。空白区切りで AND)
- フィルタ (severity / category / source / vendor / tag)。全セクションに効く。件数は他の条件を掛けた後の数。状態は URL クエリに残る (共有・再読み込み可)
- 並び替え (日付 / score / EPSS)
- UI 言語切替 (フィルタ・見出しの JP/EN)
- 英語記事の日本語表示 (Chrome 内蔵 Translator API・端末内処理・localStorage キャッシュ。非対応ブラウザは Google 翻訳リンク)
- アイテムごとのコピー (タイトル + 概要 + URL) — 翻訳ツールへ貼り付け用
- ダーク/ライトトグル (デフォルトはシステム preferred-color-scheme)
- スター (localStorage)
- 既読 (localStorage)

---

## CI/CD

`.github/workflows/threat-radar.yml`:

```yaml
on:
  schedule: [{cron: "30 21 * * *"}]   # 毎日 21:30 UTC = 06:30 JST
  workflow_dispatch:                   # 手動実行可

jobs:
  collect:
    steps:
      - actions/checkout
      - actions/setup-go (1.22)
      - go run ./threat-radar/collector/cmd/collector
      - git commit data/
      - git push
```

データの書き戻しは `dev` ブランチに直接 commit (PR は作らない、データだけなので)。
GH Pages はそのブランチを見ているので即反映。

---

## 拡張ポイント

| 望むもの | 場所 | 工数 |
|---|---|---|
| 新しい RSS ソース追加 | `config.yaml` に 1 エントリ | 1 分 |
| 専用フォーマットのソース | `sources/foo.go` 新規 + `Source` interface 実装 | 1 時間 |
| ベンダー検出ルール追加 | `enrich/tagger.go` のリスト | 5 分 |
| 重要度ロジック調整 | `enrich/scorer.go` | 30 分 |
| 収集側で翻訳 (全ブラウザ対応にしたい場合) | `enrich/translator.go` で GitHub Models (Actions の GITHUB_TOKEN、`permissions: models: read`) を呼び `title_ja` / `summary_ja` を保存、`web/assets/translate.js` は `*_ja` を優先 | 半日 (無料枠の回数制限あり) |
| Slack / Discord 通知 | `cmd/collector/notify.go` 追加 | 1-2 時間 |
| CSV 出力 | `store/csv.go` 追加 | 30 分 |
| 過去ログ全文検索 (lunr.js) | `web/assets/search.js` 追加 | 半日 |

---

## 失敗モード

- **ソース 1 つが落ちている** → そのソースだけスキップ。他は継続。`stats.json` に source_health: false を記録。
- **HTTP タイムアウト** → 30 秒で諦め、次のサイクルで再試行。
- **構文不正な RSS** → `sources/rss.go` がエラーを `slog.Warn` でログし、その feed の項目は 0 件として扱う。
- **GitHub Actions が止まる** → 手動 `workflow_dispatch` で再実行可能。データは git に履歴があるので消えない。
- **(LLM 機能は不採用)** — 外部 AI API への依存ゼロ。脅威ソースが落ちる以外の失敗モードは無い。

---

## 設計判断 (なぜそうしたか)

- **DB ではなく JSON ファイル**: アイテム数が 1 日 50-200 程度しかない。git diff で履歴を見られる。バックアップ問題ゼロ。
- **ビルドステップなしのフロント**: メンテナンス対象を増やしたくない。ブラウザがネイティブで読める HTML+JS で十分速い。
- **GitHub Pages**: 別ホスティング不要。クレデンシャル不要。
- **Go**: ユーザーが既に eml-analyzer で Go を使っており継続性がある。HTTP 並列・JSON・YAML が標準ライブラリで十分。
- **収集側で LLM は使わない**: API キー管理コストと外部依存を避ける。日本語化はブラウザ内蔵の翻訳 API で閲覧側が行う (キー不要・端末内)。
