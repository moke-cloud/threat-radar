# ThreatRadar

> **サイバーセキュリティの主要動向を自動で集めて並べる、ゼロ運用ダッシュボード。**

GitHub Actions が定期的に CISA KEV / NVD / JPCERT / 主要セキュリティニュース 12+ ソースから収集 → 重要度スコアリング → 静的サイトへ反映 → GitHub Pages で公開。

サーバー不要、APIキー不要、月額ゼロ円。

---

## 何を解決するか

RSS リーダーや Twitter を巡回して「KEV に何が入った? CVE-2026-XXXX は深刻か? JPCERT 注意喚起は出てるか?」を確認するのに 30 分使ってませんか? ThreatRadar はそれを **5 分以内のスキャンで終わる**1ページにまとめます。

- :red_circle: **CRITICAL バー**: KEV 新規 / CVSS 9+ / 既知の悪用観測のみ抽出
- :calendar: **今日の追加分**: 過去 24 時間の新着だけ
- :mag: **検索 + フィルタ**: ベンダー / タグ / ソース / 時期で絞り込み
- :star: **スター**: あとで読む
- :globe_with_meridians: **UI は JP/EN 切替** (項目本文は英語のまま — 翻訳が要るときは各カードの「コピー」ボタンから DeepL 等に貼り付け)
- :rss: **個人 RSS 出力**: 絞り込んだ条件を URL 化して RSS リーダーに登録

---

## ライブデモ

公開後: `https://moke-cloud.github.io/SHIGOTOBA/threat-radar/`

(リポジトリの GitHub Pages を `/threat-radar/web` に向ければ即公開)

---

## クイックスタート

### ローカルで一回だけ動かす

```powershell
cd E:\SHIGOTOBA\threat-radar\collector
go run ./cmd/collector -config ../config.yaml -out ../data
```

`data/items/YYYY-MM-DD.ndjson`, `data/index.json`, `data/critical.json` が生成されます。

ローカルでウェブを確認:

```powershell
cd E:\SHIGOTOBA\threat-radar\web
python -m http.server 8000
# → http://localhost:8000 を開く
```

### GitHub Actions で定期自動実行

`.github/workflows/threat-radar.yml` がデフォルトで毎日 06:30 JST (= 21:30 UTC 前日) に走ります。
リポジトリの **Settings → Pages** で `branch: dev / path: /threat-radar/web` を選べば公開完了。

---

## ディレクトリ構成

```
threat-radar/
├── README.md                # このファイル
├── docs/
│   ├── ARCHITECTURE.md      # 全体アーキ・データフロー
│   ├── SOURCES.md           # 全ソース一覧と取捨選択の理由
│   └── DEPLOYMENT.md        # 運用・カスタマイズ
├── collector/               # Go 製コレクター
│   ├── go.mod
│   ├── cmd/collector/main.go
│   ├── sources/             # ソースアダプター (RSS / JSON / Atom)
│   ├── normalize/           # 共通スキーマへの正規化
│   ├── enrich/              # スコアリング・タグ付け・重複排除
│   └── store/               # JSON 出力
├── config.yaml              # ソースリスト・チューニングパラメータ
├── data/                    # 生成物 (コミット対象)
│   ├── items/               # 1 日 1 ファイル NDJSON
│   ├── index.json           # 最新 500 件 (フロントが読む)
│   ├── critical.json        # CRITICAL のみ抽出
│   └── stats.json           # 集計値 (件数・ソース別など)
├── web/                     # 静的ダッシュボード (ビルドなし)
│   ├── index.html
│   └── assets/{app.js, styles.css, i18n.js}
└── .github/workflows/
    └── threat-radar.yml     # cron ジョブ
```

---

## ソース一覧 (v1)

| # | ソース | 形式 | 種別 |
|---:|---|---|---|
| 1 | CISA KEV (Known Exploited Vulnerabilities) | JSON | vuln |
| 2 | CISA Advisories | RSS | advisory |
| 3 | NVD CVE recent | JSON | vuln |
| 4 | JPCERT/CC 注意喚起 | RSS | advisory |
| 5 | JPCERT/CC Weekly Report | RSS | advisory |
| 6 | IPA セキュリティセンター | RSS | advisory |
| 7 | The Hacker News | RSS | news |
| 8 | Bleeping Computer | RSS | news |
| 9 | Krebs on Security | RSS | news |
| 10 | SANS Internet Storm Center | RSS | news |
| 11 | Schneier on Security | RSS | analysis |
| 12 | Project Zero | Atom | research |
| 13 | Microsoft Security Response Center | RSS | advisory |
| 14 | Google Online Security Blog | RSS | research |

詳細は [docs/SOURCES.md](docs/SOURCES.md)。
追加・除外は `config.yaml` の `sources:` リストを編集するだけ。

---

## スコアリング

各アイテムには 0-100 の `score` がつき、`severity` ラベルが決まる。

| severity | score | 例 |
|---|---:|---|
| `critical` | 80-100 | KEV 新規追加 / CVSS 9.0+ + actively exploited |
| `high` | 60-79 | CVSS 7.0+ / "0day" / 主要ベンダー RCE |
| `medium` | 30-59 | 一般 advisory / 解析記事 |
| `low` | 0-29 | コラム / ベストプラクティス記事 |
| `info` | — | RSS の汎用エントリ (デフォルト) |

スコアは決定論的なヒューリスティックで計算 (LLM 不要)。詳細は `collector/enrich/scorer.go` 参照。

---

## カスタマイズ

### ベンダーウォッチリスト

`config.yaml`:

```yaml
watch:
  vendors: [microsoft, cisco, fortinet, paloalto, citrix, vmware, ivanti]
  tags:    [ransomware, supply-chain, 0day, kev]
```

該当ベンダー/タグのアイテムは critical.json に常駐 (severity が下でも目立たせる)。

### ソースの追加

`config.yaml`:

```yaml
sources:
  - id: my-blog
    name: "My Custom Security Blog"
    type: rss
    url: https://example.com/feed.xml
    category: news
    weight: 0.6   # スコア寄与の係数 (0.0 - 1.5)
```

### 翻訳について

LLM での自動翻訳は意図的に**入れていません**。理由:

- API キーを CI に置くと管理コストと漏洩リスクがある
- 機械翻訳の品質バラつきがフィードの信頼性を損なう

代わりに各アイテムカードに「⧉ コピー」ボタンを置きました。クリックすると
`title / summary / source URL` がプレーンテキストでクリップボードに入るので、
DeepL や ChatGPT に貼り付けて翻訳できます。

---

## ライセンス

- コード: MIT
- 取得したコンテンツ自体: 各ソースの利用規約に従う (このリポジトリは要約・リンク・タイトルのみ保持)

---

## なぜ作ったか

1日 30 分 × 営業日 250 日 = 年間 125 時間を脅威情報の巡回に使っていることに気づいたため。
集めて並べる作業は機械の仕事、判断する作業は人間の仕事。
