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
- :star: **スター**: あとで読む。「スターのみ」で絞り込み
- :chart_with_upwards_trend: **EPSS**: CVE ごとに悪用予測の確率を表示。EPSS 順にも並べられる
- :link: **複数ソースの印**: 同じ CVE を報じたソースの数を表示し、押すとその CVE で絞り込む
- :satellite: **ソースの状態**: 取得失敗や更新停止のフィードを画面上部に表示
- :globe_with_meridians: **UI は JP/EN 切替**。脆弱性は「製品名 — 種類 + 攻撃条件」のカードで、記事は収集時の日本語訳 (Actions 内で動かす小型 LLM・API キー不要) で、どの端末でも日本語で読める

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

## ソース一覧 (v2, 2026-11)

31 ソースをキー不要の公開フィードで集めています。

| 種別 | ソース |
|---|---|
| 政府機関・CSIRT | CISA KEV / CISA Advisories / NVD / JPCERT/CC (注意喚起・全フィード) / IPA / JC3 / フィッシング対策協議会 |
| 悪用の観測・PoC | GreyNoise / Cloudflare Threat Intelligence (Zero Wire) / ZDI / Exploit-DB |
| ベンダーの脅威リサーチ | Google Threat Intelligence (Mandiant) / Microsoft Threat Intelligence / Unit 42 / Cisco Talos / Project Zero / watchTowr Labs / Securelist / Check Point Research / Sekoia / The DFIR Report / Rapid7 / ESET / Google Online Security Blog / Trail of Bits |
| ニュース | BleepingComputer / Krebs on Security / SANS ISC / piyolog / Security NEXT |

CVE には FIRST EPSS（30日以内に悪用される確率の予測）を付けます。
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

### 日本語化と見せ方

英語の記事は 2 種類に分けて扱う。

**脆弱性レコード (NVD・ZDI・CISA KEV)** は文章を訳さず、構造化された情報から日本語のカードを組み立てる。

- 見出しは「製品名 — 脆弱性の種類」。種類は CWE 番号から日本語名を引く (IPA / JVN の呼び方に合わせる)。ZDI は決まった形のタイトルから原因と影響を読み取る
- その下に攻撃条件を並べる: ネットワーク経由 / 認証不要 / 操作不要 など (CVSS ベクトル、または ZDI の定型文から)。危険度の高い 2 つ (ネットワーク経由・認証不要) だけ色を付ける
- 製品名は CISA KEV と ZDI ではデータから直接取る。NVD は本文から小型 LLM に抜き出させ、本文にそのまま現れる名前だけを採用する (作り話を防ぐ)
- 本文は英語の原文のまま見せる。必要なときはブラウザ内蔵の翻訳で訳せる

**記事 (ニュース・各社ブログ・注意喚起)** は小型 LLM で全文を訳す。

- 日本語の見出しの下に、原文の見出しを小さく常に表示する。▾ で開くと要約の全文と原文が読める。訳文には「機械翻訳」の印が付く
- 社名・製品名 (SonicWall、Cisco など) をカタカナにした訳は捨てる。ほかに、日本語が無い / 元の CVE 番号が消えた / 異様に長い / 識別子が元とほとんど重ならない (別記事の訳と取り違えた疑い) 訳も捨て、次回に訳し直す
- まだ訳が無い記事は、ブラウザ内蔵の翻訳 API (Chrome 138 以降のデスクトップ版・端末内処理) で補う。それも無ければ「訳」ボタンが Google 翻訳へのリンクになる

**仕組み**

- 毎朝の Actions は 2 段。まず収集して公開し (約 2 分)、そのあと翻訳ジョブが走って公開し直す。新着は翻訳を待たずに出る
- 翻訳は Actions の runner 上で [llama.cpp](https://github.com/ggml-org/llama.cpp) の `llama-server` (b11740) と Qwen3-4B-Instruct-2507 (Q4_K_M・約 2.5GB) を動かして行う。`scripts/start-llm.sh` がバージョンを固定して取得し、SHA-256 を照合してから起動する。モデルは Actions のキャッシュに置く
- **API キー・Secrets は不要。記事の文面は runner の外に出ない** (送り先は 127.0.0.1 だけに制限)
- スコアの高い記事から順に処理し、1 回の実行で最大 30 分。残りは次回に回す。1 件ずつ送る (まとめて送ると小型モデルが項目を落としたり取り違えたりするため)
- 結果は `data/translations.json` にキャッシュし、記事の本文が変わらない限りやり直さない。日本語の記事は送らない
- 8B モデルも試したが、速度が約 1.8 倍かかるうえ、社名や人名のカタカナ化・曜日の誤訳が増えたため採用していない

従来どおり「⧉ コピー」ボタンで `title / summary / source URL` をクリップボードに入れ、DeepL などに貼ることもできる。

---

## ライセンス

- コード: MIT
- 取得したコンテンツ自体: 各ソースの利用規約に従う (このリポジトリは要約・リンク・タイトルのみ保持)

---

## なぜ作ったか

1日 30 分 × 営業日 250 日 = 年間 125 時間を脅威情報の巡回に使っていることに気づいたため。
集めて並べる作業は機械の仕事、判断する作業は人間の仕事。
