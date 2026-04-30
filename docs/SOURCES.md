# Sources (v1)

ThreatRadar が監視している脅威情報源の一覧。
各ソースには「**なぜ載せたか**」「**何の情報が来るか**」「**取捨選択ルール**」を記述。

新規追加・除外は `config.yaml` の `sources:` リストを編集するだけで反映されます。

---

## 公式ソース (政府機関・CSIRT)

### CISA KEV (Known Exploited Vulnerabilities)

- **URL**: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
- **形式**: JSON (差分なし、毎回フル)
- **重み**: 1.5 (最重要)
- **理由**: 米国政府が「現在悪用が確認されている」と認定した脆弱性。新規追加されたものは即対応すべき。
- **タグ自動付与**: `kev`, `actively-exploited`, `cve-*`
- **更新頻度**: 不定 (週 2-5 件)

### CISA Advisories

- **URL**: https://www.cisa.gov/cybersecurity-advisories/all.xml
- **形式**: RSS
- **重み**: 1.2
- **理由**: ICS/OT を含む包括的アドバイザリ。重要インフラへの脅威。

### NVD CVE Recent

- **URL**: https://services.nvd.nist.gov/rest/json/cves/2.0?lastModStartDate=...
- **形式**: REST JSON (最新 24 時間更新分のみ)
- **重み**: 1.0
- **理由**: 全 CVE の正規ソース。CVSS スコア付き。
- **取得制限**: API キーなしだと 6 秒に 1 リクエスト (この用途では問題なし)

### JPCERT/CC 注意喚起

- **URL**: https://www.jpcert.or.jp/rss/jpcert.rdf
- **形式**: RSS
- **重み**: 1.4
- **理由**: 日本国内向けの即応性ある注意喚起。日本語で読める利点。

### JPCERT/CC Weekly Report

- **URL**: https://www.jpcert.or.jp/rss/wr.rdf
- **形式**: RSS
- **重み**: 0.8
- **理由**: 週次まとめ、トレンド把握用。

### IPA セキュリティセンター

- **URL**: https://www.ipa.go.jp/security/announce/alert.rss
- **形式**: RSS
- **重み**: 1.2
- **理由**: 日本の政府機関による警報。一般利用者向けが多いが企業も対象。

---

## 主要セキュリティニュース

### The Hacker News

- **URL**: https://feeds.feedburner.com/TheHackersNews
- **形式**: RSS
- **重み**: 0.7
- **理由**: 英語圏で読まれている。速報性は高いが煽りも多いので重み低め。

### Bleeping Computer

- **URL**: https://www.bleepingcomputer.com/feed/
- **形式**: RSS
- **重み**: 0.9
- **理由**: ランサムウェア・マルウェア記事の質が高い。実害ベースの報道。

### Krebs on Security

- **URL**: https://krebsonsecurity.com/feed/
- **形式**: RSS
- **重み**: 1.0
- **理由**: 独自取材ベースの深掘り記事。fraud / breach 系に強い。

### SANS Internet Storm Center

- **URL**: https://isc.sans.edu/rssfeed.xml
- **形式**: RSS
- **重み**: 1.0
- **理由**: アナリストの一次観測 (handler diary)。技術的具体性が高い。

### Schneier on Security

- **URL**: https://www.schneier.com/feed/atom/
- **形式**: Atom
- **重み**: 0.6
- **理由**: 暗号・セキュリティ哲学の論考。緊急対応情報ではないが背景知識として。

---

## 研究・脆弱性研究

### Project Zero (Google)

- **URL**: https://googleprojectzero.blogspot.com/feeds/posts/default
- **形式**: Atom
- **重み**: 1.1
- **理由**: 高品質な脆弱性研究。独自発見の 0day も含まれる。

### Microsoft Security Response Center (MSRC) Blog

- **URL**: https://msrc.microsoft.com/blog/feed/
- **形式**: RSS
- **重み**: 1.2
- **理由**: Microsoft 製品の公式アドバイザリ。Patch Tuesday 関連。

### Google Online Security Blog

- **URL**: https://security.googleblog.com/feeds/posts/default
- **形式**: Atom
- **重み**: 0.9
- **理由**: Google の防御研究・新ツール発表。

---

## 任意で追加候補 (v1 では未収録)

| ソース | URL | 検討理由 |
|---|---|---|
| Mandiant Blog | https://www.mandiant.com/resources/blog/rss.xml | APT の追跡記事 |
| Rapid7 Blog | https://www.rapid7.com/blog/rss/ | Metasploit / 脆弱性詳説 |
| Trail of Bits | https://blog.trailofbits.com/feed/ | 暗号・ブロックチェーンセキュリティ |
| Recorded Future | https://www.recordedfuture.com/feed/ | 脅威インテリジェンス |
| Dark Reading | https://www.darkreading.com/rss.xml | 業界動向 |
| Have I Been Pwned | https://haveibeenpwned.com/api/v3/breaches | 漏洩情報 (公開 API) |
| Exploit-DB | https://www.exploit-db.com/rss.xml | PoC 公開 |
| ZDI Published | https://www.zerodayinitiative.com/rss/published | ベンダーパッチ情報 |
| GitHub Security Advisories | https://api.github.com/advisories | OSS 脆弱性 |
| AlienVault OTX | API key 必要 | IoC ベース |
| Abuse.ch URLhaus | https://urlhaus.abuse.ch/feeds/ | 悪性 URL |

これらを追加するときは `config.yaml` に entry を加え、動作確認するだけ。

---

## 取捨選択ルール

### 採用基準

1. **更新頻度が安定** (週 1 回以上、何ヶ月も止まっていない)
2. **専門性が高い** (リライトのリライトではなく一次情報か、深掘り解析)
3. **公開 RSS/JSON で取得可能** (HTML スクレイピングは脆い)
4. **言語が日本語または英語**

### 除外する条件

1. **アフィリエイトや SEO 目的が露骨** (タイトルが煽り、本文が薄い)
2. **同一情報の二次配信のみ** (一次ソースが既にカバー済み)
3. **ペイウォール** (要約しか取れず判断材料にならない)
4. **多言語 (日英以外)** (要件外)

---

## ソース重み (weight) の運用

`weight` は **そのソースから来た記事の基礎スコアの倍率**。0.0-1.5 を推奨。

- `1.5` 公式・確度最高 (CISA KEV 等)
- `1.2-1.4` 政府系・主要ベンダー公式 (CISA / JPCERT / MSRC / IPA)
- `1.0` 信頼できる独立メディア (Krebs / SANS)
- `0.8-0.9` 一般メディア (Bleeping / Hacker News)
- `0.5-0.7` 論考系 (Schneier 等、緊急性は低い)

新規ソースを足すときは、まず `0.8` で始めて、運用しながら調整。
