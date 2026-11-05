# Sources (v2, 2026-11 見直し)

ThreatRadar が監視している脅威情報源の一覧です。実体は `config.yaml` の `sources:` で、ここはその理由の記録です。

## 採用の基準

- **キー不要で機械取得できること。** RSS / Atom / JSON の公開フィードに限ります。CI に秘密情報を置かない方針は v1 から変えていません。
- **一次情報か、それに準じる調査であること。** 政府機関・CSIRT の告知、悪用の観測、ベンダーの脅威リサーチを優先します。他媒体の記事を言い換えるだけのニュースは外しました。
- **複数の源を並べること。** 脅威情報フィード同士の重なりは小さいことが測定されています（Li ら USENIX Security 2019、Bouwman ら USENIX Security 2020）。1つの源に頼らず、同じ CVE を報じた源の数を画面に出しています。

## 重みとスコア

`weight` 1.0 が基本点 30 点です。KEV の 1.5 は 45 点になります。重みを書かない源は 0.7 として扱います。
これに、悪用・RCE などのタグ、ウォッチ対象ベンダー、FIRST EPSS の予測値（0.1 以上で +8、0.5 以上で +15）が加わります。

## 一覧

### 政府機関・CSIRT

| ID | 名前 | 重み | 備考 |
|---|---|---:|---|
| cisa-kev | CISA KEV | 1.5 | 悪用が確認された脆弱性。カタログ全件を毎回取り、追加日が30日以内のものだけ残す |
| cisa-advisories | CISA Advisories | 1.2 | GitHub Actions からときどき 403 が返る。失敗は画面の「ソースの状態」に出る |
| nvd-recent | NVD | 1.0 | 直近48時間に公開された CVE。CVSS 8.0 未満と未採点は捨てる。一覧には最大150件 |
| jpcert-at | JPCERT/CC 注意喚起 | 1.2 | |
| jpcert-wr | JPCERT/CC 全フィード | 0.6 | Weekly Report・JVN を含む |
| ipa-alert | IPA セキュリティセンター | 1.2 | |
| jc3 | JC3 脅威情報 | 1.0 | 日本サイバー犯罪対策センター。2026-11 追加 |
| antiphishing | フィッシング対策協議会 | 0.8 | 緊急情報と月次報告。講演告知も混ざる。2026-11 追加 |

### 悪用の観測・PoC

| ID | 名前 | 重み | 備考 |
|---|---|---:|---|
| greynoise | GreyNoise Threat Briefs | 1.1 | 自社センサーで観測したスキャン・悪用の速報。2026-11 追加 |
| cloudflare-ti | Cloudflare Threat Intelligence | 1.0 | Radar の Zero Wire 告知を含む。Zero Wire 専用の RSS/API は無い。2026-11 追加 |
| zdi | Zero Day Initiative | 1.0 | 公開済みアドバイザリ。一覧には最大100件 |
| exploit-db | Exploit-DB | 0.8 | 公開 PoC。2026-11 追加 |

### ベンダーの脅威リサーチ

| ID | 名前 | 重み | 備考 |
|---|---|---:|---|
| gtig | Google Threat Intelligence (Mandiant) | 1.1 | 旧 mandiant.com のフィードは HTML になり90日間0件だった。2026-11 に移行 |
| ms-threat-intel | Microsoft Threat Intelligence | 1.2 | Security Blog 全体から脅威インテリジェンスのトピックに絞った |
| unit42 | Palo Alto Networks Unit 42 | 1.0 | 2026-11 追加 |
| talos | Cisco Talos | 1.0 | 2026-11 追加 |
| project-zero | Google Project Zero | 1.0 | 新ドメイン projectzero.google に移行 |
| watchtowr | watchTowr Labs | 1.0 | エッジ機器の脆弱性研究。2026-11 追加 |
| securelist | Kaspersky Securelist | 0.9 | 2026-11 追加 |
| checkpoint | Check Point Research | 0.9 | 2026-11 追加 |
| sekoia | Sekoia TDR | 0.9 | 2026-11 追加 |
| dfir-report | The DFIR Report | 0.9 | 更新は数か月おき。「更新停止?」と出ても異常とは限らない。2026-11 追加 |
| rapid7 | Rapid7 | 0.9 | 2026-10 から配信 XML に制御文字が混ざり取り込めていなかった。除去処理を入れて復旧 |
| eset | ESET WeLiveSecurity | 0.8 | 2026-11 追加 |
| google-security | Google Online Security Blog | 0.8 | Blogger 版は 2026-04 で更新停止。blog.google/security に移行 |
| trailofbits | Trail of Bits | 0.7 | 脅威より研究寄りなので重みを下げた |

### ニュース

| ID | 名前 | 重み | 備考 |
|---|---|---:|---|
| bleeping | BleepingComputer | 0.9 | |
| krebs | Krebs on Security | 1.0 | |
| sans-isc | SANS Internet Storm Center | 1.0 | ハニーポット観測を含む日次記事 |
| piyolog | piyolog | 1.0 | 国内インシデントの一次情報を集めた記録。2026-11 追加 |
| security-next | Security NEXT | 0.7 | 国内ニュース。2026-11 追加 |

## 外したもの

| 源 | 理由 |
|---|---|
| The Hacker News | 他媒体の記事の言い換えが多く、一覧の約2割を占めていた |
| Schneier on Security | 論評が中心で、脅威情報ではない |

## 検討したが入れなかったもの

| 源 | 理由 |
|---|---|
| VulnCheck KEV | CISA KEV より早い悪用情報を出す。無料だがアカウント登録とトークンが要る |
| abuse.ch (ThreatFox / URLhaus / MalwareBazaar) | 無料だが Auth-Key が要る。IOC 中心でダッシュボードの粒度と合わない |
| Shadowserver | ダッシュボードは閲覧のみ。API は申請制 |
| Cloudflare Radar API | API トークンが要る |
| トレンドマイクロ / NTT セキュリティ / 警察庁 / NICTER | 機械取得できるフィードが見つからなかった |
| JVN iPedia RSS / MyJVN API | 調査時に 503 が続いた。JVN は JPCERT/CC 全フィード経由で入る |
| Volexity / Huntress / Wiz | フィードが無い、または製品告知が多い |

## 付加情報

- **FIRST EPSS** (`epss.enabled`): 新規アイテムの CVE について、30日以内に悪用される確率の予測値を付けます。公開 API でキーは不要です。失敗しても収集は止まらず、「ソースの状態」に出ます。

## ソースの状態 (`data/sources.json`)

毎回の取得結果を書き出します。画面上部の「ソースの状態」はこれを読みます。

- **取得失敗**: HTTP エラーや解析失敗。エラー文を表示します。
- **更新停止?**: 最新記事が45日より前。配信が止まった可能性があります。
- **0 件**: 取得は成功したが項目が無い。

前回成功した日時は次の実行に引き継ぐので、フィードが黙って止まっても気づけます。v1 では Mandiant が90日間0件のまま気づけませんでした。
