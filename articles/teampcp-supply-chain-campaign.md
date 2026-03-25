---
title: "【図解】TeamPCPサプライチェーンキャンペーンまとめ ─ 海外セキュリティチームの分析をAIに解説してもらった"
emoji: "🔗"
type: "tech"
topics: ["security", "supplychain", "cicd", "github", "trivy"]
published: true
---

:::message
**本記事の位置づけ**
本記事は、Wiz Research・Sysdig TRT・Microsoft Security Blog・Datadog Security Labs 等の海外セキュリティチームが公開した一次ソースを、AI（Claude / Anthropic）を使って整理・解説したものです。筆者独自の分析ではありません。各ソースへのリンクを記載していますので、原文もあわせてご確認ください。

「第1波〜第3波」の分類は説明の便宜上つけたラベルであり、公式な分類名ではありません。
:::

:::message alert
**本件は2026年3月25日時点で進行中です。** 新たな波及先が発見される可能性があります。最新情報は末尾の一次ソースを確認してください。
:::

## この記事を書いた動機

日本語での情報がまだ少なかったので、海外の著名セキュリティチームが出している分析をAIに図解してもらいながら整理しました。

## 1. 全体像

Trivyというセキュリティスキャナだけの話だと思っていたが、どうやら各事業者が封じ込めようとしても封じ込められず、次々と別のツールに飛び火して、今も解決できていないようにみえる。

### 各事業者の対応と声明

| 事業者 | 記事タイトル / 声明 | 要約 |
|---|---|---|
| **Aqua Security**（Trivy開発元） | [Trivy Supply Chain Attack: What Happened and What You Need to Know](https://www.aquasec.com/blog/trivy-supply-chain-attack-what-you-need-to-know/) | 「クレデンシャルのローテーションがアトミックではなく、攻撃者が更新後のトークンを取得した可能性がある」と認めた。商用製品への影響はないとしつつ、OSS版Trivyユーザーには即座の対応を推奨 |
| **Checkmarx** | [Checkmarx Security Update](https://checkmarx.com/blog/checkmarx-security-update/) | 3/23に KICS GitHub Action と2つのOpenVSX拡張が侵害されたことを開示。「顧客データや本番環境への影響は認識していない」としつつ、影響時間帯にダウンロードした組織にはインシデント対応を推奨 |
| **Docker** | [Trivy supply chain compromise: What Docker Hub users should know](https://www.docker.com/blog/trivy-supply-chain-compromise-what-docker-hub-users-should-know/) | Docker Hub上の汚染イメージ（0.69.4〜0.69.6, latest）の影響時間帯を特定。Dockerソケットをマウントしていた場合はホスト全体を侵害されたものとして扱うよう警告 |
| **CrowdStrike** | [From Scanner to Stealer: Inside the trivy-action Supply Chain Compromise](https://www.crowdstrike.com/en-us/blog/from-scanner-to-stealer-inside-the-trivy-action-supply-chain-compromise/) | Falconプラットフォームの複数顧客でスクリプト実行の検知が急増したことから調査を開始。77タグ中76がポイズニングされていたことを確認し、攻撃チェーン全体を公開 |
| **Microsoft** | [Guidance for detecting, investigating, and defending against the Trivy supply chain compromise](https://www.microsoft.com/en-us/security/blog/2026/03/24/detecting-investigating-defending-against-trivy-supply-chain-compromise/) | Defender for Cloud が self-hosted GitHub Actions ランナー上で攻撃チェーン全体を観測。Defender XDR / MDE 向けの KQL 検知クエリと対応ガイダンスを公開 |
| **LiteLLM (BerriAI)** | [Security Update（Wiz経由で確認）](https://www.wiz.io/blog/threes-a-crowd-teampcp-trojanizes-litellm-in-continuation-of-campaign) | 3/25付で公式セキュリティアップデートを公開。PyPIにより汚染バージョンは隔離済み。メンテナのPyPI資格情報が不正利用された可能性が指摘されている |

Microsoft は Defender for Cloud で攻撃チェーンの全段階（プロセス探索 → メモリスキャン → クレデンシャル収集 → 暗号化 → 送信）を観測しており、MDE（Microsoft Defender for Endpoint）の Advanced Hunting 向け KQL クエリも公開している。KQL の詳細は「2. IoC情報と調査方法」で解説する。

### 海外著名セキュリティチームの分析

この攻撃の全体像は、以下のセキュリティチームのブログに詳しくまとめられている。

- **Wiz Research** — Trivy・Checkmarx KICS・LiteLLM それぞれについて個別の技術分析記事を公開。最も包括的
- **Sysdig Threat Research Team** — Trivyで盗んだ認証情報がCheckmarxへの侵害に連鎖した構造を分析
- **Datadog Security Labs** — キャンペーン全体を4つのステージに整理して時系列で解説
- **Rami McCarthy氏 (ramimac.me)** — 全ステージのタイムラインとIoCを1ページにまとめた包括的リファレンス

特に Rami McCarthy 氏の [タイムラインページ](https://ramimac.me/teampcp/) と Datadog の [分析記事](https://securitylabs.datadoghq.com/articles/litellm-compromised-pypi-teampcp-supply-chain-campaign/) に今も進行中の状況が詳しくまとめられているので、Claude に翻訳と現在の状況を整理してもらった。以下が攻撃の各段階である。いまはあまり騒ぎになっていないけど、VS CodeやCursorの拡張モジュールも対象といわれると、一般企業内にも今後影響がでないか少し心配している。

![TeamPCPサプライチェーン攻撃の全体像](/images/teampcp-overview.png)
*図：攻撃の全体像（Claude生成。一次ソースの情報を整理した概念図）*

### 根本原因

Aqua SecurityのTrivyリポジトリに `pull_request_target` という GitHub Actions のワークフロー設定があった。この設定により、外部からのプルリクエストがCI環境内の認証トークン（PAT = Personal Access Token）を読み取れる状態だった。

2月28日、AI自律型ボット「hackerbot-claw」がこの設定ミスを悪用してPATを窃取した。Aqua Securityは3月1日にインシデントを開示し、クレデンシャルをローテーションした。しかし、Aqua Security自身が認めているように「ローテーションがアトミックではなく、攻撃者が更新後のトークンを取得した可能性がある」。この不完全なローテーションにより、攻撃者はアクセスを維持した。

- 出典：[Aqua Security 公式声明](https://www.aquasec.com/blog/trivy-supply-chain-attack-what-you-need-to-know/)
- 出典：[Wiz Research - Trivy Compromised by TeamPCP](https://www.wiz.io/blog/trivy-compromised-teampcp-supply-chain-attack)

### 第1波：Trivy（3月19日）

残存クレデンシャルを使い、攻撃者は3月19日17:43 UTC に再侵入した。

実行された攻撃：
- `aquasecurity/trivy-action` の77タグ中76を、悪意あるコミットに強制書換え（force-push）
- `aquasecurity/setup-trivy` の全7タグを同様に書換え
- 悪意ある Trivy v0.69.4 バイナリを GitHub Releases・Docker Hub・GHCR・Amazon ECR に配布

書き換えられたActionを実行すると、**TeamPCP Cloud Stealer** が動作する。正規の Trivy スキャンも並行で実行されるため、パイプラインの出力は正常に見え、侵害に気づけない。

CrowdStrikeは「Falcon プラットフォームの複数顧客でスクリプト実行の検知が急増し」、そこから調査を開始してこの侵害を発見した。Microsoft も Defender for Cloud で self-hosted ランナー上の攻撃チェーンを観測している。GitHub Actions側の侵害時間窓は約3〜12時間（コンポーネントによって異なる）だが、Docker Hub側の影響期間は3/19〜3/23と数日に跨ぐため、コンポーネント別に確認が必要。

**Docker Hub の汚染（封じ込め失敗の連鎖）**

この第1波で特に厄介だったのが、Docker Hubの汚染が繰り返されたこと。Docker の公式ブログによると、経緯は以下の通り：

1. **3/19 18:24 UTC** — 攻撃者が Aqua Security の認証情報を使い、Docker Hub に汚染イメージ `aquasec/trivy:0.69.4` と `latest` を push。Aqua の正規認証情報を使っているため、Docker Hub 側からは通常の更新と区別できなかった
2. **3/20 03:26 UTC** — Aqua が初回クリーンアップを実施した後、攻撃者が再び `latest` タグを汚染イメージに向け直した
3. **3/22** — GitHub Releases には存在しない `0.69.5` と `0.69.6` という新たな汚染イメージが push された

つまり一度封じ込めたはずが、残存するクレデンシャルで何度も汚染し直された。Docker は 3/23 にイメージを隔離し、安全な最終リリースは `0.69.3` であると特定している。

- 出典：[CrowdStrike - From Scanner to Stealer](https://www.crowdstrike.com/en-us/blog/from-scanner-to-stealer-inside-the-trivy-action-supply-chain-compromise/)
- 出典：[Microsoft Security Blog - Detecting Trivy Supply Chain Compromise](https://www.microsoft.com/en-us/security/blog/2026/03/24/detecting-investigating-defending-against-trivy-supply-chain-compromise/)
- 出典：[StepSecurity - Trivy Compromised a Second Time](https://www.stepsecurity.io/blog/trivy-compromised-a-second-time---malicious-v0-69-4-release)
- 出典：[Docker - Trivy supply chain compromise: What Docker Hub users should know](https://www.docker.com/blog/trivy-supply-chain-compromise-what-docker-hub-users-should-know/)

### 第2波：Checkmarx KICS / AST（3月23日）

第1波で窃取されたクレデンシャルが、別のセキュリティベンダーへの侵害に利用された。

Sysdig TRT が Trivy 侵害の約4日後に Checkmarx/ast-github-action でも同一のスティーラーが実行されているのを観測し、「Trivy 侵害で窃取されたクレデンシャルが追加のAction汚染に使われたことを示唆する」と報告した。Wiz Research も独立して、KICS GitHub Action の35タグ全てが3月23日 12:58〜16:50 UTC にハイジャックされたことを確認している。

同日、Checkmarx の VS Code 拡張機能（OpenVSX経由で配布される ast-results v2.53 と cx-dev-assist v1.7）も汚染されていたことが ReversingLabs と Wiz によって確認された。VS Code 拡張経由の場合、CI/CDランナーではなく**開発者のローカルPC**が侵害対象となる。

Checkmarx は「顧客データや本番環境への影響は認識していない」との声明を出しつつ、影響を受けた時間帯にダウンロードした組織にはインシデント対応を推奨している。

- 出典：[Sysdig TRT - TeamPCP expands](https://www.sysdig.com/blog/teampcp-expands-supply-chain-compromise-spreads-from-trivy-to-checkmarx-github-actions)
- 出典：[Wiz Research - KICS GitHub Action Compromised](https://www.wiz.io/blog/teampcp-attack-kics-github-action)
- 出典：[Checkmarx 公式声明](https://checkmarx.com/blog/checkmarx-security-update/)

### 第3波：LiteLLM / PyPI（3月24日）

攻撃はGitHub Actionsの世界を超え、PyPI（Pythonパッケージ配布基盤）にも到達した。

3月24日朝、LiteLLM（100以上のLLM APIを統一インターフェースで呼ぶPythonライブラリ）の悪意あるバージョン 1.82.7 と 1.82.8 が PyPI に公開された。Wiz Research によると、LiteLLM はクラウド環境の36%に存在しており、影響範囲は極めて広い。

特に 1.82.8 は `.pth` ファイルによる永続化手法を導入しており、LiteLLM を import していなくても、その Python 環境で何かを実行する（`python` コマンドを起動する）だけでスティーラーが発火する。つまり `pip install litellm==1.82.8` した時点で、以降その環境のあらゆる Python 実行が侵害される。

ReversingLabs は「ペイロードはTrivy・Checkmarxの侵害で使われたものとほぼ同一」と報告している。メンテナのPyPI資格情報が不正利用された可能性が指摘されており、Endor Labs は「このキャンペーンはほぼ確実にまだ終わっていない」と警告している。

PyPI セキュリティチームの迅速な対応により汚染バージョンは隔離されたが、隔離前にダウンロードした環境は侵害されたものとして扱う必要がある。

- 出典：[Wiz Research - LiteLLM Trojanized](https://www.wiz.io/blog/threes-a-crowd-teampcp-trojanizes-litellm-in-continuation-of-campaign)
- 出典：[Datadog Security Labs - LiteLLM compromised on PyPI](https://securitylabs.datadoghq.com/articles/litellm-compromised-pypi-teampcp-supply-chain-campaign/)
- 出典：[Endor Labs - TeamPCP Isn't Done](https://www.endorlabs.com/learn/teampcp-isnt-done)

### 侵害が疑われる対象（2026/3/25時点）

図の最下部「侵害が疑われる対象」に対応する部分。以下のいずれかに該当する場合、侵害の影響を受けている可能性がある。

**CI/CDサーバ（GitHub Actions等）**
- `aquasecurity/trivy-action` をタグ参照で使用（77タグ中76が汚染。安全なのは v0.35.0 のみ）
- `aquasecurity/setup-trivy` をタグ参照で使用（全7タグ汚染）
- `Checkmarx/kics-github-action` をタグ参照で使用（全35タグ汚染）
- `Checkmarx/ast-github-action` をタグ参照で使用（v2.3.28 で確認）

**開発者PC（Windows / Mac / Linux）**
- VS Code / Cursor に Checkmarx 拡張をインストール（OpenVSX経由の ast-results v2.53、cx-dev-assist v1.7）
- `pip install litellm` でバージョン 1.82.7 / 1.82.8 をインストール
- Node.js プロジェクトの依存に CanisterWorm 汚染 npm パッケージが含まれる

**コンテナ環境**
- Docker Hub / GHCR / ECR から `aquasec/trivy:0.69.4`〜`0.69.6` または `latest`（3/19 18:24 UTC〜3/23 01:36 UTC）を pull した環境
- Docker はさらに「Docker ソケットをマウントしていた場合はホスト全体を侵害されたものとして扱え」と警告（出典：[Docker公式ブログ](https://www.docker.com/blog/trivy-supply-chain-compromise-what-docker-hub-users-should-know/)）

**クラウド環境（AWS / GCP / Azure / M365）**
- 上記のいずれかで侵害された環境に保存されていた IAM 鍵・サービスアカウントキー・Azure AD トークン等が窃取され、クラウド環境への不正アクセスに利用される可能性がある

**SaaS**
- 利用中の SaaS が裏で Trivy を使っている場合、SaaS 側のクレデンシャル漏洩を経由した間接被害の可能性がある
- 報道によると、Mandiant CTO は「1,000以上のSaaS環境がこの攻撃者に対処中」と述べたとされる（確定被害数ではなく推計。出典：[CSO Online](https://www.csoonline.com/article/4149938/trivy-supply-chain-breach-compromises-over-1000-saas-environments-lapsus-joins-the-extortion-wave.html)、[The Register](https://www.theregister.com/2026/03/24/1k_cloud_environments_infected_following/)）

**GitHub 組織**
- org 内に `tpcp-docs` または `docs-tpcp` という名前のリポジトリが存在する場合、窃取データがそこに保存された確定的証拠

---

## 2. 影響製品、IoC情報と調査方法

### 影響製品

このキャンペーンで影響を受ける製品・パッケージの一覧は、以下のサイトで随時更新されている。まず自社環境に該当するものがないか、これらで確認するのが最初のステップになる。

| サイト | 内容 | URL |
|---|---|---|
| **Rami McCarthy氏 タイムラインページ** | キャンペーン全体の影響製品・バージョン・安全なバージョン・IoCを1ページにまとめた包括的リファレンス。随時更新されている | https://ramimac.me/teampcp/ |
| **Socket.dev キャンペーントラッカー** | Trivy GitHub Actions Compromiseの影響を受けたパッケージ・タグを一覧化。Socketダッシュボードの「Threat Intel → Campaigns」からも確認可能。Wiz Researchも「この情報をまとめてくれたSocketに感謝」と引用している | https://socket.dev/supply-chain-attacks/trivy-github-actions-compromise |
| **GitHub Security Advisory** | CVE-2026-33634に対応するGHSA-69fq-xp46-6x23。影響バージョンと安全なバージョンを公式に管理 | https://github.com/aquasecurity/trivy/security/advisories/GHSA-69fq-xp46-6x23 |
| **Aqua Security 公式声明** | 影響コンポーネント・時間窓・安全バージョン・IoCを掲載。調査の進展に合わせて更新中 | https://www.aquasec.com/blog/trivy-supply-chain-attack-what-you-need-to-know/ |

なお、CISAのKEV（Known Exploited Vulnerabilities）カタログにはCVE-2026-33634は2026/3/25時点で掲載されていない。NVDにはエントリがあるが詳細解析は進行中。公的機関による包括的な「影響製品リスト」は現時点では存在しないため、上記の民間ソースを参照する必要がある。

### IoC情報

現時点で信頼できるIoC情報について、Claudeにまとめてもらった。主な出典は以下の通り。

- [Wiz Research - Trivy Compromised by TeamPCP](https://www.wiz.io/blog/trivy-compromised-teampcp-supply-chain-attack)
- [Wiz Research - KICS GitHub Action Compromised](https://www.wiz.io/blog/teampcp-attack-kics-github-action)
- [Wiz Research - LiteLLM Trojanized](https://www.wiz.io/blog/threes-a-crowd-teampcp-trojanizes-litellm-in-continuation-of-campaign)
- [Rami McCarthy - TeamPCP Supply Chain Campaign Timeline & IOCs](https://ramimac.me/teampcp/)
- [Microsoft Security Blog - Detecting Trivy Supply Chain Compromise](https://www.microsoft.com/en-us/security/blog/2026/03/24/detecting-investigating-defending-against-trivy-supply-chain-compromise/)
- [Aqua Security - GHSA-69fq-xp46-6x23](https://github.com/aquasecurity/trivy/security/advisories/GHSA-69fq-xp46-6x23)

**ネットワーク（通信先）**

| 種別 | 値 | 用途 |
|---|---|---|
| C2ドメイン | `scan.aquasecurtiy[.]org` | Trivy波の窃取データ送信先（typo注意：secur**tiy**） |
| C2ドメイン | `checkmarx[.]zone` | Checkmarx / LiteLLM波の窃取データ送信先 |
| C2ドメイン | `models.litellm[.]cloud` | LiteLLM v1.82.8 の窃取データ送信先 |
| Cloudflare Tunnel | `plug-tab-protective-relay.trycloudflare.com` | Aqua内部クレデンシャル（GPG鍵、Docker Hub、Slack等）の窃取 |
| ICP C2 | `tdtqy-oyaaa-aaaae-af2dq-cai.raw.icp0.io` | CanisterWormのC2。ブロックチェーン上のため従来のテイクダウン不可 |
| IP | `45.148.10.212` | scan.aquasecurtiy[.]org の解決先 |
| IP | `83.142.209.11` | checkmarx[.]zone の解決先 |

**ファイル・プロセス**

| 種別 | 値 |
|---|---|
| アーカイブ名 | `tpcp.tar.gz`（窃取データの暗号化アーカイブ） |
| プロセス | `entrypoint.sh` から `grep -qiE (env\|ssh)` を実行 |
| メモリスキャン | `/proc/*/mem` を走査し `{"value":"<secret>","isSecret":true}` パターンを検索 |
| 永続化（systemd） | ユーザーサービスとして `sysmon.py` を登録（50分毎にC2からペイロード取得） |
| 永続化（Python） | `.pth` ファイルによるPython起動時自動実行（LiteLLM波） |
| 一時ファイル | `/tmp/runner_collected_*.txt`（収集したクレデンシャルの一時保存先） |

**GitHub**

| 種別 | 値 |
|---|---|
| フォールバック窃取（Trivy波） | 被害者org内に `tpcp-docs` リポジトリを自動作成 |
| フォールバック窃取（Checkmarx波） | 被害者org内に `docs-tpcp` リポジトリを自動作成 |

**汚染パッケージ・イメージ**

| 対象 | 汚染バージョン | 安全なバージョン |
|---|---|---|
| `aquasecurity/trivy-action` | 0.0.1〜0.34.2（77タグ中76） | v0.35.0 / SHA: `57a97c7e7821a5776cebc9bb87c984fa69cba8f1` |
| `aquasecurity/setup-trivy` | v0.2.0〜v0.2.6（全7タグ） | v0.2.6（再リリース版） / SHA: `3fb12ec` |
| Trivy バイナリ | v0.69.4 | v0.69.3 以前 |
| Trivy Docker イメージ | 0.69.4, 0.69.5, 0.69.6, latest（3/19〜3/23） | 0.69.3 |
| `Checkmarx/kics-github-action` | 全35タグ | リポジトリ復旧済み（SHAピン留め推奨） |
| `Checkmarx/ast-github-action` | v2.3.28（確認済み） | 同上 |
| Checkmarx OpenVSX拡張 | ast-results v2.53.0, cx-dev-assist v1.7.0 | ast-results 最新版, cx-dev-assist v1.10.0以降 |
| `litellm`（PyPI） | 1.82.7, 1.82.8 | 1.82.6 以前（PyPIで隔離済み） |

### 調査方法

主要ベンダーから公開されている調査方法について、まとめてもらった。「何を調べるか」ごとに整理している。

#### 端末の調査

主要EDRベンダーは、TeamPCP Cloud Stealerの活動を**既存の検知ルールまたは新規公開ルールで検知できる**ことを公式に報告している。「TeamPCP専用」のシグネチャではなく、クレデンシャル収集・メモリスキャン・暗号化送信といった**挙動ベースの検知**で捕捉している点が共通している。

| ベンダー | 検知対応状況 | 出典 |
|---|---|---|
| **Microsoft Defender XDR / MDE** | 対応する検知ルールのリストを公開済み。Defender for Cloudでは攻撃チェーン全体を観測。Advanced Hunting用KQLクエリも公開 | [Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2026/03/24/detecting-investigating-defending-against-trivy-supply-chain-compromise/) |
| **CrowdStrike Falcon** | 既存のスクリプト制御検知で、CI/CDと矛盾する挙動（クレデンシャル収集、暗号化データのステージング、外部送信）として検知・ブロック | [CrowdStrike Blog](https://www.crowdstrike.com/en-us/blog/from-scanner-to-stealer-inside-the-trivy-action-supply-chain-compromise/) |
| **Palo Alto Cortex XDR** | エンドポイントランタイム保護で、不正なsystemdサービス作成、脆弱性スキャナからの異常なプロセスツリー、未署名バイナリの実行を検知可能 | [Palo Alto Networks Blog](https://www.paloaltonetworks.com/blog/cloud-security/trivy-supply-chain-attack/) |
| **Sysdig Secure / Falco** | 4つのランタイム検知ルールを公開。Trivy波・Checkmarx波の両方を同じルールで検出。「AWS IMDSアクセス + データアップロード」の組み合わせが最も高シグナル | [Sysdig TRT Blog](https://www.sysdig.com/blog/teampcp-expands-supply-chain-compromise-spreads-from-trivy-to-checkmarx-github-actions) |

以下、各ベンダーが公開している具体的な調査方法を記載する。

**Microsoft Defender for Endpoint（MDE）/ Defender XDR**

Microsoft Security Blog が公開している Advanced Hunting 向け KQL クエリ：

:::details MDE / Defender XDR 向け KQL（CloudProcessEvents）
```kusto
CloudProcessEvents
| where ProcessCommandLine has_any (
    'scan.aquasecurtiy.org',
    '45.148.10.212',
    'plug-tab-protective-relay.trycloudflare.com',
    'tdtqy-oyaaa-aaaae-af2dq-cai.raw.icp0.io',
    'checkmarx.zone',
    '/tmp/runner_collected_',
    'tpcp.tar.gz'
)
or (ParentProcessName == 'entrypoint.sh'
    and ProcessCommandLine has 'grep -qiE (env|ssh)')
```
:::

Defender for Cloud では self-hosted GitHub Actions ランナー上の攻撃チェーン全体（プロセス探索 → メモリスキャン → クレデンシャル収集 → 暗号化 → 送信）を観測しており、対応する検知ルールが有効化されている。

同ブログには、`DeviceProcessEvents` と `DeviceNetworkEvents` を結合して端末からC2への通信を検索するクエリも掲載されている。VS Code拡張やLiteLLM経由で開発者PCが侵害された場合の痕跡をMDEで検索する際に使える。

:::details MDE 向け KQL（DeviceProcessEvents + DeviceNetworkEvents）
```kusto
DeviceProcessEvents
| where ProcessCommandLine has_all ('/dev/null', '--data-binary', '-X POST', 'scan.aquasecurtiy.org')
  or ProcessCommandLine has_any ('pgrep -f Runner.Listener', 'pgrep -f Runner.Worker')
  or ProcessCommandLine has_any ('tmp/runner_collected_', 'tpcp.tar.gz')
| join kind=leftouter (
    DeviceNetworkEvents
    | where RemoteIP == '45.148.10.212'
  ) on DeviceId
| project Timestamp, FileName, ProcessCommandLine, RemoteIP, RemoteUrl
```
:::

- 出典：[Microsoft Security Blog - Guidance for detecting, investigating, and defending against the Trivy supply chain compromise](https://www.microsoft.com/en-us/security/blog/2026/03/24/detecting-investigating-defending-against-trivy-supply-chain-compromise/)

**CrowdStrike Falcon**

攻撃チェーンのプロセスツリーがブログで公開されている。

- 出典：[CrowdStrike - From Scanner to Stealer: Inside the trivy-action Supply Chain Compromise](https://www.crowdstrike.com/en-us/blog/from-scanner-to-stealer-inside-the-trivy-action-supply-chain-compromise/)

**Sysdig Secure / Falco**

Falco のランタイム検知ルール4本がブログで公開されている。

- 出典：[Sysdig TRT - TeamPCP expands: Supply chain compromise spreads from Trivy to Checkmarx GitHub Actions](https://www.sysdig.com/blog/teampcp-expands-supply-chain-compromise-spreads-from-trivy-to-checkmarx-github-actions)

#### ネットワーク・SIEMの調査

ファイアウォール・プロキシ・SIEMのログで、上記IoC一覧のC2ドメイン・IPへの通信（特にHTTPS POST）を検索する。CIランナーからの外部通信についてはベースラインとの比較が有効で、Upwind がネットワーク監視でベースライン逸脱として検知した事例も報告されている。

- 出典：[Upwind - Trivy Supply Chain Incident: GitHub Actions Compromise Breakdown](https://www.upwind.io/feed/trivy-supply-chain-incident-github-actions-compromise-breakdown)

#### コンテナ環境の調査

**Docker Hub**

Docker が公式ブログで汚染イメージのダイジェスト値（SHA256）を公開している。ローカルイメージストア、レジストリミラー、Artifactory / Nexus キャッシュに以下のダイジェストが存在しないか確認する。

影響期間：3月19日 18:24 UTC 〜 3月23日 01:36 UTC（`0.69.4`, `0.69.5`, `0.69.6`, `latest` タグ）

:::message alert
Docker は「Docker ソケットをマウント（`-v /var/run/docker.sock`）していた場合、コンテナからホストの Docker デーモンにフルアクセス可能なため、ホスト全体を侵害されたものとして扱え」と警告している。
:::

- 出典：[Docker - Trivy supply chain compromise: What Docker Hub users should know](https://www.docker.com/blog/trivy-supply-chain-compromise-what-docker-hub-users-should-know/)

#### クラウド環境の調査

AWS / GCP / Azure について、このキャンペーン固有の調査ガイドは現時点では各クラウドプロバイダからは公開されていない。ただし、窃取対象にはこれらの認証情報が含まれているため、以下の一般的な調査が推奨される。

- **AWS**：CloudTrail で通常と異なるリージョン・サービスからの API 呼出がないか確認。IMDSv1 経由の認証情報窃取が攻撃手法に含まれるため、IMDSv2 への移行状況も確認
- **GCP**：Cloud Audit Logs でサービスアカウントキーの異常利用を確認
- **Azure / M365**：Entra ID のサインインログで不審な場所・デバイスからのアクセスを確認

侵害が確認された場合は、各クラウドプロバイダの標準的なクレデンシャルローテーション手順に従う。

- 参考：[Sysdig TRT - 推奨対応](https://www.sysdig.com/blog/teampcp-expands-supply-chain-compromise-spreads-from-trivy-to-checkmarx-github-actions)（「Rotate all secrets, tokens, and cloud credentials that were accessible to CI runners during the affected window」）

#### GitHub の調査

- org 内に `tpcp-docs` または `docs-tpcp` という名前のリポジトリが存在しないか確認する（存在すれば窃取成功の確定的証拠）
- GitHub Audit Log で影響期間中の不審なリポジトリ作成・トークン利用を確認する
- CI/CD ワークフロー実行ログ（3/19〜3/23）で `tpcp.tar.gz`、`aquasecurtiy`、`checkmarx.zone` への参照がないか確認する

- 出典：[Aqua Security - GHSA-69fq-xp46-6x23](https://github.com/aquasecurity/trivy/security/advisories/GHSA-69fq-xp46-6x23)
- 出典：[Sysdig TRT - 推奨対応](https://www.sysdig.com/blog/teampcp-expands-supply-chain-compromise-spreads-from-trivy-to-checkmarx-github-actions)

#### 被害パッケージの確認

自社の開発環境で汚染パッケージを使っていないか、以下のコマンドで確認できる。

:::details 確認コマンド例（bash）
```bash
# GitHub Actions（ワークフローファイル内のタグ参照を検索）
grep -r "aquasecurity/trivy-action" .github/workflows/
grep -r "aquasecurity/setup-trivy" .github/workflows/
grep -r "Checkmarx/kics-github-action" .github/workflows/
grep -r "Checkmarx/ast-github-action" .github/workflows/

# Python（LiteLLM）
pip show litellm  # バージョンが 1.82.7 / 1.82.8 でないか確認

# Docker（Trivy イメージ）
docker images | grep aquasec/trivy  # 0.69.4〜0.69.6 が存在しないか

# VS Code 拡張
code --list-extensions | grep -i checkmarx  # ast-results / cx-dev-assist が入っていないか
```
:::

### CVE情報

TeamPCPサプライチェーンキャンペーン関連のCVE・アドバイザリについて、まとめてもらった。

| 識別子 | 対象 | CVSS | 内容 |
|---|---|---|---|
| **CVE-2026-33634** | Trivy エコシステム | 9.4（Critical） | 非アトミックなシークレットローテーションによるサプライチェーン侵害。Trivyスキャナ、trivy-action、setup-trivy が対象 |
| **GHSA-69fq-xp46-6x23** | Trivy エコシステム | — | GitHub Security Advisory。影響バージョン、安全なバージョン、IoC、対応手順を記載 |
| **PYSEC-2026-2** | LiteLLM (PyPI) | — | PyPI セキュリティアドバイザリ。litellm 1.82.7 / 1.82.8 が対象 |

キャンペーン全体（Checkmarx、npm CanisterWorm等を含む）を包括するCVEは、2026/3/25時点で割り当てられていない。

- 出典：[Tenable - CVE-2026-33634](https://www.tenable.com/cve/CVE-2026-33634)
- 出典：[Aqua Security - GHSA-69fq-xp46-6x23](https://github.com/aquasecurity/trivy/security/advisories/GHSA-69fq-xp46-6x23)
- 出典：[Phoenix Security - TeamPCP Supply Chain Attack](https://phoenix.security/teampcp-supply-chain-attack-trivy-checkmarx-github-actions-npm-canisterworm/)

---

## 3. 何をすべきか

正直ここは難しくて全部は理解できていないけど、何をすべきかをClaude にまとめてもらった。情報源は以下の4つに絞っている。

- [Aqua Security 公式声明 - Trivy Supply Chain Attack: What Happened and What You Need to Know](https://www.aquasec.com/blog/trivy-supply-chain-attack-what-you-need-to-know/)
- [Microsoft Security Blog - Guidance for detecting, investigating, and defending against the Trivy supply chain compromise](https://www.microsoft.com/en-us/security/blog/2026/03/24/detecting-investigating-defending-against-trivy-supply-chain-compromise/)
- [Sysdig TRT - TeamPCP expands: Supply chain compromise spreads from Trivy to Checkmarx GitHub Actions](https://www.sysdig.com/blog/teampcp-expands-supply-chain-compromise-spreads-from-trivy-to-checkmarx-github-actions)
- [Docker - Trivy supply chain compromise: What Docker Hub users should know](https://www.docker.com/blog/trivy-supply-chain-compromise-what-docker-hub-users-should-know/)

![何をすべきか — 対応の全体像](/images/teampcp-response.png)
*図：対応の全体像（Claude生成。上記4つの情報源の内容を整理した概念図）*

### 急いでやること

以下の番号は、上の図の番号と対応している。

#### ステップ1：該当パッケージの利用有無を確認する

まずは自社の環境で汚染パッケージを使っていないかを確認する。これが最優先。2章の「被害パッケージの確認」コマンドを使って、開発チーム・インフラチームに確認を依頼する。

使っていなければ直接的な侵害リスクは低い。ただし利用中のSaaSが裏でTrivyを使っている可能性は残るので、SaaSベンダーからのセキュリティ通知が出ていないかも確認する。

#### ステップ2：IoC を検索する

2章のIoC一覧を使って、以下の3レイヤーで検索する。

- **ネットワーク**（SIEM / FW / Proxy）：C2ドメイン・IPへの通信
- **端末**（EDR）：`tpcp.tar.gz` 関連のプロセス・ファイル
- **クラウド監査ログ**（CloudTrail / Cloud Audit Logs / Entra ID サインインログ）：窃取された認証情報による異常なAPI呼出・ログイン

#### ステップ3：GitHub org を確認する

GitHub を使っている場合、org 内に `tpcp-docs` または `docs-tpcp` という名前のリポジトリが存在しないか確認する。存在していれば、窃取データがそこに保存された確定的証拠となる。

#### ステップ4：侵害が確認された場合 — 全クレデンシャルをローテーションする

Aqua Security の公式声明とSysdig TRTの推奨対応に基づくと、影響期間中にCIランナーやコンテナがアクセス可能だった全てのシークレットを侵害されたものとして扱い、ローテーションする。対象は以下の通り。

- **GitHub**：Personal Access Token（PAT）、GitHub App トークン、Deploy Key
- **クラウド**：AWS IAM アクセスキー、GCP サービスアカウントキー、Azure サービスプリンシパル
- **インフラ**：SSH鍵、Kubernetes サービスアカウントトークン、Docker レジストリ認証情報
- **アプリケーション**：データベースパスワード、APIキー、Webhook URL（Slack / Discord）
- **パッケージレジストリ**：npm / PyPI のパブリッシュトークン

Aqua Security 自身が「ローテーションがアトミックでなかった」ことが被害拡大の直接原因だったと認めている。ローテーションは一度に全部やる。部分的にやると、更新途中のトークンを攻撃者に取得される可能性がある。

#### ステップ5：侵害が確認された場合 — 該当マシンを隔離・再構築する

- **CIランナー**（GitHub Actions self-hosted runner等）：破棄して再作成する
- **開発者PC**：VS Code拡張やLiteLLM経由で侵害された場合、systemdサービス（`sysmon.py`）やPython `.pth` ファイルによる永続化が仕掛けられている可能性がある。これらを確認し、必要に応じてクリーンインストール
- **コンテナホスト**：Docker公式ブログの警告に従い、Docker ソケットをマウントしていた場合はホスト全体を侵害されたものとして扱う

#### ステップ6：侵害が確認された場合 — クラウドのアクティブセッション無効化

クレデンシャルをローテーションしても、既存のセッションが有効なままでは不十分。各クラウドプロバイダでアクティブセッションを破棄する。

- **AWS**：STS で発行済み一時認証情報を無効化
- **GCP**：OAuth トークンの取り消し
- **Azure / M365**：Entra ID でユーザー/サービスプリンシパルのセッションを無効化

#### ステップ7：監査ログを保全する

GitHub Audit Log、CloudTrail、Cloud Audit Logs 等を証拠として保全する。窃取された認証情報がいつ・どこから使われたかを特定するために必要。

### 恒久対策

#### GitHub Actions のピン留め

今回の攻撃の核心は「Git のタグは書き換え可能」という仕様を悪用したもの。Microsoft Security Blog も Sysdig TRT も、恒久対策の筆頭として「タグ参照をコミットSHA参照に切り替える」ことを推奨している。

:::details タグ参照 vs コミットSHA参照の例
```yaml
# タグ参照（攻撃者が中身を差し替え可能）
- uses: aquasecurity/trivy-action@v0.34.0

# コミットSHA参照（この特定のコードを指す。差し替え不可能）
- uses: aquasecurity/trivy-action@57a97c7e7821a5776cebc9bb87c984fa69cba8f1
```
:::

タグは「v2と名のつくもの」を指すラベルにすぎず、push権限があれば中身を差し替えられる。コミットSHAは「この特定のコード」を指すハッシュ値なので、原理的に差し替え不可能。

なお、GitHub は組織ポリシーとして SHA ピン留めを強制する機能も提供している。個人の注意ではなく組織として強制できる。

- 参考：[GitHub Actions policy now supports blocking and SHA-pinning actions](https://github.blog/changelog/2025-08-15-github-actions-policy-now-supports-blocking-and-sha-pinning-actions/)

#### 長期トークンの廃止

今回の根本原因は、aqua-bot の PAT が長期間有効で org 全体にアクセス可能だったこと。CI/CDでは OIDC（Workload Identity Federation）に移行し、短期トークンのみ使う。窃取されても有効期限が短いため被害が限定される。PyPI についても Trusted Publishers（OIDCベースの公開）への移行が推奨されている。

#### CI ランナーのランタイム監視

Sysdig TRT によると、今回の攻撃では静的解析や依存関係スキャンでは検知できなかった（信頼されたActionのソースに直接注入されたため）。ドメインレピュテーションによる検知も、新規登録ドメインのため有効ではなかった。有効だったのはランタイム検知（システムコール・ネットワーク接続・プロセス引数の監視）で、Trivy波・Checkmarx波の両方を検出できたと報告されている。

CI ランナーを「本番ホストと同じ厳格さで監視する」という考え方が今後は必要になる。Microsoft Security Blog もタグの可変性対策（SHAピン留め）、権限制御、シークレットの取り扱い、エフェメラル運用等の予防策を列挙しており、CI/CDパイプラインのセキュリティを本番環境と同等に扱うべきだという方向性が読み取れる。

#### IMDS の制限

Stealer は AWS の EC2 Instance Metadata Service（IMDS）に問い合わせて IAM ロールの認証情報を窃取する手法も使っている。CI ランナーコンテナからの IMDS アクセスは IMDSv2 のホップリミットで制限するか、クラウド認証情報が不要な場合は IMDS 自体を無効化する。

#### 依存パッケージの検証強化

- lockfile のハッシュ検証を有効化する
- npm では `minimumReleaseAge` の設定により、公開直後のバージョンが自動インストールされることを防ぐ
- Sigstore / cosign によるパッケージの署名検証を導入する

#### 社内ネットワーク・PC の観点

CI/CD や開発環境に直接関わらない部門でも、以下の対応を検討する。

- **SaaS ベンダーへの確認**：利用中の SaaS が Trivy や LiteLLM をバックエンドで使っていないか、ベンダーからのセキュリティ通知を確認する。Mandiant によると 1,000 以上の SaaS 環境が影響を受けている
- **VS Code / Cursor 拡張の確認**：開発部門以外でも VS Code を使っている場合がある。Checkmarx 拡張（ast-results、cx-dev-assist）がインストールされていないか全社的に確認する
- **MFA の確認**：窃取された認証情報が悪用された場合の被害を限定するため、重要なアカウント（クラウド管理者、GitHub org 管理者等）の MFA が有効になっているか改めて確認する
- **インシデント対応手順の確認**：Checkmarx も Aqua Security も、各社の「標準的なインシデント対応手順に従って対応を」と声明で述べている。手順が形骸化していないか、今回を機に確認する

---

## 4. 参考情報

日本語の情報があまり多くないので、Claudeにおすすめの日本語解説ページをまとめてもらった。今度の週末読んでみようと思う。

| サイト | 記事タイトル | おすすめ理由 |
|---|---|---|
| **やっていく気持ち**（米内貴志氏 / Flatt Security） | [2026年3月19日の Trivy 再侵害の概要と対応指針](https://diary.shift-js.info/trivy-compromise/) | 日本語で読めるTeamPCP関連の一次分析としてはベスト。GitHub Events APIとcommitデータからエビデンスを取得し、Imposter Commitの手法、ペイロードの3段階構造、IoC一覧まで網羅されている。「きれいな図を作る時間がなかったので、いかにもClaudeが書きそうな図ですが」という一言に親近感がある |
| **FutureVuls Blog**（フューチャー株式会社） | [Trivy サプライチェーン攻撃：FutureVuls 配布バイナリの安全性検証レポート](https://www.vuls.biz/blog/trivy-supplychain-report) | 自社製品がTrivyをエンジンとして使っているベンダーが、自社バイナリの安全性をバイナリハッシュ・ビルドタイムスタンプ・Sigstore署名検証の3点で検証し、その過程を公開したレポート。「自分たちの製品は大丈夫か？」を確認する手順の実例として参考になる |
| **FutureVuls Blog**（フューチャー株式会社） | [Trivy サプライチェーン攻撃（第2波・3/19発生）：FutureVuls 影響調査レポート](https://www.vuls.biz/blog/trivy-supplychain-report2) | 上記の第2波版。攻撃ウィンドウ内のCI実行確認コマンドや、Dependabotが悪意あるv0.69.4を検出して自動PRを生成しようとした挙動まで調査している。CI/CDの影響調査を実際にやるとこうなる、という手順書として実用的 |
| **FutureVuls Blog**（フューチャー株式会社） | [GitHub Actions・Docker Hub・npm・PyPIに波及：Trivyサプライチェーン攻撃の影響確認ガイド](https://www.vuls.biz/blog/trivy-supplychain-attack-check) | 3/25公開の最新記事。Trivy以外の波及先（Docker Hub、npm、PyPI）も含めた影響確認ガイド。本記事の1章の内容と重なる部分が多いので、日本語で全体像を確認したい場合はこちらも |
| **Sysdig 日本語ブログ** | [TeamPCPの拡大：サプライチェーン侵害がTrivyからCheckmarx GitHub Actionsへ拡大](https://www.sysdig.com/jp/blog/teampcp-expands-supply-chain-compromise-spreads-from-trivy-to-checkmarx-github-actions) | Sysdig TRTの英語分析記事の日本語翻訳版。Trivy→Checkmarxへの連鎖侵害の構造と、ランタイム検知が有効だった理由が解説されている。検知ルール（Falco）の具体例もあるので、CIランナーの監視を検討している人向け |
| **セキュリティ対策Lab** | [Trivyへのソフトウェア サプライチェーン攻撃が再発](https://rocket-boys.co.jp/security-measures-lab/trivy-supply-chain-attack-github-actions-tampering-cicd-secrets-exposure-risk/) | Aqua SecurityとGitHubの公式情報をベースに、影響バージョン・安全バージョン・影響時間帯を日本語で簡潔にまとめた記事。技術的な深堀りは少ないが、「結局どのバージョンが危ないの？」を手早く確認したい場合に便利 |
| **note**（こうき氏） | [Trivyが侵害された——セキュリティツール自体が攻撃経路になる時代](https://note.com/koki321386/n/n52b94cbc1fdb) | 技術詳細よりも「セキュリティツール自体が攻撃ベクターになる」という構造的な問題についての考察。「有名なOSSだから安全」という前提はxz utilsで揺らぎ、Trivyで崩れた、という指摘。週末に読んで考えるのに向いている |

なお、2026/3/25時点で JPCERT/CC および IPA からこのキャンペーンに関する公式の注意喚起は確認できていない。今後発出される可能性があるので、各機関のサイトも定期的に確認することを推奨する。

---

*本記事はAI（Claude / Anthropic）を使用して各ソースの情報を整理・構成しています。*
*本件は進行中のインシデントのため、新たな情報が判明した場合は記事を更新する予定です。*
*AIOpsJunk — 記録する実験、3ヶ月で忘れる前に。*
