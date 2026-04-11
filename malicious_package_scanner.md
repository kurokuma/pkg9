# Malicious Package Scanner 設計書（完全版 v2）

## 1. 文書の目的

本書は、悪性・不審パッケージを検知するクロスプラットフォーム対応スキャナの正式設計書である。

初期対応エコシステムは npm および PyPI とするが、将来的に OpenVSX、RubyGems、Maven、NuGet、crates.io などの ecosystem を追加できる構造を前提とする。

本システムは、展開済みパッケージの内容・マニフェスト・メタデータ・構成・パッケージ全体の特徴を解析し、YAML ベースのルールと複数の scanner primitive によって findings を生成する。現在の対応範囲よりも、拡張性・保守性・再現性・性能・運用性・説明可能性を重視して設計する。

---

## 2. 設計目標

### 2.1 機能目標

- 展開済みパッケージディレクトリを入力として受け取れる
- npm / PyPI の package metadata と manifest を認識できる
- built-in ルールおよび組織固有 custom ルールを実行できる
- findings / warnings / errors を JSON で構造化出力できる
- scanner primitive を組み合わせて検知を行える
- ルール作成・検証・運用を継続可能な形で行える

### 2.2 非機能目標

- Linux / macOS / Windows で動作する
- ルール数・ファイル数が多い場合でも不要な評価を避け、高速に動作する
- deterministic な出力を行い、差分比較しやすい
- ecosystem 追加時にコアが壊れにくい
- DSL 拡張や matcher 追加、scanner 追加に耐えられる
- 誤検知抑制、ルールテスト、再スキャン比較、説明可能性など運用面に耐えられる

### 2.3 設計思想

本システムは「npm 用スキャナ」「PyPI 用スキャナ」の集合ではなく、**拡張可能なパッケージスキャン基盤** として設計する。

中心となる考え方は以下である。

1. ecosystem ごとの差異は adapter で吸収する
2. コアは canonical model のみを扱う
3. YAML ルールは typed DSL / condition tree として内部表現へ変換する
4. ルール表現力は matcher registry と scanner registry の拡張で高める
5. canonical rule と ecosystem-specific rule を両立させる
6. scanner primitive と preprocessing を rule engine の下支えとして持つ
7. explainability と artifacts を内部設計に組み込む

---

## 3. スコープ

### 3.1 今回の対象

- CLI ベースのスキャンツール
- npm / PyPI adapter
- YAML ルールのロード・検証・コンパイル・実行
- file / manifest / package scope の基礎サポート
- findings / warnings / errors を含む JSON 出力
- built-in / custom rule の分離
- scanner layer / preprocessing layer / analysis artifacts の基本構造
- ルールテストの最小基盤

### 3.2 将来対象

- OpenVSX、RubyGems、Maven、NuGet、crates.io 等の adapter
- archive 直接入力
- AST matcher
- cross-file rule
- intent / lightweight dataflow
- inter-module flow
- suppression / baseline
- rule generate
- SARIF 等の追加出力形式
- heuristic score / risk score

### 3.3 今回は対象外

- GUI / Web UI
- 分散実行基盤
- LLM 前提の自動ルール生成
- 高度な sandbox 実行環境
- 本格的な ML 分類器

---

## 4. 全体アーキテクチャ

```text
+------------------------+
| CLI / App Layer        |
+------------------------+
            |
            v
+------------------------+
| Scan Orchestrator      |
+------------------------+
   |            |             |               |
   |            |             |               |
   v            v             v               v
+------+   +-----------+  +----------+  +-------------+
|Adapters| |Preprocess |  |Scanners  |  |Rule Engine  |
+------+   +-----------+  +----------+  +-------------+
   |            |             |               |
   +------------+-------------+---------------+
                        |
                        v
+----------------------------------------------------------+
| Canonical Package / Manifest / File / Artifact Model     |
+----------------------------------------------------------+
                        |
                        v
+----------------------+     +-----------------------------+
| Findings / Issues    | --> | Explain / Score / Output    |
+----------------------+     +-----------------------------+
```

### 4.1 各レイヤの役割

#### Adapter Layer

ecosystem 固有の構造や metadata を canonical model に変換する。

#### Preprocessing Layer

検知前の正規化・軽量復号・単純難読化解除・トークン化などを行う。

#### Scanner Layer

ルールとは独立した primitive scanner を実行し、signals / observations / artifacts を生成する。

#### Rule Engine

compiled rule を canonical model と scanner outputs に適用する。

#### Explain / Score / Output

findings の説明情報、任意のスコア、JSON 出力を生成する。

---

## 5. 設計原則

### 5.1 Core は ecosystem を知らない

コアは npm や PyPI の構造を直接認識しない。ecosystem 固有情報は adapter が canonical model に変換する。

### 5.2 Adapter は ecosystem knowledge provider である

adapter は単なる manifest parser ではなく、以下を提供する。

- metadata 抽出
- canonical field 生成
- ecosystem-specific field 生成
- known hook points の抽出
- file classification の補助
- language hint の提供

### 5.3 Preprocessing と Detection は分離する

復号・展開・文字列正規化・簡易難読化解除は detection logic 本体から分離する。

### 5.4 Scanner primitive をルールの前段として扱う

すべてを YAML ルールで表現しようとせず、よく使う分析は scanner primitive として独立させる。

### 5.5 Rule Engine は DSL を逐次解釈しない

YAML は入力表現にすぎず、ロード後に validate・compile を経て内部表現へ変換する。

### 5.6 Matcher と Scanner は registry により拡張可能である

表現力は YAML の自由記述ではなく、matcher registry と scanner registry の拡張により実現する。

### 5.7 出力は triage と machine processing の両方に適する

findings / warnings / errors を明確に分離し、再現性・比較可能性・集計容易性・説明可能性を重視する。

---

## 6. モジュール構成

```text
cmd/
  scanner/
    main.go

internal/
  app/
  cli/
  core/
  adapters/
    adapter.go
    npm/
    pypi/
    openvsx/          # 将来
  files/
  manifests/
  preprocess/
  scanners/
    registry.go
    entropy/
    hash/
    typo/
    dependency/
    ai_config/
    actions/
  rules/
  matcher/
  output/
  explain/
  scoring/
  model/
  parsers/
  issues/
  util/

docs/
  design-spec.md
  rule-format.md
  adapter-spec.md
  scanner-spec.md
  output-spec.md

rules/
  builtin/
  custom/

testdata/
  samples/
  rules/
```

---

## 7. Core Data Model

### 7.1 ScanTarget

スキャン対象パッケージを表す共通モデル。

#### 必須フィールド

- `target_id`
- `ecosystem`
- `package_name`
- `version`
- `archive_hash` または `content_hash`
- `root_path`
- `metadata_raw`
- `canonical_package`
- `ecosystem_fields`
- `files`
- `manifests`
- `artifacts`

### 7.2 CanonicalPackage

ecosystem 非依存で使える共通パッケージ情報。

#### 例

- `name`
- `version`
- `description`
- `authors`
- `maintainers`
- `repository`
- `homepage`
- `bugs_url`
- `dependencies`
- `dev_dependencies`
- `optional_dependencies`
- `entrypoints`
- `hooks`
- `has_install_hook`
- `has_build_hook`
- `license`
- `published_at`
- `files_count`
- `scripts_present`

### 7.3 EcosystemFields

ecosystem 固有の生情報または canonical 化困難な情報を保持する。

例:

- npm: `package_json.scripts.postinstall`
- pypi: `pyproject.project.scripts`
- pypi: `setup_cfg.options.entry_points`

### 7.4 ScanFile

各ファイルの共通モデル。

#### 必須フィールド

- `relative_path`
- `file_name`
- `extension`
- `size`
- `hash`
- `is_text`
- `is_manifest`
- `language_hint`
- `classification`
- `normalized_path`
- `decode_status`

### 7.5 Manifest

マニフェストファイルの抽象化。

#### フィールド

- `manifest_type`
- `path`
- `canonical_fields`
- `ecosystem_fields`
- `raw`
- `parse_status`

manifest type の例:

- `package_json`
- `pyproject_toml`
- `setup_py`
- `setup_cfg`
- `requirements_txt`

### 7.6 AnalysisArtifact

scanner や preprocessing が生成する中間成果物を表す。

#### 例

- extracted URLs
- decoded strings
- suspicious imports
- entropy observations
- lifecycle hooks found
- dependency observations
- IOC matches
- typo candidates

---

## 8. Ecosystem Adapter Architecture

### 8.1 Adapter Interface

各 ecosystem adapter は、少なくとも次の責務を持つ。

- `Detect(path) -> bool`
- `LoadTarget(path) -> ScanTarget`
- `ExtractCanonicalPackage(target) -> CanonicalPackage`
- `ExtractManifests(target) -> []Manifest`
- `ExtractKnownHooks(target) -> []Hook`
- `GetEcosystemFields(target) -> map`

### 8.2 Adapter の責務

- input path が対応 ecosystem か判定する
- 必要な manifest を見つける
- metadata を読み出す
- canonical fields を生成する
- package-level rule で使える hook / dependency / entrypoint 等を抽出する

### 8.3 npm Adapter の例

- `package.json`
- scripts
- dependencies / devDependencies / optionalDependencies
- bin
- repository / homepage / bugs
- files list

canonical 化例:

- `has_install_hook` ← `preinstall`, `install`, `postinstall` の有無
- `hooks.install` ← scripts の install 系
- `entrypoints` ← bin, main, exports

### 8.4 PyPI Adapter の例

- `pyproject.toml`
- `setup.py`
- `setup.cfg`
- `requirements*.txt`
- entry_points
- dependencies

canonical 化例:

- `entrypoints`
- `dependencies`
- install/build 相当フック情報
- `repository`, `homepage`

### 8.5 Adapter 拡張ルール

- コアを修正しなくても追加可能であることを目指す
- ecosystem-specific logic は adapter 配下に閉じ込める
- canonical 化できるものは積極的に canonical fields に上げる
- canonical 化できないものは ecosystem_fields に残す

---

## 9. Preprocessing Layer

### 9.1 目的

検知前に、難読化・文字列変換・表記差異を軽減し、scanner / matcher の精度を高める。

### 9.2 初期対象

- text normalization
- whitespace normalization
- line ending normalization
- simple string concat folding
- charcode decode candidate
- base64 decode candidate
- hex array flattening candidate
- const propagation lite

### 9.3 原則

- 完全な deobfuscation を目指さない
- reversible / explainable な変換を優先する
- 原文と変換後の対応関係を artifacts として保持できるようにする

### 9.4 出力

preprocessing は findings を直接出さず、以下を返す。

- normalized text
- decoded candidates
- transform metadata
- warnings / diagnostics

---

## 10. Scanner Layer

### 10.1 目的

ルール DSL に全責務を持たせず、頻出する分析観点を scanner primitive として切り出す。

### 10.2 Scanner の分類

#### Content Scanners

- pattern-oriented scanner
- entropy scanner
- hash scanner
- credential pattern scanner

#### Package / Metadata Scanners

- dependency scanner
- lifecycle hook scanner
- package IOC scanner
- typosquat scanner

#### Domain-specific Scanners

- Python scanner
- GitHub Actions scanner
- AI config scanner

#### Flow / Intent Scanners（将来段階的拡張）

- source-sink pairing
- intra-file lightweight flow
- cross-file reference graph
- inter-module taint

### 10.3 Scanner Interface

各 scanner は少なくとも以下を返せるべきである。

- observations
- artifacts
- optional findings
- optional warnings / errors
- diagnostics

### 10.4 初期実装対象候補

- entropy scanner
- hash scanner
- dependency IOC scanner
- typosquat scanner
- lifecycle hook scanner
- AI config scanner
- GitHub Actions scanner

### 10.5 Scanner Pack 概念

scanner は pack 単位で構成できるようにする。

例:

- `scanner-pack-javascript`
- `scanner-pack-python`
- `scanner-pack-package-intel`
- `scanner-pack-ai-config`
- `scanner-pack-ci`

---

## 11. Rule System Architecture

### 11.1 基本方針

- ルールは YAML で記述する
- DSL としての意味論は本システム独自に持つ
- Semgrep 風の見た目に寄せるが、package scanning 用に最適化する
- 完全互換は目指さない

### 11.2 ルールの大きな構造

1. `metadata`
2. `scope`
3. `selectors`
4. `conditions`
5. `emit`

### 11.3 metadata

- `id`
- `name`
- `description`
- `severity`
- `confidence`
- `tags`
- `category`
- `namespace`
- `rule_source`
- `rule_version`
- `schema_version`
- `min_engine_version`
- `references`
- `taxonomy`（任意）

### 11.4 scope

- `file`
- `manifest`
- `package`

将来:

- `cross_file`

### 11.5 selectors

- `ecosystems`
- `languages`
- `file_glob`
- `manifest_types`
- `classifications`
- `canonical_fields_present`
- `path_glob`
- `max_file_size`
- `required_scanners`

### 11.6 conditions

条件木として表現する。

論理ノード:

- `all_of`
- `any_of`
- `not`

leaf 条件:

- `contains`
- `contains_all`
- `contains_any`
- `regex`
- `field_equals`
- `field_exists`
- `path_matches`
- `dependency_name_matches`
- `count_files_matching`
- `manifest_key_exists`
- `manifest_value_equals`
- `scanner_signal_exists`
- `artifact_match`

### 11.7 emit

- `finding_name`
- `message`
- `evidence_fields`
- `context_strategy`
- `references`
- `remediation_hint`

---

## 12. Rule Types

### 12.1 Canonical Rule

canonical model のみを前提としたルール。

#### 特徴

- ecosystem をまたいで再利用しやすい
- 今後 ecosystem を増やしたときにも効きやすい
- built-in の中心に据える価値が高い

#### 例

- install hook を持つ
- 外部 URL を含む
- entrypoint が定義されている
- dependency に一致するパターンを持つ

### 12.2 Ecosystem-specific Rule

ecosystem 固有の field や manifest を見るルール。

#### 特徴

- 高精度な検知に必要
- 共通化しにくい構造に対応できる
- adapter ごとの知識を活用しやすい

#### 例

- npm の `package.json.scripts.postinstall`
- pypi の `setup.py` 特有パターン

### 12.3 Scanner-assisted Rule

scanner の signal / artifact を前提として評価するルール。

#### 例

- entropy scanner が高エントロピー文字列を報告
- dependency IOC scanner が IOC 一致を報告
- typo scanner が typo candidate を報告

### 12.4 設計上の原則

- 可能な限り canonical rule で書けるようにする
- 固有構造に依存する場合のみ ecosystem-specific rule を使う
- scanner primitive で表現した方がよいものは scanner-assisted rule に寄せる

---

## 13. Matcher Registry

### 13.1 目的

ルール表現力を YAML の自由記述ではなく、matcher の差し替え・追加可能性により確保する。

### 13.2 初期 matcher

- `contains`
- `contains_all`
- `contains_any`
- `regex`
- `field_exists`
- `field_equals`
- `manifest_key_exists`
- `manifest_value_equals`
- `path_matches`
- `scanner_signal_exists`
- `artifact_match`

### 13.3 将来 matcher

- `ast_pattern`
- `import_exists`
- `entropy_above`
- `url_match`
- `dependency_name_match`
- `cross_file_reference`
- `count_files_matching`
- `package_metric_above`

### 13.4 Matcher Contract

各 matcher は少なくとも以下を返せるべきである。

- matched / not matched
- evidence
- location（該当する場合）
- matched_text（該当する場合）
- optional diagnostics

### 13.5 Matcher 禁止事項

- 無制限の高コスト処理
- 任意コード実行
- 外部アクセス前提の matcher
- 無制限 cross join 的評価

---

## 14. Rule Compilation

### 14.1 必要性

YAML を毎回逐次解釈すると遅くなるため、ロード時にルールを内部表現へ変換する。

### 14.2 コンパイル対象

- glob のコンパイル
- regex のコンパイル
- selector の正規化
- required tokens の抽出
- condition tree の validation
- 対象 scope の明示化
- required scanners の解決

### 14.3 CompiledRule が持つべき情報

- metadata
- scope
- normalized selectors
- compiled conditions
- required tokens
- execution hints
- matcher references
- scanner prerequisites

### 14.4 execution hints

- target ecosystem set
- file extension filters
- manifest type filters
- token requirements
- file size upper bound
- scope kind

---

## 15. Scan Pipeline

### 15.1 全体フロー

1. 入力 path を受け取る
2. adapter を選定する
3. ScanTarget を生成する
4. files を列挙・分類する
5. manifests を抽出する
6. canonical package model を構築する
7. preprocessing を実行する
8. scanner packs を実行する
9. rule をロード・validate・compile する
10. scope ごとに対象を列挙する
11. selector / precondition で候補 rule を絞る
12. matcher を評価する
13. findings / warnings / errors / artifacts を集約する
14. summary / explain / score を生成する
15. JSON を出力する

### 15.2 Scope 別の評価対象

#### file scope

- ScanFile 単位で評価

#### manifest scope

- Manifest 単位で評価

#### package scope

- CanonicalPackage + ecosystem_fields + file inventory + scanner artifacts を対象に評価

---

## 16. File Processing Design

### 16.1 File Loader

各ファイルについて以下を一度だけ処理し、キャッシュする。

- raw bytes
- text decode
- normalized text
- line offsets
- token set
- hash
- text/binary classification

### 16.2 File Classification

最低限以下を判定する。

- source code
- manifest
- config
- binary
- archive
- generated/minified candidate
- unknown

### 16.3 Context Extraction

- before / after は別にせず `context` に統合
- line-based または char-based で切り出す
- 最大長制限を持つ
- 機密値 redaction 可能にする余地を残す

---

## 17. Analysis Artifacts Model

### 17.1 目的

中間解析成果物を内部に残し、explain、rule tuning、generate、将来のスコアリングに活用する。

### 17.2 代表例

- URLs
- domains
- suspicious imports
- decoded strings
- matched IOC indicators
- high entropy tokens
- package hooks
- typo candidates
- dependency matches
- workflow indicators

### 17.3 扱い

- デフォルト出力では optional
- verbose / debug モードでは出力可能
- internal APIs では first-class entity として扱う

---

## 18. Performance Design

### 18.1 基本方針

ボトルネックは大抵以下である。

- ディスク I/O
- テキスト正規化
- regex
- manifest parsing
- scanner の重い処理

### 18.2 必須最適化

- ルール前コンパイル
- selector/precondition による候補削減
- ファイルキャッシュ
- scope ごとの対象絞り込み
- scanner pack の必要時実行
- deterministic かつ効率的な処理順序

### 18.3 Cheap Filter と Expensive Evaluation

#### cheap filter

- ecosystem filter
- scope filter
- extension filter
- path glob
- manifest type
- token existence
- size limit
- required scanner presence

#### expensive evaluation

- 複合条件評価
- 将来の AST matcher
- 高コスト regex
- flow analysis

### 18.4 Resource Guard

- 最大ファイルサイズ
- 最大ファイル数
- 最大 findings 数
- context 最大長
- 総テキスト処理量上限
- スキャン timeout
- scanner execution budget

---

## 19. Deterministic Output

### 19.1 必要性

差分比較、CI、レビュー、再現性のため、出力順序は安定させる。

### 19.2 安定化対象

- file 列挙順
- scanner 実行順
- rule ロード順
- findings のソート順
- warnings / errors のソート順

### 19.3 推奨ソートキー

findings:

1. severity
2. rule_id
3. file_path
4. line_start
5. fingerprint

warnings/errors:

1. level
2. code
3. file_path
4. rule_id

---

## 20. Output Model

### 20.1 トップレベル構造

```json
{
  "scan_metadata": {},
  "summary": {},
  "findings": [],
  "warnings": [],
  "errors": [],
  "artifacts": []
}
```

### 20.2 scan_metadata

- `scan_id`
- `engine_version`
- `schema_version`
- `package_name`
- `version`
- `ecosystem`
- `target_id`
- `archive_hash`
- `started_at`
- `finished_at`
- `config_snapshot`

### 20.3 summary

- `scan_status`
- `files_discovered`
- `files_scanned`
- `files_skipped`
- `rules_loaded`
- `rules_executed`
- `rules_failed`
- `scanners_executed`
- `scanner_warnings_total`
- `findings_total`
- `warnings_total`
- `errors_total`
- `severity_counts`
- `skip_reason_counts`

### 20.4 findings

- `fingerprint`
- `rule_id`
- `rule_version`
- `rule_source`
- `finding_name`
- `severity`
- `message`
- `scope`
- `file_path`
- `file_name`
- `location`
- `matched_text`
- `context`
- `tags`
- `references`
- `why_matched`
- `contributing_scanners`

### 20.5 warnings / errors

- `code`
- `level`
- `message`
- `component`
- `file_path`（任意）
- `rule_id`（任意）
- `scanner_id`（任意）
- `recoverable`
- `details`

### 20.6 artifacts

- `artifact_type`
- `source_component`
- `scope`
- `file_path`
- `value`
- `metadata`

### 20.7 scan_status

- `completed`
- `completed_with_warnings`
- `completed_with_errors`
- `partial`
- `failed`

---

## 21. Evidence and Explainability

### 21.1 Evidence Model

内部的には finding の根拠を保持する。

#### 含めたい情報

- matched matcher
- matched condition path
- matched_text
- field_name
- manifest key
- file path
- location
- scanner signals
- additional evidence map

### 21.2 Explain Model

ユーザー向けまたは analyst 向け説明を構成する情報。

- `why_matched`
- `matched_conditions`
- `contributing_scanners`
- `references`
- `taxonomy`
- `remediation_hint`

### 21.3 利用先

- explain 機能
- rule tuning
- analyst triage
- generate 機能の将来実装

---

## 22. Scoring Layer（将来前提）

### 22.1 方針

初期実装では必須ではないが、heuristic / risk score を載せる余地を設ける。

### 22.2 スコア要素候補

- high severity findings
- install hooks
- IOC matches
- typo score
- entropy observations
- suspicious decoded strings
- actions / workflow indicators

### 22.3 原則

- スコアは findings を置き換えない
- triage 優先度付けの補助として扱う
- 説明可能な heuristic から始める

---

## 23. Errors / Warnings Design

### 23.1 方針

エラーや警告は findings と分離し、構造化オブジェクトとして扱う。

### 23.2 主な warning 例

- `FILE_TOO_LARGE_TRUNCATED`
- `UNSUPPORTED_FILE_TYPE`
- `ENCODING_DETECTION_FAILED`
- `MATCHER_SKIPPED`
- `SCANNER_SKIPPED`
- `CONTEXT_TRUNCATED`

### 23.3 主な error 例

- `RULE_SCHEMA_INVALID`
- `RULE_DUPLICATE_ID`
- `RULE_COMPILE_FAILED`
- `FILE_READ_FAILED`
- `MANIFEST_PARSE_FAILED`
- `SCANNER_EXECUTION_FAILED`
- `SCAN_TIMEOUT`

### 23.4 skip reason

- `too_large`
- `binary`
- `unsupported_type`
- `read_failed`
- `policy_excluded`
- `timeout`

---

## 24. Rule Versioning and Compatibility

### 24.1 必須項目

- `schema_version`
- `rule_version`
- `min_engine_version`

### 24.2 理由

- DSL が将来拡張される
- matcher が増える
- scanner dependency が増える
- 旧ルールとの互換性問題が起こる

### 24.3 方針

- ルールは schema_version に従って validate する
- engine は解釈可能な schema_version のみ受け入れる
- min_engine_version を満たさない場合は error とする

---

## 25. Built-in / Custom Rule Management

### 25.1 分離

- `rules/builtin/`
- `rules/custom/`

### 25.2 出力に残すべき項目

- `rule_source`
- `namespace`
- `rule_version`

### 25.3 重複ポリシー

- 同一 `rule_id` の重複は原則禁止
- override を許すなら明示モードに限定

---

## 26. Rule Validation

### 26.1 検証内容

- YAML 構文
- 必須フィールド
- severity / scope / matcher / scanner 名の妥当性
- selector の整合性
- condition tree の構文整合性
- duplicate rule_id
- version compatibility

### 26.2 バリデーション結果

- CLI では非ゼロ終了コードを返せる
- スキャン時は errors に格納可能

---

## 27. Rule Testing

### 27.1 必要性

拡張性を維持するには、ルールの継続的追加に耐える品質管理が必要。

### 27.2 最小構成

- positive sample
- negative sample
- expected finding count
- expected rule_id

### 27.3 将来

- expected fingerprints
- performance budget
- false positive regression test

---

## 28. Suppression / Baseline（将来前提）

### 28.1 今回の扱い

フル実装は必須ではないが、将来対応できる設計にしておく。

### 28.2 想定単位

- rule_id
- path + rule_id
- fingerprint

### 28.3 必要性

誤検知抑制、例外扱い、差分比較が必須になるため。

---

## 29. Rule Generate（将来前提）

### 29.1 位置づけ

自動完成機能ではなく、ルール作成支援機能として設計する。

### 29.2 将来候補

- `rules init`
- `rules scaffold`
- `rules generate from-sample`

### 29.3 今回の設計への影響

- rule schema がテンプレ化しやすいこと
- evidence / artifacts が内部に残ること
- CLI が `rules` サブコマンド構造を持つこと

---

## 30. Cross-platform Design

### 30.1 必須配慮

- パス区切り差異
- case sensitivity 差異
- 改行コード差異
- 文字コード差異
- 長パス

### 30.2 方針

- ルール評価は normalized path を前提にする
- テキストは正規化した上で matcher に渡す
- OS 依存挙動を adapter や util 層で吸収する

---

## 31. Security Considerations

### 31.1 入力は信頼しない

パッケージやファイル内容は悪意ある入力である前提で設計する。

### 31.2 必須対策

- path traversal を考慮した将来設計
- 巨大入力制限
- regex 暴走抑制
- 任意コード実行禁止
- 外部アクセス不要設計

### 31.3 出力に関する注意

- `context` はサイズ制限を設ける
- 将来的に secret redaction 可能にする
- 過度に巨大な findings を出さない

---

## 32. CLI Design

### 32.1 最低限必要なコマンド

#### `scan`

パッケージをスキャンする。

```bash
scanner scan --path ./pkg --ecosystem npm --format json
```

#### `rules validate`

ルールの整合性を検証する。

#### `rules list`

ロード可能なルール一覧を表示する。

### 32.2 将来追加候補

- `rules init`
- `rules scaffold`
- `benchmark`
- `inspect`
- `explain`

---

## 33. 実装優先順位

### Phase 1: 骨格

- Go module
- CLI 雛形
- model 定義
- JSON 出力スキーマ

### Phase 2: adapter

- npm adapter
- pypi adapter
- canonical package model 構築

### Phase 3: file / manifest / preprocess 基盤

- file loader
- classification
- manifest parse
- normalized text / line offsets
- preprocessing primitive

### Phase 4: scanner layer

- scanner registry
- lifecycle hook scanner
- entropy scanner
- hash scanner
- dependency IOC scanner
- typo scanner の土台

### Phase 5: rules

- schema
- validation
- compile
- built-in/custom loading

### Phase 6: matcher

- initial matcher registry
- selector filtering
- findings generation
- scanner-assisted rule support

### Phase 7: issues / artifacts / summary

- warnings/errors
- artifacts
- skip reason counts
- scan_status
- explain metadata

### Phase 8: tests

- unit tests
- integration tests
- rule fixture tests
- scanner fixture tests

---

## 34. 採用判断の原則

機能を追加する際は、以下の順に判断する。

1. canonical model を汚さないか
2. adapter で吸収すべき問題ではないか
3. scanner primitive にすべきか
4. matcher 追加で表現できるか
5. rule DSL を壊さずに済むか
6. deterministic output を崩さないか
7. resource guard を破らないか

---

## 35. この設計で得られるもの

- npm / PyPI 以外の ecosystem を追加しやすい
- ルール DSL を matcher 追加で拡張しやすい
- scanner primitive を pack 単位で追加しやすい
- 共通ルールと固有ルールを整理して運用できる
- findings の再現性・比較可能性・説明可能性が高い
- rules / adapters / scanners / matchers を独立に改善しやすい
- 将来の rule generate、suppression、AST matcher、scoring に接続しやすい

---

## 36. 最終方針

本システムは、単発の悪性パッケージチェッカーではなく、**ecosystem と rule pack、scanner pack が増え続けても破綻しないパッケージスキャン基盤** として実装する。

そのため、最優先事項は以下である。

1. canonical package model を正式化する
2. ecosystem adapter interface を明確にする
3. preprocessing layer と scanner layer を rule engine から分離する
4. rule DSL を condition tree + matcher registry 方式で実装する
5. canonical rule と ecosystem-specific rule と scanner-assisted rule を両立させる
6. versioning、deterministic output、resource guard、explainability を最初から入れる

この方針に従い、まずは npm / PyPI 対応の堅実な v1 を完成させ、その後 adapter・scanner・matcher・rule pack を拡張する。

