# Malicious Package Scanner

展開済みの npm / PyPI / Go module パッケージを対象にした、ルール駆動型のパッケージスキャナです。

このプロジェクトは単発のチェッカーではなく、拡張可能なスキャン基盤として実装されています。パッケージメタデータ、manifest、ファイル、前処理 artifacts、scanner signals を解析し、再現性のある JSON finding を出力します。

English README: [README.md](./README.md)

## 現在の対応範囲

- CLI ベースのスキャナ
- npm / PyPI / Go module adapter
- YAML ルールのロード、検証、実行
- file / manifest / package scope
- findings / warnings / errors / optional artifacts の JSON 出力
- JSON / SARIF 出力
- built-in / custom ルールディレクトリ
- deobfuscation preprocessing
- JavaScript の AST ベース検知
- Python の AST / packaging 対応スキャン
- AST 補助の intent / inter-module dataflow
- browser 向け wallet / credential theft スキャン
- obfuscation、AI config、typosquat、entropy、lifecycle、hash scanner

## ディレクトリ構成

```text
cmd/scanner/           CLI エントリポイント
internal/adapters/     ecosystem adapter
internal/core/         スキャンのオーケストレーション
internal/files/        ファイル読み込みと分類
internal/preprocess/   正規化と decode candidate 生成
internal/scanners/     scanner primitive
internal/rules/        ルール schema、読み込み、compile
internal/matcher/      条件評価
internal/model/        canonical data model
rules/builtin/         built-in ルール
rules/custom/          custom ルール
testdata/samples/      テスト用サンプルパッケージ
```

## 動作要件

- Go 1.26 以上
- 展開済みのパッケージディレクトリ

## ビルド

```bash
go build ./cmd/scanner
```

ビルド後は生成されたバイナリをそのまま実行できます。

```bash
./scanner -h
./scanner scan --path ./testdata/samples/npm-basic --rules-dir ./rules
```

Go のデフォルトキャッシュ先が使えない環境では、ローカルキャッシュを使ってください。

```bash
mkdir -p .cache/go-build .cache/go-mod
GOCACHE=$(pwd)/.cache/go-build GOMODCACHE=$(pwd)/.cache/go-mod go build ./cmd/scanner
```

## 使い方

### パッケージをスキャンする

```bash
go run ./cmd/scanner scan --path ./testdata/samples/npm-basic --rules-dir ./rules
```

または build 後:

```bash
./scanner scan --path ./testdata/samples/npm-basic --rules-dir ./rules
```

ヘルプ:

```bash
go run ./cmd/scanner -h
go run ./cmd/scanner scan -h
go run ./cmd/scanner rules -h
```

主なオプション:

- `--ecosystem npm|pypi|gomod`: adapter を明示指定
- `--format json|sarif`: 出力形式を指定
- `--include-artifacts`: internal artifacts を JSON に含める
- `--rules-dir ./rules`: ルールのルートディレクトリを変更
- `--baseline ./baseline.json`: baseline に一致する finding を suppress
- `--write-baseline ./baseline.json`: 現在の finding を baseline JSON に書き出し

### ルールを検証する

```bash
go run ./cmd/scanner rules validate --rules-dir ./rules
```

### ルール一覧を表示する

```bash
go run ./cmd/scanner rules list --rules-dir ./rules
```

## 出力形式

出力形式は `json` と `sarif` をサポートします。

JSON のトップレベルは次の構造です。

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

`artifacts` は `--include-artifacts` 指定時のみ出力されます。

`summary` には次も含まれます。

- `risk_score`
- `risk_level`
- `suppressed_findings`
- `priority`
- `risk_factors`

SARIF の例:

```bash
./scanner scan --path ./testdata/samples/npm-basic --rules-dir ./rules --format sarif
```

baseline 運用の例:

```bash
./scanner scan --path ./testdata/samples/npm-basic --rules-dir ./rules --write-baseline ./baseline.json
./scanner scan --path ./testdata/samples/npm-basic --rules-dir ./rules --baseline ./baseline.json
```

`risk_score` は `0..100` に丸められます。  
`risk_level` は `SAFE`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` のいずれかです。

## 組み込み Scanner

- `lifecycle_hook`: パッケージメタデータから lifecycle hook を抽出
- `entropy`: テキストファイル中の高エントロピー文字列を検出
- `hash`: 各ファイルの SHA-256 を記録
- `hash_ioc`: 組み込み hash IOC と照合
- `dependency_ioc`: 組み込み IOC リストと依存関係を照合
- `typosquat`: 依存関係名の typo-squatting 候補を検出
- `obfuscation`: minified 以外の難読化指標を検出
- `ai_config`: AI 設定ファイルの prompt injection を検出
- `intent_dataflow`: source-sink の intent coherence、alias 伝播、function assignment、wrapper method、imported alias、local cross-file call edge を検出
- `js_ast`: JavaScript AST から eval、exec、credential access、dropper、prototype hook を検出
- `browser`: browser wallet tampering と browser credential theft を exfiltration 前提の heuristic で検出
- `python`: Python source / packaging から exec、credential、network、setup、remote requirements を検出

## 組み込みルール

現在の built-in ルールは [rules/builtin](./rules/builtin) にあります。

読み込まれている正確な rule ID 一覧は次で表示できます。

```bash
./scanner rules list --rules-dir ./rules
```

主なルール系統:

- `ai_config.*`: `ai_config.compound_injection`
- `ast.*`: `ast.binary_dropper`, `ast.credential_access`, `ast.dangerous_exec`, `ast.prototype_hook`
- `browser.*`: `browser.credential_theft`, `browser.wallet_tampering`
- `dataflow.*`: `dataflow.inter_module`
- `dependency.*`: `dependency.typosquat_detected`
- `hash.*`: `hash.ioc_match`
- `intent.*`: `intent.coherence`
- `obfuscation.*`: `obfuscation.detected`
- `package.*`: lifecycle script、dependency URL、install-time behavior
- `pkg.*`: package-level entropy、install hook、dependency IOC summary
- `python.*`: Python の exec、credential、network、surveillance、anti-analysis、setup
- `shell.*`: shell execution、exfiltration、reverse shell、destructive command
- `source.*`: source-level の credential、exfiltration、persistence、staging、anti-analysis

主なカバレッジ:

- npm lifecycle script の悪用検知
- lifecycle script 内の token / credential access の細粒度検知
- 危険な shell pattern、exfiltration、reverse shell、破壊的 command の派生検知
- dynamic require/import、require.cache poisoning、env proxy interception、sandbox check
- staged decode/eval と binary-payload 系の source pattern
- Telegram / Slack / Google Analytics 系の exfiltration pattern
- iframe keylogging、SSH authorized_keys persistence、Electron app.asar tampering、socket ベース C2 pattern
- install-time global package installation、localhost websocket daemon persistence、Solana dead-drop C2、header-keyed payload execution
- signal ベースの browser wallet tampering / browser credential theft finding
- JavaScript AST シグナル
- Python の挙動 / packaging シグナル
- Python の Discord webhook、Gmail SMTP surveillance、Startup persistence pattern
- Python の tracer / debugger / uptime / analyst tooling を狙う anti-analysis pattern
- AI config injection
- obfuscation
- intent coherence / inter-module dataflow lite
- typosquat 検知
- entropy と IOC 補助 finding

直近の精度改善:

- URL dependency は repository / homepage metadata ではなく dependency section に限定
- `require.cache` は read-only access ではなく mutation / delete を中心に検知
- socket C2 は minified な `io()` 一般を避けるよう調整
- intent/dataflow の source 判定は汎用 `process.env` より secret-like な env / credential material を優先

## Risk 評価

`risk_score` は `0..100` に丸め込まれる集計スコアです。

現在の主な加点要素:

- finding severity:
  - `critical` `+30`
  - `high` `+18`
  - `medium` `+10`
  - `low` `+4`
  - `info` `+1`
- package-level bonus:
  - install hook `+8`
  - build hook `+3`
  - `intent_coherence` signal `+15`
  - `inter_module_dataflow` signal `+15`
  - `obfuscation_detected` signal `+8`
  - `ai_config_injection` signal `+10`
  - `ast_dangerous_exec` signal `+8`
  - `python_exec_behavior` signal `+8`
  - `typosquat_detected` signal `+6`

`risk_level` の閾値:

- `SAFE`: `0`
- `LOW`: `1..24`
- `MEDIUM`: `25..49`
- `HIGH`: `50..74`
- `CRITICAL`: `75..100`

`priority` の閾値:

- `P1`: score `>= 85`、または cross-file dataflow、または install hook + dangerous exec
- `P2`: score `>= 60`、または obfuscation、または credential-to-sink
- `P3`: score `>= 30`、または finding 2 件以上
- `P4`: score `>= 1`
- `P5`: score `0`

現在の `risk_factors`:

- `install_hook_with_exec`
- `credential_to_sink`
- `cross_file_dataflow`
- `obfuscation`
- `ai_config_injection`
- `typosquat`
- `critical_finding`
- `high_severity_finding`

## 評価観点

評価時の主な観点:

- 検知カバレッジ: 明確に悪性な package を `SAFE` にしないか
- 誤検知: 正常 package をどの程度 `SAFE` に寄せられるか
- 説明可能性: file、rule、signal まで追えるか
- 優先度付け: `risk_score`、`risk_level`、`priority` が運用感覚に合うか
- 安定性: 同じ入力で再実行しても結果が安定するか

簡易採点表:

| 項目 | 1 | 3 | 5 |
| --- | --- | --- | --- |
| 検知カバレッジ | 明白な malware を見逃す | 一部の malware family は拾える | 明確な悪性 package を概ね安定して拾える |
| 誤検知 | benign package が頻繁に `MEDIUM+` になる | 良し悪しが混在する | 多くの benign package が `SAFE/LOW` に収まる |
| 説明可能性 | なぜ当たったか追いにくい | 一部は追える | rule、signal、file path が概ね明確 |
| 優先度付け | score が実態に合わない | 部分的に使える | score と priority が実務上有用 |
| 拡張性 | rule/scanner の追加が壊れやすい | 中程度 | 新しい rule/scanner を素直に追加できる |

## 高度化に向けた次の Step

- JS / Python の taint を SSA / CFG 寄りに強化する
- inter-procedural と cross-file の call graph 解決を厳密化する
- wallet tampering、cookie theft、credential store abuse 向け browser scanner をさらに専用化する
- file context の弱い package-level AST finding を減らす
- benign / malicious corpus を継続比較できる評価 fixture を整備する

## ルールファイル

ルールは YAML で定義し、次のディレクトリからロードします。

- [rules/builtin](./rules/builtin)
- [rules/custom](./rules/custom)

現在のルールモデル:

- `metadata`
- `scope`
- `selectors`
- `conditions`
- `emit`

対応 scope:

- `file`
- `manifest`
- `package`

現在の matcher:

- `contains`
- `regex`
- `field_exists`
- `field_equals`
- `field_matches`
- `field_in`
- `manifest_key_exists`
- `manifest_value_equals`
- `path_matches`
- `scanner_signal_exists`
- `signal_count_at_least`
- `artifact_match`
- `artifact_field_equals`
- 論理ノード `all_of`, `any_of`, `not`

## テスト

```bash
mkdir -p .cache/go-build .cache/go-mod
GOCACHE=$(pwd)/.cache/go-build GOMODCACHE=$(pwd)/.cache/go-mod go test ./...
```

## ステータス

これはまだ基盤実装ですが、JavaScript AST scanning、Python AST-assisted scanning、browser wallet / credential theft 専用 scanning、deobfuscation preprocessing、AI config scanning、typosquat detection、複数 ecosystem の package parsing、richer matcher、baseline ベースの suppression、alias / property を追う強化版の intra/inter-file dataflow、risk scoring の上に乗る prioritization layer まで入っています。

## 現在の制約

- JavaScript / Python の dataflow は、local alias、再代入、function assignment、object/dict property flow、wrapper method、imported alias、単純な call edge を追いますが、SSA / CFG 完備の解析ではなく heuristic です。
- cross-file 解決は import graph、imported wrapper、local call edge までで、動的 import や reflection、実行時 dispatch の全パターンは扱いません。
- 大規模な IOC / threat-intel dataset は、明示的に追加しない限り対象外です。
