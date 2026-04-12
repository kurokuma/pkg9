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
