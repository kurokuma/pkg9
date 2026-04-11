# Malicious Package Scanner

展開済みの npm / PyPI パッケージを対象にした、ルール駆動型のパッケージスキャナです。

このプロジェクトは単発のチェッカーではなく、拡張可能なスキャン基盤として実装されています。パッケージメタデータ、manifest、ファイル、前処理 artifacts、scanner signals を解析し、再現性のある JSON finding を出力します。

English README: [README.md](./README.md)

## 現在の対応範囲

- CLI ベースのスキャナ
- npm / PyPI adapter
- YAML ルールのロード、検証、実行
- file / manifest / package scope
- findings / warnings / errors / optional artifacts の JSON 出力
- built-in / custom ルールディレクトリ
- deobfuscation preprocessing
- JavaScript の AST ベース検知
- Python の AST / packaging 対応スキャン
- intent / inter-module dataflow lite
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

- `--ecosystem npm|pypi`: adapter を明示指定
- `--include-artifacts`: internal artifacts を JSON に含める
- `--rules-dir ./rules`: ルールのルートディレクトリを変更

### ルールを検証する

```bash
go run ./cmd/scanner rules validate --rules-dir ./rules
```

### ルール一覧を表示する

```bash
go run ./cmd/scanner rules list --rules-dir ./rules
```

## 出力形式

トップレベルは次の JSON 構造です。

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

## 組み込み Scanner

- `lifecycle_hook`: パッケージメタデータから lifecycle hook を抽出
- `entropy`: テキストファイル中の高エントロピー文字列を検出
- `hash`: 各ファイルの SHA-256 を記録
- `hash_ioc`: 組み込み hash IOC と照合
- `dependency_ioc`: 組み込み IOC リストと依存関係を照合
- `typosquat`: 依存関係名の typo-squatting 候補を検出
- `obfuscation`: minified 以外の難読化指標を検出
- `ai_config`: AI 設定ファイルの prompt injection を検出
- `intent_dataflow`: source-sink の intent coherence と cross-file flow lite を検出
- `js_ast`: JavaScript AST から eval、exec、credential access、dropper、prototype hook を検出
- `python`: Python source / packaging から exec、credential、network、setup、remote requirements を検出

## 組み込みルール

現在の built-in ルールは [rules/builtin](./rules/builtin) にあります。

主なカバレッジ:

- npm lifecycle script の悪用検知
- 危険な shell pattern
- JavaScript AST シグナル
- Python の挙動 / packaging シグナル
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
- `manifest_key_exists`
- `manifest_value_equals`
- `path_matches`
- `scanner_signal_exists`
- `artifact_match`
- 論理ノード `all_of`, `any_of`, `not`

## テスト

```bash
mkdir -p .cache/go-build .cache/go-mod
GOCACHE=$(pwd)/.cache/go-build GOMODCACHE=$(pwd)/.cache/go-mod go test ./...
```

## ステータス

これはまだ基盤実装ですが、JavaScript AST scanning、Python AST-assisted scanning、deobfuscation preprocessing、AI config scanning、typosquat detection、軽量な intra/inter-file dataflow まで入っています。一方で、より厳密な alias analysis、call graph 解決、taint tracking、ecosystem 追加、suppression、scoring、追加出力形式などは今後の実装対象です。

## 未到達の項目

- JavaScript / Python のより厳密な alias analysis と taint propagation
- file / module をまたぐ、より完全な call graph 解決
- class / object method を含む、より正確な inter-procedural dataflow
- npm / PyPI 以外の ecosystem 追加
- 現在の regex / field / scanner-assisted 以外の richer matcher
- suppression / baseline の運用機能
- scoring / 優先度付けレイヤ
- SARIF などの追加出力形式
- 大規模な intelligence dataset は、明示的に追加しない限りこの実装の対象外
