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
- 基本的な preprocessing と scanner primitive

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
- `dependency_ioc`: 組み込み IOC リストと依存関係を照合

## 組み込みルール

現在の built-in ルールは [rules/builtin](/Users/nanoha/work/pkg9/rules/builtin) にあります。

- npm の install lifecycle hook 検知
- 高エントロピー token signal 検知
- 不審な dependency IOC 検知

## ルールファイル

ルールは YAML で定義し、次のディレクトリからロードします。

- [rules/builtin](/Users/nanoha/work/pkg9/rules/builtin)
- [rules/custom](/Users/nanoha/work/pkg9/rules/custom)

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

これは v1 の基盤実装です。エンドツーエンドのスキャンは可能ですが、`malicious_package_scanner.md` にある設計目標のうち、より高度な matcher、ecosystem 追加、cross-file analysis、suppression、scoring、追加出力形式などは今後の実装対象です。
