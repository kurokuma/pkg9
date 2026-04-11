# Malicious Package Scanner

A rule-driven package scanner for unpacked npm and PyPI packages.

This project is an extensible scanning foundation rather than a one-off checker. It analyzes package metadata, manifests, files, preprocessing artifacts, and scanner signals, then emits deterministic JSON findings.

Japanese README: [README.ja.md](./README.ja.md)

## Current Scope

- CLI-based scanner
- npm and PyPI adapters
- YAML rule loading, validation, and execution
- File, manifest, and package scopes
- Structured JSON output for findings, warnings, errors, and optional artifacts
- JSON and SARIF output
- Built-in and custom rule directories
- Deobfuscation preprocessing
- AST-based JavaScript scanning
- AST-based and packaging-aware Python scanning
- Intent and inter-module dataflow lite
- Obfuscation, AI config, typosquat, entropy, lifecycle, and hash scanners

## Repository Layout

```text
cmd/scanner/           CLI entrypoint
internal/adapters/     ecosystem adapters
internal/core/         scan orchestration
internal/files/        file loading and classification
internal/preprocess/   normalization and decode candidates
internal/scanners/     scanner primitives
internal/rules/        rule schema, loading, compile
internal/matcher/      condition evaluation
internal/model/        canonical data models
rules/builtin/         built-in rules
rules/custom/          local custom rules
testdata/samples/      sample packages for tests
```

## Requirements

- Go 1.26 or later
- Unpacked package directory as scan input

## Build

```bash
go build ./cmd/scanner
```

Run the built binary:

```bash
./scanner -h
./scanner scan --path ./testdata/samples/npm-basic --rules-dir ./rules
```

If your environment restricts the default Go cache path, use a local cache:

```bash
mkdir -p .cache/go-build .cache/go-mod
GOCACHE=$(pwd)/.cache/go-build GOMODCACHE=$(pwd)/.cache/go-mod go build ./cmd/scanner
```

## Usage

### Scan a package

```bash
go run ./cmd/scanner scan --path ./testdata/samples/npm-basic --rules-dir ./rules
```

or, after build:

```bash
./scanner scan --path ./testdata/samples/npm-basic --rules-dir ./rules
```

Help:

```bash
go run ./cmd/scanner -h
go run ./cmd/scanner scan -h
go run ./cmd/scanner rules -h
```

Optional flags:

- `--ecosystem npm|pypi`: force adapter selection
- `--format json|sarif`: choose output format
- `--include-artifacts`: include internal artifacts in JSON output
- `--rules-dir ./rules`: change rule root directory
- `--baseline ./baseline.json`: suppress findings that match a baseline file
- `--write-baseline ./baseline.json`: write current findings to a baseline file

### Validate rules

```bash
go run ./cmd/scanner rules validate --rules-dir ./rules
```

### List rules

```bash
go run ./cmd/scanner rules list --rules-dir ./rules
```

## Output

The scanner supports `json` and `sarif` output.

JSON output has this top-level structure:

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

`artifacts` is omitted unless `--include-artifacts` is enabled.

`summary` also includes:

- `risk_score`
- `risk_level`
- `suppressed_findings`

Example SARIF output:

```bash
./scanner scan --path ./testdata/samples/npm-basic --rules-dir ./rules --format sarif
```

Baseline workflow:

```bash
./scanner scan --path ./testdata/samples/npm-basic --rules-dir ./rules --write-baseline ./baseline.json
./scanner scan --path ./testdata/samples/npm-basic --rules-dir ./rules --baseline ./baseline.json
```

`risk_score` is clamped to `0..100`.
`risk_level` is one of `SAFE`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`.

## Built-in Scanners

- `lifecycle_hook`: extracts lifecycle hooks from package metadata
- `entropy`: reports high-entropy tokens in text files
- `hash`: records per-file SHA-256 hashes
- `hash_ioc`: matches file hashes against a built-in IOC set
- `dependency_ioc`: matches dependencies against a built-in IOC list
- `typosquat`: checks dependency names against common packages
- `obfuscation`: detects obfuscation indicators outside minified JS
- `ai_config`: detects prompt-injection style AI config files
- `intent_dataflow`: detects source-sink intent coherence and cross-file flow lite
- `js_ast`: parses JavaScript AST for eval, exec, credential access, droppers, and prototype hooks
- `python`: scans Python source and packaging files for exec, credentials, network, setup, and remote requirements

## Built-in Rules

Current built-in rules are stored in [rules/builtin](./rules/builtin).

Current coverage includes:

- npm lifecycle script abuse
- dangerous shell patterns
- JavaScript AST signals
- Python behavior and packaging signals
- AI config injection
- obfuscation
- intent coherence and inter-module dataflow lite
- typosquat detection
- entropy and IOC-assisted findings

## Rule Files

Rules are defined in YAML and loaded from:

- [rules/builtin](./rules/builtin)
- [rules/custom](./rules/custom)

Current rule model supports:

- `metadata`
- `scope`
- `selectors`
- `conditions`
- `emit`

Supported scopes:

- `file`
- `manifest`
- `package`

Current matcher set includes:

- `contains`
- `regex`
- `field_exists`
- `field_equals`
- `manifest_key_exists`
- `manifest_value_equals`
- `path_matches`
- `scanner_signal_exists`
- `artifact_match`
- logical nodes `all_of`, `any_of`, `not`

## Tests

```bash
mkdir -p .cache/go-build .cache/go-mod
GOCACHE=$(pwd)/.cache/go-build GOMODCACHE=$(pwd)/.cache/go-mod go test ./...
```

## Status

This is still a foundation implementation, but it now includes AST-based JavaScript scanning, Python AST-assisted scanning, deobfuscation preprocessing, AI config scanning, typosquat detection, lightweight intra/inter-file dataflow, heuristic risk scoring, SARIF output, and baseline-driven suppression. It is still not a full Semgrep- or CodeQL-class engine: deeper alias analysis, precise call graph resolution, stronger taint tracking, more ecosystems, and richer prioritization remain future work.

## Not Yet Implemented

- Precise alias analysis and stronger taint propagation for JavaScript and Python
- More complete call graph resolution across files and modules
- More accurate inter-procedural and class/object method dataflow
- Additional ecosystems beyond npm and PyPI
- Richer matcher types beyond the current regex / field / scanner-assisted set
- Richer scoring and prioritization layer
- Large curated intelligence datasets are intentionally out of scope here unless explicitly added
