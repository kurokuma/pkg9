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
- Built-in and custom rule directories
- Basic preprocessing and scanner primitives

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

Optional flags:

- `--ecosystem npm|pypi`: force adapter selection
- `--include-artifacts`: include internal artifacts in JSON output
- `--rules-dir ./rules`: change rule root directory

### Validate rules

```bash
go run ./cmd/scanner rules validate --rules-dir ./rules
```

### List rules

```bash
go run ./cmd/scanner rules list --rules-dir ./rules
```

## Output

The scanner emits JSON with this top-level structure:

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

## Built-in Scanners

- `lifecycle_hook`: extracts lifecycle hooks from package metadata
- `entropy`: reports high-entropy tokens in text files
- `hash`: records per-file SHA-256 hashes
- `dependency_ioc`: matches dependencies against a built-in IOC list

## Built-in Rules

Current built-in rules are stored in [rules/builtin](/Users/nanoha/work/pkg9/rules/builtin):

- install lifecycle hook detection for npm packages
- high-entropy token signal detection
- suspicious dependency IOC detection

## Rule Files

Rules are defined in YAML and loaded from:

- [rules/builtin](/Users/nanoha/work/pkg9/rules/builtin)
- [rules/custom](/Users/nanoha/work/pkg9/rules/custom)

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

This is a v1 foundation implementation. It already supports end-to-end scanning, but several design targets in `malicious_package_scanner.md` are still future work, including richer matchers, more ecosystems, cross-file analysis, suppression, scoring, and additional output formats.
