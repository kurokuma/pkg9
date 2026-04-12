# Malicious Package Scanner

A rule-driven package scanner for unpacked npm, PyPI, and Go module packages.

This project is an extensible scanning foundation rather than a one-off checker. It analyzes package metadata, manifests, files, preprocessing artifacts, and scanner signals, then emits deterministic JSON findings.

Japanese README: [README.ja.md](./README.ja.md)

## Current Scope

- CLI-based scanner
- npm, PyPI, and Go module adapters
- YAML rule loading, validation, and execution
- File, manifest, and package scopes
- Structured JSON output for findings, warnings, errors, and optional artifacts
- JSON and SARIF output
- Built-in and custom rule directories
- Deobfuscation preprocessing
- AST-based JavaScript scanning
- AST-based and packaging-aware Python scanning
- AST-assisted intent and inter-module dataflow
- Browser-focused wallet and credential theft scanning
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

- `--ecosystem npm|pypi|gomod`: force adapter selection
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
- `priority`
- `risk_factors`

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
- `intent_dataflow`: tracks source-sink coherence, alias propagation, function assignments, wrapper methods, imported aliases, and local cross-file call edges
- `js_ast`: parses JavaScript AST for eval, exec, credential access, droppers, and prototype hooks
- `browser`: detects browser wallet tampering and browser credential theft with exfiltration-aware heuristics
- `python`: scans Python source and packaging files for exec, credentials, network, setup, and remote requirements

## Built-in Rules

Current built-in rules are stored in [rules/builtin](./rules/builtin).

You can print the exact loaded rule IDs with:

```bash
./scanner rules list --rules-dir ./rules
```

Built-in rule families:

- `ai_config.*`: `ai_config.compound_injection`
- `ast.*`: `ast.binary_dropper`, `ast.credential_access`, `ast.dangerous_exec`, `ast.prototype_hook`
- `browser.*`: `browser.credential_theft`, `browser.wallet_tampering`
- `dataflow.*`: `dataflow.inter_module`
- `dependency.*`: `dependency.typosquat_detected`
- `hash.*`: `hash.ioc_match`
- `intent.*`: `intent.coherence`
- `obfuscation.*`: `obfuscation.detected`
- `package.*`: lifecycle script, dependency URL, and install-time behavior rules
- `pkg.*`: package-level entropy, install hook, and dependency IOC summary rules
- `python.*`: Python exec, credential, network, surveillance, anti-analysis, and setup rules
- `shell.*`: shell execution, exfiltration, reverse shell, and destructive command rules
- `source.*`: source-level credential, exfiltration, persistence, staging, and anti-analysis rules

Current coverage includes:

- npm lifecycle script abuse
- granular lifecycle token / credential access patterns
- dangerous shell patterns, exfiltration, reverse shell, and destructive shell variants
- dynamic require/import, require.cache poisoning, env proxy interception, sandbox checks
- staged decode/eval and binary-payload style source patterns
- Telegram, Slack, and Google Analytics exfiltration patterns
- iframe keylogging, SSH authorized_keys persistence, Electron app.asar tampering, and socket-based C2 patterns
- install-time global package installation, localhost websocket daemon persistence, Solana dead-drop C2, and header-keyed payload execution
- signal-backed browser wallet tampering and browser credential theft findings
- JavaScript AST signals
- Python behavior and packaging signals
- Python Discord webhook, Gmail SMTP surveillance, and Startup persistence patterns
- Python anti-analysis patterns targeting tracer, debugger, uptime, and analyst tooling checks
- AI config injection
- obfuscation
- intent coherence and inter-module dataflow lite
- typosquat detection
- entropy and IOC-assisted findings

Recent precision tuning includes:

- URL dependency matching is limited to dependency sections rather than repository or homepage metadata
- `require.cache` findings focus on mutation or deletion rather than read-only inspection
- socket C2 detection avoids broad minified `io()` style matches
- intent/dataflow source detection prefers secret-like env and credential material over generic `process.env` usage

## Risk Evaluation

`risk_score` is a clamped `0..100` aggregate score.

Current score inputs:

- Finding severities:
  - `critical` `+30`
  - `high` `+18`
  - `medium` `+10`
  - `low` `+4`
  - `info` `+1`
- Package-level bonuses:
  - install hook `+8`
  - build hook `+3`
  - `intent_coherence` signal `+15`
  - `inter_module_dataflow` signal `+15`
  - `obfuscation_detected` signal `+8`
  - `ai_config_injection` signal `+10`
  - `ast_dangerous_exec` signal `+8`
  - `python_exec_behavior` signal `+8`
  - `typosquat_detected` signal `+6`

`risk_level` thresholds:

- `SAFE`: `0`
- `LOW`: `1..24`
- `MEDIUM`: `25..49`
- `HIGH`: `50..74`
- `CRITICAL`: `75..100`

`priority` thresholds:

- `P1`: score `>= 85`, or cross-file dataflow, or install hook plus dangerous exec
- `P2`: score `>= 60`, or obfuscation, or credential-to-sink behavior
- `P3`: score `>= 30`, or at least two findings
- `P4`: score `>= 1`
- `P5`: score `0`

`risk_factors` currently include:

- `install_hook_with_exec`
- `credential_to_sink`
- `cross_file_dataflow`
- `obfuscation`
- `ai_config_injection`
- `typosquat`
- `critical_finding`
- `high_severity_finding`

## Evaluation Guide

Recommended evaluation viewpoints:

- Detection coverage: whether clearly malicious packages avoid `SAFE`
- False positives: how often benign packages are raised above `SAFE`
- Explainability: whether a finding can be traced to a concrete file, rule, and signal
- Prioritization quality: whether `risk_score`, `risk_level`, and `priority` match analyst intuition
- Stability: whether reruns on the same input stay deterministic

Suggested scorecard:

| Area | 1 | 3 | 5 |
| --- | --- | --- | --- |
| Detection coverage | misses obvious malware | catches some malware families | consistently catches clearly malicious packages |
| False positives | benign packages often score `MEDIUM+` | mixed benign results | most benign packages stay `SAFE/LOW` |
| Explainability | findings are hard to trace | partial traceability | rule, signal, and file path are usually clear |
| Prioritization | score does not match severity | partly useful | score and priority are operationally useful |
| Extensibility | rule/scanner changes are brittle | moderate effort | new rules and scanners fit cleanly |

## Next Steps For A More Advanced Scanner

- Move JS and Python taint analysis closer to SSA/CFG-based flow tracking
- Improve inter-procedural and cross-file call graph resolution
- Add richer browser-focused scanners for wallet tampering, cookie theft, and credential store abuse
- Reduce package-level AST findings that currently lack file-level command context
- Add evaluation fixtures that continuously compare malicious and benign corpora over time

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
- `field_matches`
- `field_in`
- `manifest_key_exists`
- `manifest_value_equals`
- `path_matches`
- `scanner_signal_exists`
- `signal_count_at_least`
- `artifact_match`
- `artifact_field_equals`
- logical nodes `all_of`, `any_of`, `not`

## Tests

```bash
mkdir -p .cache/go-build .cache/go-mod
GOCACHE=$(pwd)/.cache/go-build GOMODCACHE=$(pwd)/.cache/go-mod go test ./...
```

## Status

This is still a foundation implementation, but it now includes AST-based JavaScript scanning, Python AST-assisted scanning, dedicated browser wallet/credential theft scanning, deobfuscation preprocessing, AI config scanning, typosquat detection, multi-ecosystem package parsing, richer matcher primitives, baseline-driven suppression, stronger alias/property-aware intra/inter-file dataflow, and a prioritization layer on top of risk scoring.

## Current Limitations

- The JavaScript and Python dataflow engines now track local aliases, reassignment, function assignments, object/dict property flow, wrapper methods, imported function aliases, and simple call edges, but they are still heuristic rather than SSA/CFG-complete.
- Cross-file resolution covers import graphs, imported wrappers, and local call edges, but not every dynamic import, reflection, or runtime-generated dispatch pattern.
- Large curated IOC or threat-intel datasets remain intentionally out of scope unless explicitly added.
