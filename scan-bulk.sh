#!/usr/bin/env bash

set -euo pipefail

usage() {
  cat <<'EOF'
Usage: ./scan-bulk.sh [options] <root-dir>

Scan each unpacked package directory directly under <root-dir>.
For each directory, scan its `package/` subdirectory and write the scanner JSON to `<folder_name>.json`.

Options:
  --rules-dir <dir>     Rules root directory. Default: ./rules
  --ecosystem <name>    Optional ecosystem override passed to the scanner
  --baseline <file>     Optional baseline file passed to the scanner
  --include-artifacts   Include artifacts in each scan result
  --out-dir <dir>       Output directory for JSON files. Default: current directory
  --scanner <command>   Scanner command to use. Default: ./scanner if present, otherwise "go run ./cmd/scanner"
  -h, --help            Show this help
EOF
}

if [[ $# -eq 0 ]]; then
  usage
  exit 1
fi

rules_dir="./rules"
ecosystem=""
baseline=""
include_artifacts=0
out_dir="."
scanner_cmd=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --rules-dir)
      rules_dir=$2
      shift 2
      ;;
    --ecosystem)
      ecosystem=$2
      shift 2
      ;;
    --baseline)
      baseline=$2
      shift 2
      ;;
    --include-artifacts)
      include_artifacts=1
      shift
      ;;
    --out-dir)
      out_dir=$2
      shift 2
      ;;
    --scanner)
      scanner_cmd=$2
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    --)
      shift
      break
      ;;
    -*)
      echo "unknown option: $1" >&2
      exit 1
      ;;
    *)
      break
      ;;
  esac
done

if [[ $# -ne 1 ]]; then
  usage
  exit 1
fi

root_dir=$1
if [[ ! -d "$root_dir" ]]; then
  echo "root directory not found: $root_dir" >&2
  exit 1
fi
mkdir -p "$out_dir"

if [[ -z "$scanner_cmd" ]]; then
  if [[ -x "./scanner" ]]; then
    scanner_cmd="./scanner"
  else
    scanner_cmd="go run ./cmd/scanner"
  fi
fi

while IFS= read -r pkg_dir; do
  folder_name=$(basename "$pkg_dir")
  scan_path="$pkg_dir/package"
  if [[ ! -d "$scan_path" ]]; then
    echo "SKIP $folder_name: package directory not found at $scan_path" >&2
    continue
  fi
  abs_path=$(cd "$scan_path" && pwd)
  output_path="$out_dir/${folder_name}.json"

  cmd=("$scanner_cmd" scan --path "$abs_path" --rules-dir "$rules_dir" --format json)
  if [[ -n "$ecosystem" ]]; then
    cmd+=(--ecosystem "$ecosystem")
  fi
  if [[ -n "$baseline" ]]; then
    cmd+=(--baseline "$baseline")
  fi
  if [[ "$include_artifacts" -eq 1 ]]; then
    cmd+=(--include-artifacts)
  fi

  if [[ "$scanner_cmd" == "go run ./cmd/scanner" ]]; then
    cmd=(go run ./cmd/scanner "${cmd[@]:1}")
  fi

  echo "SCAN $folder_name -> $output_path" >&2
  "${cmd[@]}" > "$output_path"
done < <(find "$root_dir" -mindepth 1 -maxdepth 1 -type d | sort)
