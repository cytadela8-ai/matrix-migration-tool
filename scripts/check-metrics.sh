#!/usr/bin/env bash
set -euo pipefail

# Analyze Rust syntax, including error-propagation branches, with rust-code-analysis 0.0.25.
metrics_dir=$(mktemp -d)
rust-code-analysis-cli -m -p src -p tests -p tests/support/mod.rs -O json -o "$metrics_dir"
shopt -s globstar nullglob
metrics_files=("$metrics_dir"/**/*.json)
violations=$(
  jq -s '
    [.[] | .. | objects | select(.kind? == "function" or .kind? == "closure") |
      select(.metrics.cyclomatic.max > 8 or (.end_line - .start_line + 1) > 100 or
        .metrics.nargs.functions_max > 5) |
      {name, start_line, end_line, complexity: .metrics.cyclomatic.max}] |
      if length > 0 then . else empty end' "${metrics_files[@]}"
)
if [[ -n "$violations" ]]; then
  echo "$violations"
  exit 1
fi
awk 'length($0) > 100 {print FILENAME ":" FNR ": exceeds 100 columns"; failed=1}
  END {exit failed}' src/*.rs tests/*.rs tests/support/*.rs
