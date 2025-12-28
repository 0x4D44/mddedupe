#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "Usage: $0 <rustc> [args...]" >&2
  exit 1
fi

real_rustc="$1"
shift

out_dir=""
args=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --out-dir)
      out_dir="$2"
      args+=("$1" "$2")
      shift 2
      ;;
    --out-dir=*)
      out_dir="${1#--out-dir=}"
      args+=("$1")
      shift
      ;;
    *)
      args+=("$1")
      shift
      ;;
  esac
done

# Force rustc temp files into the final output directory so rename() stays within a single directory,
# avoiding EXDEV errors on filesystems that disallow cross-directory renames.
if [[ -n "$out_dir" ]]; then
  export TMPDIR="$out_dir"
fi

exec "$real_rustc" "${args[@]}"
