#!/usr/bin/env bash
# Offline, SHA256-verified local secret scanner for a single Git repo or fleet
# directory (such as ~/Projects). Never transmits candidate secrets over the
# network and always enforces --redact=100.
#
# Optional workstation overlay: if ${XDG_CONFIG_HOME:-$HOME/.config}/security-guardrails/local.toml
# exists, its rules are layered on top of .gitleaks.toml so organization-specific
# domain patterns stay strictly local and out of public repositories.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_BASELINE_CONFIG="${SCRIPT_DIR}/../.gitleaks.toml"
PREPARE_SCRIPT="${SCRIPT_DIR}/prepare_gitleaks_config.py"
LOCAL_OVERLAY_CONFIG="${XDG_CONFIG_HOME:-$HOME/.config}/security-guardrails/local.toml"

GITLEAKS_VERSION="8.30.1"
GITLEAKS_SHA256_LINUX_X64="551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb"
GITLEAKS_SHA256_LINUX_ARM64="e4a487ee7ccd7d3a7f7ec08657610aa3606637dab924210b3aee62570fb4b080"

CACHE_DIR="${XDG_CACHE_HOME:-$HOME/.cache}/security-guardrails/gitleaks-${GITLEAKS_VERSION}"
CACHED_BIN="${CACHE_DIR}/gitleaks"

usage() {
  cat <<'EOF'
Usage: scripts/scan_secrets.sh [--fleet] <path>

Options:
  --fleet    Discover and scan every Git repository / worktree under <path>
  -h, --help Show this help message

Examples:
  TARGET_REPO="$HOME/Projects/my_repo__worktrees/main"
  ./scripts/scan_secrets.sh "$TARGET_REPO"

  PROJECTS_DIR="$HOME/Projects"
  ./scripts/scan_secrets.sh --fleet "$PROJECTS_DIR"
EOF
}

ensure_gitleaks() {
  if [[ -x "$CACHED_BIN" ]]; then
    echo "$CACHED_BIN"
    return 0
  fi

  local os arch asset expected_sha256 url tmp_dir
  os="$(uname -s)"
  arch="$(uname -m)"
  if [[ "$os" != "Linux" ]]; then
    echo "ERROR: Automatic verified bootstrap supports Linux (x86_64/aarch64); install gitleaks v${GITLEAKS_VERSION} manually on ${os}." >&2
    exit 2
  fi

  case "$arch" in
    x86_64|amd64)
      asset="gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz"
      expected_sha256="$GITLEAKS_SHA256_LINUX_X64"
      ;;
    aarch64|arm64)
      asset="gitleaks_${GITLEAKS_VERSION}_linux_arm64.tar.gz"
      expected_sha256="$GITLEAKS_SHA256_LINUX_ARM64"
      ;;
    *)
      echo "ERROR: Unsupported CPU architecture: ${arch}" >&2
      exit 2
      ;;
  esac

  url="https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/${asset}"
  tmp_dir="$(mktemp -d)"
  trap 'rm -rf "$tmp_dir"' RETURN

  echo "Bootstrapping SHA256-verified gitleaks v${GITLEAKS_VERSION}..." >&2
  curl --proto '=https' --tlsv1.2 -fsSL "$url" -o "${tmp_dir}/${asset}"
  echo "${expected_sha256}  ${tmp_dir}/${asset}" | sha256sum -c - >&2

  mkdir -p "$CACHE_DIR"
  tar -xzf "${tmp_dir}/${asset}" -C "$tmp_dir" gitleaks
  install -m 0755 "${tmp_dir}/gitleaks" "$CACHED_BIN"
  echo "$CACHED_BIN"
}

scan_single_repo() {
  local gitleaks_bin="$1"
  local repo_path="$2"
  local base_cfg="$REPO_BASELINE_CONFIG"
  local tmp_overlay="" tmp_cfg="" effective_cfg="" rc=0
  local caller_arg=() ignore_args=()

  if [[ -f "$LOCAL_OVERLAY_CONFIG" ]]; then
    tmp_overlay="$(mktemp "${TMPDIR:-/tmp}/overlay-gitleaks.XXXXXX.toml")"
    if ! base_cfg="$(python3 "$PREPARE_SCRIPT" --baseline "$REPO_BASELINE_CONFIG" --caller "$LOCAL_OVERLAY_CONFIG" --output "$tmp_overlay")"; then
      rm -f "$tmp_overlay"
      return 1
    fi
  fi

  tmp_cfg="$(mktemp "${TMPDIR:-/tmp}/effective-gitleaks.XXXXXX.toml")"
  if [[ -f "${repo_path}/.gitleaks.toml" ]]; then
    caller_arg=(--caller "${repo_path}/.gitleaks.toml")
  fi

  if ! effective_cfg="$(python3 "$PREPARE_SCRIPT" --baseline "$base_cfg" "${caller_arg[@]}" --output "$tmp_cfg")"; then
    rm -f "$tmp_overlay" "$tmp_cfg"
    return 1
  fi

  if [[ -f "${repo_path}/.gitleaksignore" ]]; then
    ignore_args=(--gitleaks-ignore-path "${repo_path}/.gitleaksignore")
  fi

  if [[ -e "${repo_path}/.git" ]]; then
    "$gitleaks_bin" git "$repo_path" \
      --config "$effective_cfg" \
      "${ignore_args[@]}" \
      --redact=100 \
      --no-banner \
      --exit-code 1 || rc=1
  fi

  "$gitleaks_bin" dir "$repo_path" \
    --config "$effective_cfg" \
    "${ignore_args[@]}" \
    --redact=100 \
    --no-banner \
    --exit-code 1 || rc=1

  rm -f "$tmp_overlay" "$tmp_cfg"
  return "$rc"
}

FLEET_MODE=0
if [[ $# -eq 0 ]]; then
  usage >&2
  exit 2
fi

while [[ $# -gt 0 ]]; do
  case "$1" in
    --fleet)
      FLEET_MODE=1
      shift
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
      echo "ERROR: Unknown flag: $1" >&2
      usage >&2
      exit 2
      ;;
    *)
      break
      ;;
  esac
done

if [[ $# -ne 1 ]]; then
  usage >&2
  exit 2
fi

TARGET_PATH="$(cd "$1" && pwd)"
GITLEAKS_BIN="$(ensure_gitleaks)"

if [[ "$FLEET_MODE" -eq 0 ]]; then
  echo "Scanning ${TARGET_PATH}..."
  scan_single_repo "$GITLEAKS_BIN" "$TARGET_PATH"
  exit $?
fi

FAILED=0
SCANNED=0
while IFS= read -r -d '' git_marker; do
  repo_dir="$(dirname "$git_marker")"
  SCANNED=$((SCANNED + 1))
  echo "=== [${SCANNED}] ${repo_dir} ==="
  if ! scan_single_repo "$GITLEAKS_BIN" "$repo_dir"; then
    FAILED=$((FAILED + 1))
  fi
done < <(python3 - "$TARGET_PATH" <<'PY'
import os, pathlib, sys
root = pathlib.Path(sys.argv[1])
skip = {"node_modules", ".venv", "venv", "target", "__pycache__", ".cache"}
for dirpath, dirnames, filenames in os.walk(root):
    if ".git" in dirnames or ".git" in filenames:
        sys.stdout.write(os.path.join(dirpath, ".git") + "\0")
        dirnames[:] = []
        continue
    dirnames[:] = [d for d in dirnames if d not in skip and not d.startswith(".")]
PY
)

echo "Fleet scan complete: scanned ${SCANNED} repositories, ${FAILED} with findings."
[[ "$FAILED" -eq 0 ]]
