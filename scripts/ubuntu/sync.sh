#!/usr/bin/env bash
set -Eeuo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
# shellcheck source=lib/common.sh
source "$script_dir/lib/common.sh"

mode="sync"
case "${1:-}" in
  --dry-run)
    mode="dry-run"
    shift
    ;;
  --validate-workspace)
    mode="validate"
    shift
    ;;
esac

workspace="${1:-${HOME}/android/lineage-23.2}"
[[ $# -le 1 ]] || die "Usage: $0 [--dry-run|--validate-workspace] [workspace]"

repo_root="$(resolve_repo_root)"
manifest_name="fleur-lineage-23.2.xml"
manifest_source="$repo_root/manifests/$manifest_name"
local_manifest="$workspace/.repo/local_manifests/$manifest_name"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
snapshot="$repo_root/manifests/snapshots/$timestamp.xml"
log_file="$repo_root/logs/sync-$timestamp.log"

if [[ "$mode" == "dry-run" ]]; then
  printf 'DRY-RUN mkdir -p %q\n' "$workspace"
  printf 'DRY-RUN cd %q\n' "$workspace"
  printf 'DRY-RUN repo init -u https://github.com/LineageOS/android.git -b lineage-23.2 --git-lfs --no-clone-bundle\n'
  printf 'DRY-RUN install -m 0644 %q %q\n' "$manifest_source" "$local_manifest"
  printf 'DRY-RUN repo sync --progress -c --force-sync --optimized-fetch --prune --no-tags -j8\n'
  printf 'DRY-RUN verify pinned project revisions from %q\n' "$manifest_source"
  printf 'DRY-RUN repo manifest -r > %q\n' "$snapshot"
  exit 0
fi

if [[ "$mode" == "validate" ]]; then
  require_ext4_workspace "$workspace"
  exit 0
fi

require_command repo
require_command git
require_command git-lfs
require_command python3
require_command tee
[[ -f "$manifest_source" ]] || die "Missing local manifest: $manifest_source"

mkdir -p "$workspace"
require_ext4_workspace "$workspace"
mkdir -p "$workspace/.repo/local_manifests" "$repo_root/manifests/snapshots" "$repo_root/logs"

run_sync() {
  cd "$workspace"
  install -m 0644 "$manifest_source" "$local_manifest"
  repo init \
    -u https://github.com/LineageOS/android.git \
    -b lineage-23.2 \
    --git-lfs \
    --no-clone-bundle
  repo sync --progress -c --force-sync --optimized-fetch --prune --no-tags -j8

  while IFS=$'\t' read -r project_path revision; do
    actual="$(git -C "$workspace/$project_path" rev-parse HEAD)"
    [[ "$actual" == "$revision" ]] || \
      die "Revision mismatch for $project_path: expected $revision, found $actual"
  done < <(
    python3 - "$manifest_source" <<'PY'
import sys
import xml.etree.ElementTree as ET

for project in ET.parse(sys.argv[1]).getroot().findall("project"):
    print(f"{project.attrib['path']}\t{project.attrib['revision']}")
PY
  )

  temporary_snapshot="${snapshot}.tmp"
  repo manifest -r >"$temporary_snapshot"
  mv -f -- "$temporary_snapshot" "$snapshot"
  log "Pinned snapshot: $snapshot"
}

run_sync 2>&1 | tee "$log_file"
