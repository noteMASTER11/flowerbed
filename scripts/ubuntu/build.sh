#!/usr/bin/env bash
set -Eeuo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
# shellcheck source=lib/common.sh
source "$script_dir/lib/common.sh"

dry_run=false
jobs=8
workspace=""

while (($#)); do
  case "$1" in
    --dry-run)
      dry_run=true
      shift
      ;;
    --jobs)
      [[ $# -ge 2 ]] || die "--jobs requires a value"
      jobs="$2"
      shift 2
      ;;
    -*)
      die "Unknown option: $1"
      ;;
    *)
      [[ -z "$workspace" ]] || die "Only one workspace may be supplied"
      workspace="$1"
      shift
      ;;
  esac
done

[[ "$jobs" =~ ^[1-9][0-9]*$ ]] || die "Jobs must be a positive integer"
workspace="${workspace:-${HOME}/android/lineage-23.2}"

if [[ "$dry_run" == true ]]; then
  printf 'DRY-RUN cd %q\n' "$workspace"
  printf 'DRY-RUN export USE_CCACHE=1 CCACHE_EXEC=$(command -v ccache) BUILD_USERNAME=flowerbed BUILD_HOSTNAME=wsl2-builder\n'
  printf 'DRY-RUN ccache -M 100G\n'
  printf 'DRY-RUN ccache -z\n'
  printf 'DRY-RUN source build/envsetup.sh\n'
  printf 'DRY-RUN breakfast fleur\n'
  printf 'DRY-RUN m bacon -j%s\n' "$jobs"
  exit 0
fi

repo_root="$(resolve_repo_root)"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
log_file="$repo_root/logs/build-$timestamp.log"
metadata_file="$repo_root/logs/build-$timestamp.json"

require_ext4_workspace "$workspace"
require_command ccache
require_command python3
require_command tee
[[ -f "$workspace/build/envsetup.sh" ]] || die "Missing build/envsetup.sh in $workspace"
[[ -d "$workspace/device/xiaomi/fleur" ]] || die "Missing device/xiaomi/fleur"
[[ -d "$workspace/vendor/xiaomi/fleur" ]] || die "Missing vendor/xiaomi/fleur"
[[ -d "$workspace/kernel/xiaomi/mt6781" ]] || die "Missing kernel/xiaomi/mt6781"
mkdir -p "$repo_root/logs"

start_utc="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
start_epoch="$(date +%s)"

run_build() {
  cd "$workspace"
  export USE_CCACHE=1
  export CCACHE_EXEC
  CCACHE_EXEC="$(command -v ccache)"
  export BUILD_USERNAME=flowerbed
  export BUILD_HOSTNAME=wsl2-builder
  ccache -M 100G
  ccache -z
  # shellcheck disable=SC1091
  source build/envsetup.sh
  breakfast fleur
  m bacon "-j$jobs"
}

set +e
run_build 2>&1 | tee "$log_file"
status=${PIPESTATUS[0]}
set -e

end_utc="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
end_epoch="$(date +%s)"
elapsed_seconds=$((end_epoch - start_epoch))
ccache -s 2>&1 | tee -a "$log_file"

python3 - "$metadata_file" "$start_utc" "$end_utc" "$elapsed_seconds" "$jobs" "$status" <<'PY'
import json
from pathlib import Path
import platform
import sys
import tempfile

path = Path(sys.argv[1])
payload = {
    "startUtc": sys.argv[2],
    "endUtc": sys.argv[3],
    "elapsedSeconds": int(sys.argv[4]),
    "jobs": int(sys.argv[5]),
    "exitCode": int(sys.argv[6]),
    "kernel": platform.release(),
}
with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=path.parent, delete=False) as handle:
    json.dump(payload, handle, indent=2, sort_keys=True)
    handle.write("\n")
    temporary = Path(handle.name)
temporary.replace(path)
PY

log "Build exit code: $status"
log "Build log: $log_file"
log "Build metadata: $metadata_file"
exit "$status"
