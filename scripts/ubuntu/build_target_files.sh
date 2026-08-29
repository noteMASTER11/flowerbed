#!/usr/bin/env bash
set -Eeuo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
# shellcheck source=lib/common.sh
source "$script_dir/lib/common.sh"

dry_run=false
verbose=false
jobs=8
workspace=""

while (($#)); do
  case "$1" in
    --dry-run)
      dry_run=true
      shift
      ;;
    --verbose)
      verbose=true
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
  # The dry-run must print, not execute, this substitution.
  # shellcheck disable=SC2016
  printf 'DRY-RUN export USE_CCACHE=1 CCACHE_EXEC=$(command -v ccache) BUILD_USERNAME=flowerbed BUILD_HOSTNAME=wsl2-builder\n'
  printf 'DRY-RUN ccache -M 100G\n'
  printf 'DRY-RUN ccache -z\n'
  printf 'DRY-RUN source build/envsetup.sh\n'
  printf 'DRY-RUN breakfast fleur\n'
  if [[ "$verbose" == true ]]; then
    printf 'DRY-RUN export SOONG_UI_NINJA_ARGS=-v\n'
  fi
  printf 'DRY-RUN python3 scripts/ubuntu/build_provenance.py pre-build --kernel-root %q/kernel/xiaomi/mt6781 --kernel-policy sources/kernel-fix.json --patch patches/android_kernel_xiaomi_mt6781/0001-mdpm-cfi-function-pointer-signature.patch --application-script scripts/ubuntu/apply_patches.sh\n' "$workspace"
  printf 'DRY-RUN m target-files-package otatools -j%s\n' "$jobs"
  printf 'DRY-RUN python3 scripts/ubuntu/build_provenance.py finalize --unsigned-target-files %q/out/target/product/fleur/obj/PACKAGING/target_files_intermediates/lineage_fleur-target_files.zip --kernel-root %q/kernel/xiaomi/mt6781 --kernel-policy sources/kernel-fix.json --patch patches/android_kernel_xiaomi_mt6781/0001-mdpm-cfi-function-pointer-signature.patch --application-script scripts/ubuntu/apply_patches.sh\n' "$workspace" "$workspace"
  exit 0
fi

repo_root="$(resolve_repo_root)"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
nonce="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
run_id="$timestamp-$nonce"
log_file="$repo_root/logs/target-files-$run_id.log"
metadata_file="$repo_root/logs/target-files-$run_id.json"
pre_provenance="$repo_root/logs/target-files-$run_id.pre-build-provenance.json"
final_provenance="$repo_root/logs/target-files-$run_id.build-provenance.json"
manifest_snapshot="$repo_root/manifests/snapshots/$run_id.xml"
runtime_dir="$repo_root/.cache/target-files-$run_id"
before_snapshot="$runtime_dir/target-files-before.json"
after_snapshot="$runtime_dir/target-files-after.json"
memory_snapshot="$runtime_dir/memory-and-swap.txt"
disk_snapshot="$runtime_dir/disk.txt"
ccache_snapshot="$runtime_dir/ccache.txt"
target_files="$workspace/out/target/product/fleur/obj/PACKAGING/target_files_intermediates/lineage_fleur-target_files.zip"
target_files_relative="out/target/product/fleur/obj/PACKAGING/target_files_intermediates/lineage_fleur-target_files.zip"
backup_target_files="$target_files.pre-run-$run_id"
kernel_root="$workspace/kernel/xiaomi/mt6781"
kernel_policy="$repo_root/sources/kernel-fix.json"
kernel_patch="$repo_root/patches/android_kernel_xiaomi_mt6781/0001-mdpm-cfi-function-pointer-signature.patch"
application_script="$repo_root/scripts/ubuntu/apply_patches.sh"

require_ext4_workspace "$workspace"
require_command ccache
require_command python3
require_command repo
require_command tee
require_command free
require_command df
[[ -f "$workspace/build/envsetup.sh" ]] || die "Missing build/envsetup.sh in $workspace"
[[ -d "$workspace/device/xiaomi/fleur" ]] || die "Missing device/xiaomi/fleur"
[[ -d "$workspace/vendor/xiaomi/fleur" ]] || die "Missing vendor/xiaomi/fleur"
[[ -d "$kernel_root" ]] || die "Missing kernel/xiaomi/mt6781"
[[ -f "$kernel_policy" ]] || die "Missing kernel policy: $kernel_policy"
[[ -f "$kernel_patch" ]] || die "Missing kernel patch: $kernel_patch"
[[ -f "$application_script" ]] || die "Missing patch application script: $application_script"
[[ ! -e "$pre_provenance" ]] || die "pre-build provenance output already exists"
[[ ! -e "$final_provenance" ]] || die "final build provenance output already exists"
mkdir -p "$repo_root/logs" "$repo_root/manifests/snapshots" "$runtime_dir"

preserve_existing_target_files() {
  local target="$1" backup="$2" output="$3"
  python3 - "$target" "$backup" "$output" <<'PY'
import hashlib
import json
from pathlib import Path
import stat
import sys

target = Path(sys.argv[1])
backup = Path(sys.argv[2])
output = Path(sys.argv[3])
if target.exists() or target.is_symlink():
    metadata = target.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise SystemExit("target-files output is not a regular non-symlink file")
    if backup.exists() or backup.is_symlink():
        raise SystemExit("target-files pre-run backup already exists")
    digest = hashlib.sha256()
    with target.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    record = {
        "exists": True,
        "sha256": digest.hexdigest(),
        "device": metadata.st_dev,
        "inode": metadata.st_ino,
        "size": metadata.st_size,
        "mtimeNs": metadata.st_mtime_ns,
        "ctimeNs": metadata.st_ctime_ns,
        "backup": str(backup),
    }
    target.replace(backup)
else:
    record = {"exists": False}
output.write_text(json.dumps(record, sort_keys=True) + "\n", encoding="utf-8")
PY
}

require_refreshed_target_files() {
  local before="$1" target="$2" output="$3" start_ns="$4" log="$5" expected_path="$6"
  python3 - "$before" "$target" "$output" "$start_ns" "$log" "$expected_path" <<'PY'
import hashlib
import json
from pathlib import Path
import stat
import sys
import zipfile

before = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
target = Path(sys.argv[2])
output = Path(sys.argv[3])
start_ns = int(sys.argv[4])
log = Path(sys.argv[5])
expected_path = sys.argv[6]
try:
    metadata = target.lstat()
except OSError as error:
    raise SystemExit("target-files output is missing after successful build") from error
if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
    raise SystemExit("target-files output is not a regular non-symlink file")
after = {
    "exists": True,
    "device": metadata.st_dev,
    "inode": metadata.st_ino,
    "size": metadata.st_size,
    "mtimeNs": metadata.st_mtime_ns,
    "ctimeNs": metadata.st_ctime_ns,
}
if after["mtimeNs"] < start_ns or after["ctimeNs"] < start_ns:
    raise SystemExit("target-files output predates this build")
try:
    with zipfile.ZipFile(target) as archive:
        if archive.testzip() is not None:
            raise SystemExit("target-files output is not a valid ZIP")
        if archive.namelist().count("IMAGES/boot.img") != 1:
            raise SystemExit("target-files output must contain exactly one boot image")
except zipfile.BadZipFile as error:
    raise SystemExit("target-files output is not a valid ZIP") from error
if f"Packaging target files: {expected_path}" not in log.read_text(encoding="utf-8"):
    raise SystemExit("target-files packaging proof is missing from build log")
digest = hashlib.sha256()
with target.open("rb") as source:
    for chunk in iter(lambda: source.read(1024 * 1024), b""):
        digest.update(chunk)
after["sha256"] = digest.hexdigest()
output.write_text(json.dumps(after, sort_keys=True) + "\n", encoding="utf-8")
PY
}

write_metadata() {
  local status="$1" start_utc="$2" end_utc="$3" elapsed_seconds="$4"
  python3 - "$metadata_file" "$status" "$start_utc" "$end_utc" "$elapsed_seconds" \
    "$jobs" "$target_files" "$after_snapshot" "$manifest_snapshot" "$memory_snapshot" \
    "$disk_snapshot" "$ccache_snapshot" "$log_file" "$pre_provenance" "$final_provenance" <<'PY'
import json
from pathlib import Path
import platform
import sys
import tempfile

(
    destination, status, start, end, elapsed, jobs, target, target_record,
    manifest, memory, disk, ccache, log, pre, final,
) = sys.argv[1:]
target_value = None
record_path = Path(target_record)
if record_path.is_file():
    target_value = {"path": target, **json.loads(record_path.read_text(encoding="utf-8"))}
path = Path(destination)
payload = {
    "startUtc": start,
    "endUtc": end,
    "elapsedSeconds": int(elapsed),
    "jobs": int(jobs),
    "exitCode": int(status),
    "kernel": platform.release(),
    "targetFiles": target_value,
    "manifestSnapshot": manifest,
    "memoryAndSwap": memory,
    "disk": disk,
    "ccache": ccache,
    "log": log,
    "metadata": str(path),
    "preBuildProvenance": pre,
    "buildProvenance": final,
}
with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=path.parent, delete=False) as handle:
    json.dump(payload, handle, indent=2, sort_keys=True)
    handle.write("\n")
    temporary = Path(handle.name)
temporary.replace(path)
PY
}

preserve_existing_target_files "$target_files" "$backup_target_files" "$before_snapshot"
start_utc="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
start_epoch="$(date +%s)"
start_ns="$(date +%s%N)"

run_build() {
  cd "$workspace"
  export USE_CCACHE=1
  export CCACHE_EXEC
  CCACHE_EXEC="$(command -v ccache)"
  export BUILD_USERNAME=flowerbed
  export BUILD_HOSTNAME=wsl2-builder
  ccache -M 100G
  ccache -z
  set +u
  # shellcheck disable=SC1091
  source build/envsetup.sh
  breakfast fleur
  if [[ "$verbose" == true ]]; then
    export SOONG_UI_NINJA_ARGS=-v
  else
    unset SOONG_UI_NINJA_ARGS
  fi
  python3 "$script_dir/build_provenance.py" pre-build \
    --kernel-root "$kernel_root" \
    --kernel-policy "$kernel_policy" \
    --patch "$kernel_patch" \
    --application-script "$application_script" \
    --timestamp "$start_utc" \
    --session-nonce "$nonce" \
    --output "$pre_provenance"
  m target-files-package otatools "-j$jobs"
}

set +e
(
  set -Eeuo pipefail
  run_build
) > >(tee "$log_file") 2>&1
status=$?
set -e

if [[ "$status" -eq 0 ]]; then
  if ! require_refreshed_target_files "$before_snapshot" "$target_files" "$after_snapshot" "$start_ns" "$log_file" "$target_files_relative"; then
    status=1
  fi
fi

if [[ "$status" -eq 0 ]] && ! (
  cd "$workspace"
  repo manifest -r
) >"$manifest_snapshot"; then
  log "Unable to create resolved manifest snapshot" | tee -a "$log_file"
  status=1
fi
if [[ "$status" -eq 0 ]]; then
  free -h >"$memory_snapshot"
  df -h "$workspace" >"$disk_snapshot"
  ccache -s >"$ccache_snapshot"
  cat "$memory_snapshot" "$disk_snapshot" "$ccache_snapshot" >>"$log_file"
fi

end_utc="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
end_epoch="$(date +%s)"
elapsed_seconds=$((end_epoch - start_epoch))
write_metadata "$status" "$start_utc" "$end_utc" "$elapsed_seconds"

if [[ "$status" -eq 0 ]] && ! python3 "$script_dir/build_provenance.py" finalize \
  --pre-build "$pre_provenance" \
  --unsigned-target-files "$target_files" \
  --kernel-root "$kernel_root" \
  --kernel-policy "$kernel_policy" \
  --patch "$kernel_patch" \
  --application-script "$application_script" \
  --output "$final_provenance" 2>&1 | tee -a "$log_file"; then
  status=1
  write_metadata "$status" "$start_utc" "$end_utc" "$elapsed_seconds"
fi

log "Target-files build exit code: $status"
log "Target-files build log: $log_file"
log "Target-files build metadata: $metadata_file"
log "Target-files build provenance: $final_provenance"
exit "$status"
