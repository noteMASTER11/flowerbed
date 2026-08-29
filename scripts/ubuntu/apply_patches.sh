#!/usr/bin/env bash
set -Eeuo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
# shellcheck source=lib/common.sh
source "$script_dir/lib/common.sh"

workspace="${1:-${HOME}/android/lineage-23.2}"
[[ $# -le 1 ]] || die "Usage: $0 [workspace]"

require_command git
require_ext4_workspace "$workspace"

repo_root="$(resolve_repo_root)"
patch_specs=(
  "device/xiaomi/fleur|patches/android_device_xiaomi_fleur/0001-fleur-use-reworked-mediatek-memtrack-module.patch"
  "device/xiaomi/fleur|patches/android_device_xiaomi_fleur/0002-fleur-drop-duplicate-dynamic-sensor-property.patch"
  "device/xiaomi/fleur|patches/android_device_xiaomi_fleur/0003-fleur-drop-duplicate-mali-genfs-labels.patch"
  "device/xiaomi/fleur|patches/android_device_xiaomi_fleur/0004-fleur-drop-duplicate-dynamic-sensor-context.patch"
  "device/xiaomi/fleur|patches/android_device_xiaomi_fleur/0005-fleur-use-common-mediatek-vt-context.patch"
  "device/xiaomi/fleur|patches/android_device_xiaomi_fleur/0006-fleur-expose-sku-market-names.patch"
  "kernel/xiaomi/mt6781|patches/android_kernel_xiaomi_mt6781/0001-mdpm-cfi-function-pointer-signature.patch"
)

for patch_spec in "${patch_specs[@]}"; do
  IFS='|' read -r project_path relative_patch <<<"$patch_spec"
  project="$workspace/$project_path"
  patch_file="$repo_root/$relative_patch"

  [[ -d "$project/.git" ]] || die "Missing Git project: $project"
  [[ -f "$patch_file" ]] || die "Missing patch: $patch_file"

  if git -C "$project" apply --reverse --check "$patch_file" 2>/dev/null; then
    log "Patch already applied: $relative_patch"
  elif git -C "$project" apply --check "$patch_file"; then
    git -C "$project" apply "$patch_file"
    log "Applied patch: $relative_patch"
  else
    die "Patch does not apply cleanly: $patch_file"
  fi
done
