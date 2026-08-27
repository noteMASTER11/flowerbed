#!/usr/bin/env bash
set -Eeuo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
# shellcheck source=lib/common.sh
source "$script_dir/lib/common.sh"


usage() {
  printf 'Usage: %s [--dry-run] OUTPUT_DIRECTORY\n' "${0##*/}"
}


print_commands() {
  printf '%s\n' \
    'adb get-state' \
    'adb shell getprop ro.product.device' \
    'adb shell getprop ro.product.model' \
    'adb shell getprop ro.build.fingerprint' \
    'adb shell getprop ro.lineage.version' \
    'adb shell getprop ro.boot.slot_suffix' \
    'adb shell getprop ro.boot.hwc' \
    'adb shell getprop ro.miui.build.region' \
    'adb shell getprop gsm.version.baseband' \
    'adb shell getprop sys.boot_completed' \
    'adb shell getprop ro.crypto.state' \
    'adb shell cat /proc/cmdline' \
    'adb shell cat /proc/meminfo' \
    'adb shell df -h' \
    'adb shell getenforce' \
    'adb shell settings get global device_provisioned' \
    'adb shell settings get secure user_setup_complete' \
    'adb shell dumpsys battery' \
    'adb shell dumpsys SurfaceFlinger' \
    'adb shell dumpsys media.camera' \
    'adb shell ls -l /dev/block/bootdevice/by-name' \
    'adb logcat -b all -d -v threadtime' \
    'adb shell dmesg'
}


capture() {
  local destination="$1" status
  shift
  {
    printf '$'
    printf ' %q' "$@"
    printf '\n'
    if "$@"; then
      status=0
    else
      status=$?
    fi
    printf '\n[exit-code] %d\n' "$status"
  } >"$destination" 2>&1
}


capture_properties() {
  local destination="$1" property status
  shift
  : >"$destination"
  for property in "$@"; do
    {
      printf '$ adb shell getprop %q\n' "$property"
      if adb shell getprop "$property"; then
        status=0
      else
        status=$?
      fi
      printf '[exit-code] %d\n\n' "$status"
    } >>"$destination" 2>&1
  done
}


dry_run=false
if [[ "${1:-}" == "--dry-run" ]]; then
  dry_run=true
  shift
fi

[[ $# -eq 1 ]] || {
  usage >&2
  exit 2
}

output_directory="$1"

if [[ "$dry_run" == true ]]; then
  print_commands
  exit 0
fi

require_command adb
[[ "$(adb get-state 2>/dev/null || true)" == device ]] || \
  die "ADB device is not connected and authorized"

mkdir -p -- "$output_directory"
chmod 0700 -- "$output_directory"

capture_properties "$output_directory/properties.txt" \
  ro.product.device \
  ro.product.model \
  ro.build.fingerprint \
  ro.lineage.version \
  ro.boot.slot_suffix \
  ro.boot.hwc \
  ro.miui.build.region \
  gsm.version.baseband \
  sys.boot_completed \
  ro.crypto.state

capture "$output_directory/cmdline.txt" adb shell cat /proc/cmdline
capture "$output_directory/meminfo.txt" adb shell cat /proc/meminfo
capture "$output_directory/filesystems.txt" adb shell df -h
capture "$output_directory/selinux.txt" adb shell getenforce
capture "$output_directory/provisioning.txt" adb shell settings get global device_provisioned
capture "$output_directory/setup-complete.txt" adb shell settings get secure user_setup_complete
capture "$output_directory/battery.txt" adb shell dumpsys battery
capture "$output_directory/surfaceflinger.txt" adb shell dumpsys SurfaceFlinger
capture "$output_directory/camera.txt" adb shell dumpsys media.camera
capture "$output_directory/partitions.txt" adb shell ls -l /dev/block/bootdevice/by-name
capture "$output_directory/logcat.txt" adb logcat -b all -d -v threadtime
capture "$output_directory/dmesg.txt" adb shell dmesg

log "Read-only device diagnostics written to: $output_directory"
