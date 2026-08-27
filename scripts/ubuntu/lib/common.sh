#!/usr/bin/env bash
set -Eeuo pipefail


log() {
  printf '[%s] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"
}


die() {
  log "ERROR: $*" >&2
  exit 1
}


require_command() {
  command -v "$1" >/dev/null 2>&1 || die "Missing command: $1"
}


resolve_repo_root() {
  cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd -P
}


require_ext4_workspace() {
  local path="$1" normalized filesystem
  normalized="$(realpath -m -- "$path")"
  [[ "$normalized" != /mnt/* ]] || die "Workspace must not be under /mnt"
  [[ -d "$normalized" ]] || die "Workspace does not exist: $normalized"
  filesystem="$(stat -f -c %T "$normalized")"
  [[ "$filesystem" == "ext2/ext3" || "$filesystem" == "ext2/ext3/ext4" ]] || \
    die "Workspace must be on ext4, found: $filesystem"
}

