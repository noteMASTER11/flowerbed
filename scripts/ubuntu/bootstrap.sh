#!/usr/bin/env bash
set -Eeuo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
# shellcheck source=lib/common.sh
source "$script_dir/lib/common.sh"

packages=(
  bc
  bison
  build-essential
  ccache
  curl
  flex
  g++-multilib
  gcc-multilib
  git
  git-lfs
  gnupg
  gperf
  imagemagick
  lib32readline-dev
  lib32z1-dev
  libelf-dev
  liblz4-tool
  libncurses-dev
  libssl-dev
  libxml2
  libxml2-utils
  lzop
  pngcrush
  python-is-python3
  python3
  repo
  rsync
  schedtool
  software-properties-common
  squashfs-tools
  xsltproc
  zip
  zlib1g-dev
)

mode="install"
case "${1:-}" in
  --print-packages)
    mode="print"
    ;;
  --dry-run)
    mode="dry-run"
    ;;
  "")
    ;;
  *)
    die "Usage: $0 [--print-packages|--dry-run]"
    ;;
esac

if [[ "$mode" == "print" ]]; then
  printf '%s\n' "${packages[@]}"
  exit 0
fi

if [[ "$mode" == "dry-run" ]]; then
  printf 'DRY-RUN sudo add-apt-repository -y universe\n'
  printf 'DRY-RUN sudo apt-get update\n'
  printf 'DRY-RUN sudo apt-get install -y'
  printf ' %q' "${packages[@]}"
  printf '\n'
  printf 'DRY-RUN git lfs install\n'
  printf 'DRY-RUN ccache -M 100G\n'
  printf 'DRY-RUN repo version\n'
  exit 0
fi

require_command sudo
sudo add-apt-repository -y universe
sudo apt-get update
sudo apt-get install -y "${packages[@]}"
git lfs install
ccache -M 100G

require_command repo
require_command git
require_command ccache
repo version
git lfs version
ccache --version
log "Ubuntu build dependencies are ready"
