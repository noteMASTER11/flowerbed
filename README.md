# flowerbed

Reproducible build and validation tooling for an unofficial LineageOS 23.2 build for Xiaomi Redmi Note 11S 4G and POCO M4 Pro 4G (`fleur`).

The ROM is experimental until device validation passes. No build from this repository is official LineageOS software.

## Safety

Building is non-destructive. Flashing, sideloading, formatting data, and changing partitions are separate operations that require an unlocked bootloader, a verified backup, and explicit confirmation immediately before execution.

## Repository contents

- `manifests/`: pinned device source revisions and successful build snapshots.
- `sources/`: structured source and firmware provenance.
- `scripts/ubuntu/`: environment, sync, build, artifact, and diagnostic tools.
- `docs/`: provenance, build, validation, and troubleshooting records.
- `reports/`: sanitized build and device-validation results.

Host-specific WSL storage administration is intentionally outside this repository.

## Quick start

Run the repository tooling from Ubuntu under WSL2. Keep both this checkout and the
Android source tree inside the distribution's Linux filesystem, not under `/mnt/c`
or `/mnt/d`.

```bash
git clone https://github.com/noteMASTER11/flowerbed.git ~/src/flowerbed
cd ~/src/flowerbed
scripts/ubuntu/bootstrap.sh
scripts/ubuntu/sync.sh ~/android/lineage-23.2
scripts/ubuntu/build.sh --jobs 8 ~/android/lineage-23.2
```

The build produces a standard LineageOS Virtual A/B OTA ZIP. The pinned firmware
images are included in its `payload.bin`; no separate firmware flash is required.

Continue with [build and install](docs/build-and-install.md), then run the
[device validation](docs/device-validation.md). Source and firmware selection is
recorded in [source provenance](docs/source-provenance.md). See
[troubleshooting](docs/troubleshooting.md) for known WSL2 and build failures.

## Signed release workflow

`fleur` remains the Android device and partition codename. The device patch only
selects the market-facing SKU name: Redmi Note 11S 4G or POCO M4 Pro 4G. Build a
fresh unsigned target-files archive incrementally, generate the private release
keyset once on WSL ext4 storage, post-build sign that exact archive, and run the
release verifier before exporting public artifacts. The full operator procedure,
including key custody and migration constraints, is in
[build and install](docs/build-and-install.md).

Never commit, publish, or copy private `.pk8`/`.pem` files, password records, or
the private keyset metadata to the repository, Wiki, or `C:\\output`.
