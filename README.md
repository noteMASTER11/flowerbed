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

