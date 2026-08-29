# Troubleshooting

## Workspace rejected under `/mnt`

The source and build output must reside in WSL2's Linux filesystem. Move the
checkout to a path such as `~/src/flowerbed` and the platform tree to
`~/android/lineage-23.2`. The repository does not prescribe how the host stores
or relocates the WSL virtual disk.

## `repo sync` fails or a pinned revision differs

Rerun `scripts/ubuntu/sync.sh` and retain the timestamped log. Do not silently
replace a pinned SHA with a branch tip. First establish whether the remote commit
was rewritten, a fetch was incomplete, or the manifest needs a reviewed update.

## Compiler or linker killed

Check WSL memory and swap, then rerun with fewer jobs:

```bash
scripts/ubuntu/build.sh --jobs 4 ~/android/lineage-23.2
```

Do not treat an out-of-memory failure as a source-tree defect until the kernel log
and memory limits have been checked.

## Incremental target-files runner rejects the output as stale

`build_target_files.sh` deliberately fails when `m target-files-package` leaves
the expected target-files ZIP unchanged, even if a copied older ZIP has a newer
timestamp and a forged packaging-log line. Do not point the signer at an older
ZIP or copy a prior provenance JSON. First confirm the SKU and MDPM CFI patches
are applied, then rerun the incremental target-files command. It retains
compiler outputs and ccache; it never performs a source or output cleanup.

## Release signing or verification rejects the keyset

Do not bypass a key or provenance error. Confirm that the target-files archive,
final build-provenance JSON, Android tree, and keyset are the exact paths from
the same incremental run. Keep private keys on WSL ext4 outside source trees and
check that no `.pk8`, private `.pem`, password file, or private keyset metadata
has been copied to an export directory. A lost private keyset means the update
lineage is lost: create a new keyset and perform a verified clean installation.
The provenance gate also rejects both the known raw pre-fix boot hash and its
normalized content hash, so changing an AVB footer or re-signing that old kernel
does not make it eligible for release signing.

## Missing `ota_extractor`

Build the AOSP host tool from the synchronized tree:

```bash
cd ~/android/lineage-23.2
source build/envsetup.sh
breakfast fleur
m ota_extractor
```

## Firmware verification fails

Do not sideload the ZIP. The full verifier requires all eleven partitions:
`audio_dsp`, `gz`, `lk`, `logo`, `md1img`, `pi_img`, `preloader_raw`, `scp`,
`spmfw`, `sspm`, and `tee`.

- A missing partition means the OTA payload composition is incomplete.
- A vendor revision mismatch means the build tree is not at the pinned source.
- A hash or non-zero-tail mismatch means the payload bytes do not match the
  recorded firmware input.

Keep the failed JSON/error output and build log. Do not bypass the check by
removing a partition from `sources/firmware.json`.

## ADB shows no authorized device

Use Windows `adb devices` first and accept the RSA prompt on the phone. Ensure a
single ADB server owns the connection; competing Windows and WSL ADB servers can
make USB forwarding appear intermittent. Diagnostic collection fails closed when
the state is not exactly `device`.

## Recovery rejects the OTA

Stop before retrying. Save recovery logs and record the recovery version, active
slot, OTA SHA-256, and exact error. Reconfirm `pre-device=fleur`, `ota-type=AB`,
and payload verification. Do not substitute ad-hoc firmware flashing as a repair.

## Boot loop after installation

Capture recovery logs and, if ADB becomes available, collect logcat/dmesg. Record
whether the failure began before or after data formatting and whether the device
can still enter bootloader and recovery. Any proposed repair must be tied to the
observed failure rather than a generic partition-flash sequence.
