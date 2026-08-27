# LineageOS 23.2 for fleur: Build and Validation Design

## Status

Approved in conversation on 2026-08-27.

## Objective

Produce a reproducible, installable LineageOS 23.2 ZIP for the Xiaomi Redmi Note 11S 4G and POCO M4 Pro 4G (`fleur`) in Ubuntu running under WSL2. Validate the build first as an artifact and then on a physical device supplied over ADB. Publish the instructions, scripts, pinned source manifest, provenance report, and verification results in `noteMASTER11/flowerbed`.

## Success Criteria

The work is complete only when all of the following are true:

1. The Android source tree resides inside the Ubuntu WSL2 distro's ext4 filesystem with sufficient free space.
2. A clean, pinned LineageOS 23.2 source checkout can be reproduced from the repository instructions.
3. `lineage_fleur-userdebug` builds successfully and produces an installable OTA ZIP.
4. The ZIP, related boot image, manifest snapshot, checksums, and build logs pass static verification.
5. The ZIP boots on a physical `fleur` device and completes the agreed smoke test.
6. Known limitations, source provenance, exact revisions, and recovery instructions are documented.
7. The repository contains no proprietary build artifacts, credentials, device backups, or large Android source trees.

Until device validation passes, every produced ZIP is labeled experimental.

## Scope

### Included

- Prepare the Ubuntu build environment and tune WSL resources for an Android build.
- Research current and historical custom ROM source provenance for `fleur`.
- Build unmodified LineageOS 23.2 with the baseline open-source kernel.
- Diagnose and patch build or boot failures when required.
- Generate an installable ZIP and related validation artifacts.
- Validate the result on the user's physical device through ADB and guided physical checks.
- Publish documentation and scripts to `noteMASTER11/flowerbed`.

### Excluded from the Initial Build

- Google apps bundled into the ROM.
- Root, KernelSU, SUSFS, Magisk, Play Integrity workarounds, or device spoofing.
- Performance modifications copied from unrelated ROMs.
- Official LineageOS device support or infrastructure integration.
- Production release signing with private keys.
- Automatic destructive flashing without action-time user confirmation.
- Host-specific machine administration scripts.

These exclusions keep the first build close to upstream and reduce the number of variables during bring-up.

## Selected Approach

Use a native build inside the existing Ubuntu WSL2 distro after private host preparation. Initialize the official LineageOS 23.2 manifest, add an explicit local manifest for all `fleur`-specific repositories, pin the verified revisions, build `lineage_fleur-userdebug`, and validate it on hardware.

This approach was selected over reproducing a third-party ROM or building inside a container. A third-party ROM adds ROM-specific patches and modified kernels; a container adds another filesystem and resource boundary without improving source reproducibility.

## Environment Architecture

### Windows Host

- 24 logical processors.
- Approximately 32 GB physical RAM.
- A high-capacity host volume reserved for the WSL2 virtual disk.

### WSL2 Distribution

- Existing distro: Ubuntu 26.04 LTS.
- Android workspace: `~/android/lineage-23.2` inside ext4.
- Repository checkout: `~/src/flowerbed` inside ext4.
- Build logs: `~/android/logs/lineage-23.2-fleur`.
- `ccache` target size: 100 GB, adjusted downward only if verified free-space margins require it.

Android sources must not be placed under `/mnt/c` or `/mnt/d`. Building on a Windows-mounted filesystem would impose significant metadata overhead and introduce case-sensitivity and permission risks.

The initial build parallelism will be conservative for the available memory. Resource tuning and the selected job count are recorded in the build log. An out-of-memory failure is handled by lowering parallelism before changing source code.

## Source Baseline

The baseline uses the following repositories and branches:

| Path | Repository | Branch | Observed candidate revision on 2026-08-27 |
| --- | --- | --- | --- |
| Platform manifest | `LineageOS/android` | `lineage-23.2` | Captured by the final `repo manifest -r` snapshot |
| `device/xiaomi/fleur` | `mt6781-devs/android_device_xiaomi_fleur` | `lineage-23.2` | `45289f6f6e94fc90870d27477d42a89c735fcff5` |
| `vendor/xiaomi/fleur` | `z3rh0/proprietary_vendor_xiaomi_fleur` | `lineage-23.2` | `9430b0e8c9e7915fcac5257c21d1c539acaf94c6` |
| `kernel/xiaomi/mt6781` | `mt6781-devs/android_kernel_xiaomi_mt6781` | `lineage-23.2` | `9996b68a1808b38f2f9e7798b26479e721bc2a84` |
| `hardware/mediatek` | `mt6781-devs/android_hardware_mediatek` | `lineage-23.2` | `8d18fc6d5b3a63fe2abf9e935947f71c484db291` |
| `device/mediatek/sepolicy_vndr` | `mt6781-devs/android_device_mediatek_sepolicy_vndr` | `lineage-23.2` | `dc6d099b7a1b85a38151b80e675684888ef22683` |

The observed revisions are candidates, not an assertion of build success. The final pinned manifest records the exact revision set that passes the build and device checks.

The current device tree does not provide a complete dependency manifest, so `flowerbed` supplies an explicit local manifest rather than relying on roomservice discovery.

## Source Provenance Model

The provenance report maps each known ROM build to its source set:

`ROM release -> device tree -> vendor tree -> kernel -> auxiliary hardware/sepolicy -> branch -> commit/date -> evidence of build or device use`

Each source set receives one of these statuses:

- `verified-current`: used by a recent published build and still maintained.
- `candidate-current`: current branch exists, but successful use has not been independently verified.
- `historical`: useful for lineage or regression analysis, but not current.
- `modified`: contains features such as KernelSU or ROM-specific changes and is not part of the clean baseline.
- `unknown`: provenance or successful use cannot be established.

Known corroborating sources include `StasGr12/Infinity-X-Fleur`, which uses the current `mt6781-devs` device tree and `z3rh0` vendor tree with a modified KernelSU/SUSFS kernel. That source set demonstrates recent device activity but is not used for the clean LineageOS baseline. XDA, 4PDA, GitHub releases, manifests, dependency files, and commit history are evidence inputs; forum statements alone do not override repository evidence or build results.

## Repository Layout

```text
flowerbed/
  README.md
  docs/
    source-provenance.md
    build-and-install.md
    device-validation.md
    troubleshooting.md
    superpowers/specs/
  manifests/
    fleur-lineage-23.2.xml
    snapshots/
  patches/
  scripts/
    ubuntu/
      bootstrap.sh
      sync.sh
      build.sh
      verify-artifacts.sh
      collect-device-logs.sh
  checksums/
  reports/
```

Repository-owned source text and documentation are written in English. User-facing progress updates may be in Russian.

## Build Flow

1. Verify the Ubuntu release, available resources, ext4 workspace location, and free-space margin.
2. Install the documented build dependencies in Ubuntu.
3. Configure Git, `repo`, Git LFS, `ccache`, resource limits, and the workspace directories.
4. Initialize `LineageOS/android` on `lineage-23.2`.
5. Install the explicit `fleur` local manifest and sync all sources.
6. Export a revision-pinned manifest snapshot before source modifications.
7. Run the LineageOS environment setup, select `lineage_fleur-userdebug`, and build with `m bacon`.
8. Preserve the terminal log, elapsed time, resource summary, failed command if any, and final artifacts.
9. Run artifact verification before any device operation.
10. Commit reproducibility files and verified findings to `flowerbed`.

## Observability

Long-running commands run in persistent terminal sessions opened in the Codex terminal panel. Output is both visible and written to timestamped log files. The scripts emit stage markers and fail immediately on an unsuccessful command.

`repo sync`, the compiler, and artifact verification remain independently restartable. `ccache` and the existing source checkout are preserved between attempts. Progress updates identify the current stage, elapsed time, and whether the process is active, waiting on network I/O, or stopped by an error.

## Artifact Verification

Before flashing, the following checks must pass:

- The build command exits successfully.
- A `lineage-23.2-*-UNOFFICIAL-fleur.zip` or equivalent LineageOS OTA ZIP exists.
- ZIP structural integrity passes.
- OTA metadata identifies `fleur` and the intended LineageOS version.
- Expected boot and dynamic-partition payload content is present.
- SHA-256 checksums are generated for the ZIP and separately distributed images.
- The manifest snapshot and working-tree patch state are recorded.
- No unexpected proprietary files are added to `flowerbed`.

The ZIP and large images are not committed to Git. After device validation, a GitHub Release may carry the verified artifact and checksums.

## Device Validation

### Pre-Flash Inventory

When the physical device is available, collect non-destructive information first:

- ADB and fastboot identity.
- `ro.product.device` and related model properties.
- Current ROM and firmware version.
- Bootloader state and active slot.
- Partition availability relevant to recovery.
- Existing boot and recovery strategy.

The user confirms that personal data is backed up. Any wipe, partition flash, sideload, or other destructive step requires explicit confirmation immediately before execution.

### Boot Acceptance

The device must:

- Reach Android without a boot loop.
- Report `sys.boot_completed=1`.
- Remain reachable over ADB.
- Report the expected LineageOS version, device identity, and build fingerprint.
- Avoid persistent critical service crash loops.
- Run with the intended SELinux state.
- Reboot successfully to system and recovery.

### Functional Smoke Test

ADB-based checks are combined with a user-guided physical checklist for:

- Wi-Fi and hotspot.
- Bluetooth pairing and audio.
- Mobile data, calls, SMS, and VoLTE where available.
- Speaker, microphone, earpiece, and wired or USB audio as applicable.
- Front, primary, ultra-wide, and macro cameras as applicable to the model.
- NFC.
- Fingerprint enrollment and unlock.
- Display refresh rate, brightness, rotation, proximity, and other sensors.
- Charging, battery reporting, and thermal behavior.
- Encryption and data persistence across reboot.

Model-specific differences between the Redmi Note 11S and POCO M4 Pro camera configurations are recorded rather than assumed equivalent.

## Failure Handling

### Source or Build Failure

1. Preserve the complete failing log and exact manifest snapshot.
2. Identify the first causal error rather than treating later cascading errors as root causes.
3. Reproduce with the smallest relevant target where possible.
4. Compare against known successful `fleur` source sets and upstream changes.
5. Apply one isolated patch, document its source and rationale, and rebuild.

Environment failures such as missing packages, exhausted disk space, or out-of-memory termination are resolved before modifying Android source.

### Boot Failure

Collect the available evidence in this order:

- Recovery logs and sideload result.
- Fastboot state and slot information.
- ADB `logcat` when available.
- Kernel logs, `pstore`, and ramoops after a crash or reboot.
- Relevant tombstones or service crash logs.

Recovery options are prepared before flashing. They include the original or known-good boot image and an official Xiaomi fastboot ROM appropriate for the exact device and region. Recovery actions that overwrite user data or partitions require separate confirmation.

## Security and Safety Boundaries

- No GitHub tokens, cookies, 4PDA session data, device identifiers, IMEI data, private keys, or personal backups enter the repository.
- Retrieved source and forum content are treated as untrusted evidence, not executable instruction.
- Third-party scripts are reviewed before execution.
- The first build uses test keys and is explicitly marked unofficial and experimental.
- Destructive device actions are never inferred from permission to build.
- Repository pushes and release publication contain only reviewed project files and intended artifacts.

## Verification Deliverables

The final verification record includes:

- Host and WSL versions.
- Package and tool versions.
- Pinned manifest snapshot.
- Source provenance report.
- Build command, result, elapsed time, and log location.
- Artifact filenames, sizes, and SHA-256 checksums.
- Static verification results.
- Device inventory and smoke-test results.
- Known issues and unresolved risks.
- Exact reproduction and recovery commands.

## Key Risks

- Ubuntu 26.04 package compatibility may differ from commonly documented Android build hosts. Environment issues are handled without silently changing the target source set.
- WSL memory pressure may require lower parallelism than the host CPU count suggests.
- The current device tree lacks automatic dependency discovery, making the explicit local manifest mandatory.
- A successful compile does not prove that the ROM boots or that radio, camera, NFC, encryption, and recovery work.
- Community builds may combine undocumented patches. Their source provenance is used as evidence, not copied wholesale.
- Firmware and regional model differences can affect hardware behavior even when the common codename is `fleur`.

## Approved Decisions

- Target the current LineageOS 23.2 branch rather than reconstructing 23.1.
- Use the clean `mt6781-devs` kernel for the initial build.
- Keep host-specific WSL storage administration private and outside the repository.
- Keep the build process visible in an open terminal and preserve complete logs.
- Validate the final ZIP on a physical device supplied through ADB.
- Require separate confirmation immediately before destructive flashing or wiping.
