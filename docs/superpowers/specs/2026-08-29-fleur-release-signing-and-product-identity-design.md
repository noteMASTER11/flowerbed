# fleur Release Signing and Product Identity Design

## Status

Design choices approved in conversation on 2026-08-29. Awaiting review of this written specification before implementation planning.

## Objective

Extend the reproducible LineageOS 23.2 build workflow for `fleur` so that:

1. Redmi and POCO hardware variants expose their full market names in Android while retaining the shared `fleur` platform identity required by OTA and partition tooling.
2. The resulting target-files package is post-build signed with a persistent, privately held release-key set instead of Android test keys.
3. Both a Recovery OTA ZIP and a fastboot image ZIP are generated from the same signed target-files package and pass static signature, identity, payload, firmware, and AVB verification.

The private keys are local release infrastructure. They are never committed, uploaded, embedded in documentation, or copied into public build reports.

## Product Identity

### Observed behavior

The current device tree sets the top-level product model to the hardware identifier `2201117SY`, but `PRODUCT_BUILD_PROP_OVERRIDES` and the ODM SKU property files resolve `Build.MODEL` to `fleur`. LineageOS Settings displays `Build.MODEL`, so the user-visible model is the codename.

The inspected crDroid OTA retains `fleur` for system, product, vendor, OTA, and build-fingerprint identity. Its SKU property files additionally define `ro.product.marketname` as either `Redmi Note 11S` or `POCO M4 Pro`.

### Selected mapping

The four existing SKU property files will carry both the market name and the ODM model:

| Boot hardware SKU | Market name | ODM model |
| --- | --- | --- |
| `fleur` | `Redmi Note 11S` | `Redmi Note 11S` |
| `miel` | `Redmi Note 11S` | `Redmi Note 11S` |
| `fleurp` | `POCO M4 Pro` | `POCO M4 Pro` |
| `mielp` | `POCO M4 Pro` | `POCO M4 Pro` |

Each file will define:

- `ro.product.marketname` for ROM components that explicitly prefer the marketing name.
- `ro.product.odm.model` for AOSP and LineageOS components that use `Build.MODEL`.

The following compatibility identifiers remain unchanged:

- `PRODUCT_DEVICE=fleur`
- `ro.product.*.device=fleur` where the existing SKU already uses `fleur`
- `PRODUCT_NAME=lineage_fleur`
- OTA `pre-device=fleur`
- dynamic-partition names and firmware partition names
- the stock-derived build fingerprint used by the device tree

The change must not introduce a single hard-coded Redmi or POCO name outside the existing SKU selection mechanism.

## Signing Architecture

### Selected approach

Use post-build signing. Build an unsigned/test-key target-files package with the normal Android build, then transform it into one signed target-files package. Generate every distributable artifact from that signed package.

This approach keeps private key material outside the Android source checkout, avoids coupling source synchronization to secrets, and allows the expensive compilation result to be reused. The product-identity change still requires one incremental target-files rebuild before signing because it changes ODM contents.

### Key set

Create one persistent password-protected key set dedicated to this `fleur` release lineage. It includes:

- Android package certificate roles required by the target-files package, including `releasekey`, `platform`, `shared`, `media`, `networkstack`, Bluetooth, NFC, SDK sandbox, and other roles actually referenced by `apkcerts.txt`.
- Dedicated 4096-bit keys for every APEX listed by `apexkeys.txt`, with separate container and payload key material as required by Android 16 / LineageOS 23.2.
- Private AVB keys for `boot`, `vbmeta`, `vbmeta_system`, and `vbmeta_vendor`, replacing the public Android test AVB key configured by the current device tree.
- The OTA/recovery verification certificate derived from the release key.

Key discovery is driven by the newly built target-files metadata, not by a stale hard-coded list. The script may maintain explicit role mappings, but it must fail if the target-files package references an unmapped test certificate, APEX key, or AVB test key.

### Key storage

Private material is stored under a dedicated directory inside the Ubuntu WSL ext4 filesystem, whose virtual disk resides on drive D. The default location is outside both the Android tree and the `flowerbed` checkout.

Requirements:

- directory permissions restrict access to the build user;
- private key and password files are not placed under `/mnt/c`, `/mnt/d`, the Git repository, `C:\output`, logs, or reports;
- the user enters the passphrase directly in an Ubuntu terminal;
- public X.509 certificates, public AVB keys, and their fingerprints may be exported with the release artifacts;
- the documentation explains that losing the keys prevents seamless future OTA updates under the same trust lineage.

No key-generation step overwrites an existing key. Re-running key generation must be idempotent and must stop on a partial or inconsistent key set.

## Artifact Flow

```text
patched device tree
  -> incremental target-files build
  -> unsigned/test-key target-files ZIP
  -> package/APEX/AVB/OTA signing
  -> signed target-files ZIP
       -> Recovery OTA ZIP
       -> fastboot image ZIP
       -> public certificates and fingerprints
       -> SHA256SUMS and sanitized signing report
```

The existing `out` directory and compiler cache are preserved. Signing operates on copies or new output paths and never overwrites the last known-good unsigned artifacts.

The OTA and fastboot packages must have unambiguous filenames containing `fleur`, LineageOS 23.2, the build date, and a `SIGNED` marker. The signed target-files package remains a local intermediate unless the user explicitly requests its publication.

## Migration and Installation Compatibility

A clean installation of the release-key build needs no package-key migration. Preserving `/data` while moving from the existing test-key build to the new release-key lineage may require the LineageOS key-migration mechanism because privileged packages and stored permission state trust the previous certificates.

The normal release package must not contain an automatic key migration. If data preservation is requested, produce and review a separate, explicitly named one-shot migration procedure derived from LineageOS's key-migration scripts. It must not be presented as necessary for a clean install.

TWRP may allow installation independently of the Lineage Recovery OTA certificate, but this is not treated as proof that the package or its contents are correctly release-signed. Static verification remains mandatory.

## Repository Changes

Implementation is expected to add or update:

- a reproducible patch for the four `device/xiaomi/fleur/sku/build_*.prop` files;
- an idempotent local key-generation helper that never prints secret material;
- a post-build signing script that consumes a target-files ZIP and a private key directory;
- verification code for package certificates, APEX keys, OTA signature, AVB public keys, build tags, product identity, payload partitions, and firmware hashes;
- Russian Wiki instructions for key custody, signing, installation, migration, verification, and recovery from lost keys;
- `.gitignore` protections for any conventional local signing directory or password-file name used by the scripts.

Repository-owned source and documentation remain in English except for the user-facing GitHub Wiki, which is Russian by request.

## Validation

### Source-level identity tests

Before applying the device-tree patch, a regression test must fail because the four SKU files do not provide the required mapping. After the patch it must verify:

- all four SKU files define the expected `ro.product.marketname`;
- all four define the matching `ro.product.odm.model`;
- Redmi and POCO variants remain distinct;
- `PRODUCT_DEVICE`, OTA target device, build fingerprint, and partition identity are unchanged.

### Unsigned build checks

The incremental build must regenerate target-files and show the expected properties in `ODM/etc/build_*.prop`. The compiler cache and existing `out` tree are retained.

### Signed target-files checks

Verification must prove that:

- no package or APEX metadata entry still references Android test certificates;
- every APEX container and payload has the intended public-key fingerprint;
- AVB metadata for all signed partitions resolves to the new private release lineage rather than the AOSP test key;
- build tags report `release-keys`;
- OTA metadata still targets `fleur`;
- all expected Android and firmware partitions remain in the payload;
- firmware image hashes still match the pinned firmware manifest;
- ZIP integrity and OTA signature verification pass.

### Device checks

After separately authorized installation, verify without logging unique identifiers:

- `ro.product.marketname` matches the detected SKU;
- `ro.product.model` / `Build.MODEL` shows the full market name;
- `ro.product.device` remains `fleur` for a fleur variant;
- Android boots twice, the modem reaches `ready`, and the baseband remains available;
- Recovery accepts a subsequent OTA signed by the same key lineage;
- the device is explicitly reported as hardware-tested only after these checks pass.

## Failure Handling

- A missing certificate or APEX mapping stops signing; it is never silently signed with a test key.
- A partial existing key directory stops key generation and reports the missing roles.
- Any private key path inside the repository or Windows output directory is rejected.
- A signed artifact that fails any certificate, AVB, payload, identity, or firmware check is quarantined and not copied to `C:\output` or published.
- Unsigned and previously verified artifacts remain intact for diagnosis.
- Private key material is excluded from logs, command traces, checksums intended for publication, Git commits, and GitHub releases.

## Completion Criteria

The change is complete when:

1. The SKU identity regression tests pass.
2. A fresh incremental target-files build contains the approved Redmi/POCO mapping.
3. A persistent password-protected release-key set exists only in the approved private location.
4. The signed target-files ZIP passes package, APEX, OTA, AVB, identity, payload, and firmware verification.
5. Signed Recovery OTA and fastboot ZIPs are generated from that same target-files package and copied to `C:\output` with SHA-256 checksums and a sanitized report.
6. Public documentation and the Russian Wiki explain reproduction, key custody, clean installation, optional key migration, verification, and limitations.
7. No private key, password, device identifier, proprietary build artifact, or unrelated local file is committed to Git.
