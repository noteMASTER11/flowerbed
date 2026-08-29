# fleur Release Signing and Product Identity Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Produce LineageOS 23.2 Recovery OTA and fastboot ZIPs for `fleur` that show the correct Redmi/POCO market name and are fully signed with a persistent private release-key lineage instead of Android test keys.

**Architecture:** Add SKU-specific product identity through a reproducible device-tree patch, rebuild target-files incrementally without cleaning `out` or ccache, and post-build sign that target-files package. Key inventory is derived from target-files metadata; signed OTA and fastboot packages are generated from the same signed target-files ZIP and verified before copying to Windows output.

**Tech Stack:** Bash, Python 3 standard library, `unittest`, Android releasetools, OpenSSL, `avbtool`, `apksigner`, `ota_extractor`, Git, WSL2 Ubuntu.

**Spec:** `docs/superpowers/specs/2026-08-29-fleur-release-signing-and-product-identity-design.md`

## Global Constraints

- Preserve the existing Android `out` tree and ccache; never run a clean build target.
- Keep `PRODUCT_DEVICE=fleur`, OTA `pre-device=fleur`, partition names, and the stock-derived fingerprint identity unchanged.
- Map `fleur` and `miel` to `Redmi Note 11S`; map `fleurp` and `mielp` to `POCO M4 Pro`.
- Store private keys only inside the Ubuntu WSL ext4 filesystem outside the Android tree and repository.
- Never print, log, commit, upload, checksum for publication, or copy private keys or passphrases to `C:\output`.
- Never overwrite an existing key or a previously verified unsigned or signed artifact.
- Build both distributable ZIPs from one signed target-files package.
- Do not install or flash any artifact without separate explicit authorization.
- Do not describe the build as device-validated until the post-install hardware checks pass.

## File Map

- `patches/android_device_xiaomi_fleur/0006-fleur-expose-sku-market-names.patch`: reproducible SKU property change.
- `scripts/ubuntu/apply_patches.sh`: applies patch 0006 after existing compatibility patches.
- `tests/test_product_identity.py`: regression tests for SKU mappings and invariant device identity.
- `scripts/ubuntu/signing_metadata.py`: target-files signing inventory parser.
- `tests/test_signing_metadata.py`: synthetic metadata parser tests.
- `scripts/ubuntu/generate_release_keys.py`: protected Android, APEX, and AVB key generation.
- `scripts/ubuntu/avb_password_helper.py`: non-interactive encrypted-PEM password lookup for `avbtool`.
- `tests/test_generate_release_keys.py`: key-plan, path-safety, and partial-keyset tests.
- `scripts/ubuntu/sign_release.py`: releasetools orchestration and sanitized signing manifest.
- `tests/test_sign_release.py`: command-construction and no-overwrite tests.
- `scripts/ubuntu/verify_signed_release.py`: signed target-files, OTA, fastboot, APEX, and AVB verification.
- `tests/test_signed_release.py`: signed metadata policy tests.
- `scripts/ubuntu/build_target_files.sh`: observable incremental target-files runner.
- `tests/test_scripts.py`: shell syntax, dry-run, and no-clean contract coverage.
- `.gitignore`, `README.md`, `docs/build-and-install.md`, `docs/troubleshooting.md`: safety and operator documentation.
- Separate GitHub Wiki checkout: Russian operator documentation after local validation.

---

### Task 1: SKU Product Identity Patch

**Files:**
- Create: `tests/test_product_identity.py`
- Create: `patches/android_device_xiaomi_fleur/0006-fleur-expose-sku-market-names.patch`
- Modify: `scripts/ubuntu/apply_patches.sh`

**Interfaces:**
- Consumes: patch specification `project_path|relative_patch`.
- Produces: `EXPECTED_SKUS: dict[str, str]` and a patch adding matching `ro.product.marketname` and `ro.product.odm.model`.

- [ ] **Step 1: Write the failing identity regression test**

Create `tests/test_product_identity.py`:

```python
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
PATCH = ROOT / "patches/android_device_xiaomi_fleur/0006-fleur-expose-sku-market-names.patch"
APPLIER = ROOT / "scripts/ubuntu/apply_patches.sh"
EXPECTED_SKUS = {
    "fleur": "Redmi Note 11S",
    "miel": "Redmi Note 11S",
    "fleurp": "POCO M4 Pro",
    "mielp": "POCO M4 Pro",
}


class ProductIdentityTest(unittest.TestCase):
    def test_patch_contains_market_name_and_odm_model_for_every_sku(self):
        text = PATCH.read_text(encoding="utf-8")
        for sku, market_name in EXPECTED_SKUS.items():
            self.assertIn(f"sku/build_{sku}.prop", text)
            self.assertGreaterEqual(text.count(f"+ro.product.marketname={market_name}"), 1)
            self.assertGreaterEqual(text.count(f"+ro.product.odm.model={market_name}"), 1)

    def test_patch_does_not_change_device_or_product_name(self):
        text = PATCH.read_text(encoding="utf-8")
        self.assertNotRegex(text, re.compile(r"^[+-].*PRODUCT_DEVICE", re.MULTILINE))
        self.assertNotRegex(text, re.compile(r"^[+-].*ro.product.odm.device", re.MULTILINE))
        self.assertNotRegex(text, re.compile(r"^[+-].*ro.product.odm.name", re.MULTILINE))

    def test_patch_is_registered_after_existing_fleur_patches(self):
        text = APPLIER.read_text(encoding="utf-8")
        old = text.index("0005-fleur-use-common-mediatek-vt-context.patch")
        new = text.index("0006-fleur-expose-sku-market-names.patch")
        self.assertLess(old, new)
```

- [ ] **Step 2: Verify the test fails**

Run:

```bash
cd /home/administrator/src/flowerbed
python3 -m unittest tests.test_product_identity -v
```

Expected: FAIL because patch 0006 is absent.

- [ ] **Step 3: Add the minimal patch and register it**

Patch each SKU file without changing brand, device, or product name:

```diff
diff --git a/sku/build_fleur.prop b/sku/build_fleur.prop
--- a/sku/build_fleur.prop
+++ b/sku/build_fleur.prop
@@
 vendor.usb.product_string=Redmi Note 11S
+ro.product.marketname=Redmi Note 11S
 ro.product.odm.brand=Redmi
-ro.product.odm.model=fleur
+ro.product.odm.model=Redmi Note 11S
diff --git a/sku/build_miel.prop b/sku/build_miel.prop
--- a/sku/build_miel.prop
+++ b/sku/build_miel.prop
@@
 vendor.usb.product_string=Redmi Note 11S
+ro.product.marketname=Redmi Note 11S
 ro.product.odm.brand=Redmi
-ro.product.odm.model=miel
+ro.product.odm.model=Redmi Note 11S
diff --git a/sku/build_fleurp.prop b/sku/build_fleurp.prop
--- a/sku/build_fleurp.prop
+++ b/sku/build_fleurp.prop
@@
 vendor.usb.product_string=POCO M4 Pro
+ro.product.marketname=POCO M4 Pro
 ro.product.odm.brand=POCO
-ro.product.odm.model=fleur
+ro.product.odm.model=POCO M4 Pro
diff --git a/sku/build_mielp.prop b/sku/build_mielp.prop
--- a/sku/build_mielp.prop
+++ b/sku/build_mielp.prop
@@
 vendor.usb.product_string=POCO M4 Pro
+ro.product.marketname=POCO M4 Pro
 ro.product.odm.brand=POCO
-ro.product.odm.model=miel
+ro.product.odm.model=POCO M4 Pro
```

Append:

```bash
"device/xiaomi/fleur|patches/android_device_xiaomi_fleur/0006-fleur-expose-sku-market-names.patch"
```

after patch 0005 in `apply_patches.sh`.

- [ ] **Step 4: Run focused and complete validation**

```bash
python3 -m unittest tests.test_product_identity -v
python3 -m unittest discover -s tests -v
shellcheck -x -P scripts/ubuntu scripts/ubuntu/*.sh scripts/ubuntu/lib/*.sh
```

Expected: all tests pass; ShellCheck reports no error.

- [ ] **Step 5: Commit**

```bash
git add tests/test_product_identity.py \
  patches/android_device_xiaomi_fleur/0006-fleur-expose-sku-market-names.patch \
  scripts/ubuntu/apply_patches.sh
git commit -m "fleur: expose SKU-specific market names"
```

---

### Task 2: Target-Files Signing Inventory

**Files:**
- Create: `scripts/ubuntu/signing_metadata.py`
- Create: `tests/test_signing_metadata.py`

**Interfaces:**
- Consumes: target-files ZIP containing `META/apkcerts.txt`, `META/apexkeys.txt`, and `META/misc_info.txt`.
- Produces: `SigningInventory` and `load_signing_inventory(path: Path) -> SigningInventory`.

- [ ] **Step 1: Write failing synthetic ZIP tests**

The tests must assert:

```python
inventory = load_signing_inventory(target_files)
self.assertEqual(inventory.android_roles, {"platform", "releasekey"})
self.assertEqual(inventory.apexes[0].name, "com.android.art.apex")
self.assertEqual({item.partition for item in inventory.avb_keys}, {"boot", "vbmeta", "vbmeta_system"})
self.assertTrue(inventory.uses_test_build_tags)
self.assertIn("build/make/target/product/security/testkey", inventory.source_key_stems)
```

Add malformed fixtures for a missing metadata member, duplicate conflicting APEX name, and unsupported AVB algorithm. Each raises `SigningMetadataError`.

- [ ] **Step 2: Verify import failure**

```bash
python3 -m unittest tests.test_signing_metadata -v
```

Expected: FAIL because the parser is missing.

- [ ] **Step 3: Implement immutable inventory types**

```python
@dataclass(frozen=True)
class ApkCertificate:
    name: str
    certificate: str
    private_key: str

@dataclass(frozen=True)
class ApexKey:
    name: str
    public_key: str
    private_key: str
    container_certificate: str
    container_private_key: str
    partition: str
    presigned: bool

@dataclass(frozen=True)
class AvbPartitionKey:
    partition: str
    algorithm: str
    source_key: str

@dataclass(frozen=True)
class SigningInventory:
    apk_certificates: tuple[ApkCertificate, ...]
    apexes: tuple[ApexKey, ...]
    avb_keys: tuple[AvbPartitionKey, ...]
    misc_info: Mapping[str, str]
    source_key_stems: frozenset[str]
    android_roles: frozenset[str]
    uses_test_build_tags: bool

def load_signing_inventory(target_files: Path) -> SigningInventory:
    with ZipFile(target_files) as archive:
        apk_text = _read_required_member(archive, "META/apkcerts.txt")
        apex_text = _read_required_member(archive, "META/apexkeys.txt")
        misc_text = _read_required_member(archive, "META/misc_info.txt")

    apk_certificates = _parse_apkcerts(apk_text)
    apexes = _parse_apexkeys(apex_text)
    misc_info = _parse_misc_info(misc_text)
    avb_keys = _parse_avb_keys(misc_info)
    return _assemble_inventory(apk_certificates, apexes, avb_keys, misc_info)
```

Implement `_read_required_member`, `_parse_apkcerts`, `_parse_apexkeys`, `_parse_misc_info`, `_parse_avb_keys`, and `_assemble_inventory` as pure, directly tested helpers. Parse quoted fields with `shlex.split`, normalize `.x509.pem` and `.pk8` to key stems, retain `PRESIGNED` without requesting keys, sort deterministically, and accept only `SHA256_RSA4096` for fleur AVB roles.

- [ ] **Step 4: Run focused and complete tests**

```bash
python3 -m unittest tests.test_signing_metadata -v
python3 -m unittest discover -s tests -v
```

Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add scripts/ubuntu/signing_metadata.py tests/test_signing_metadata.py
git commit -m "signing: inventory target-files key metadata"
```

---

### Task 3: Protected Release-Key Generation

**Files:**
- Create: `scripts/ubuntu/generate_release_keys.py`
- Create: `scripts/ubuntu/avb_password_helper.py`
- Create: `tests/test_generate_release_keys.py`
- Modify: `.gitignore`

**Interfaces:**
- CLI: `generate_release_keys.py --target-files PATH --android-root PATH --keys-dir PATH --subject SUBJECT [--dry-run]`.
- Produces: protected Android `.pk8`/X.509 keys, 4096-bit APEX/AVB PEM keys, public AVB keys, `keyset.json`, and mode-0600 `passwords`.

- [ ] **Step 1: Write failing plan and safety tests**

Use a fake command runner and patched `getpass.getpass`:

```python
self.assertRaises(KeyGenerationError, validate_private_destination, repo / "keys", repo, android_root)
self.assertRaises(KeyGenerationError, validate_private_destination, Path("/mnt/d/keys"), repo, android_root)
self.assertIn("com.android.art", plan.apex_names)
self.assertEqual(plan.avb_roles, ("boot", "vbmeta", "vbmeta_system", "vbmeta_vendor"))
```

Blank passphrases, mismatched confirmation, a partial directory, or existing private files without valid `keyset.json` must fail before OpenSSL runs.
Add helper tests proving that only the exact `TMP__KEY_FILE_NAME` entry is returned from the mode-0600 Android password file and that missing, duplicate, malformed, symlinked, or overly permissive password files fail without printing any other entry.

- [ ] **Step 2: Verify failure**

```bash
python3 -m unittest tests.test_generate_release_keys -v
```

Expected: FAIL because the generator is missing.

- [ ] **Step 3: Implement atomic protected key generation**

Use `getpass.getpass` once plus confirmation and pass the secret only through subprocess standard input.

Android package keys use:

```text
openssl genrsa -traditional -out "$SECURE_TEMP/$ROLE.raw.pem" 2048
openssl req -new -x509 -sha256 -key "$SECURE_TEMP/$ROLE.raw.pem" -out "$KEYS_DIR/$ROLE.x509.pem" -days 10000 -subj "$SUBJECT"
openssl pkcs8 -in "$SECURE_TEMP/$ROLE.raw.pem" -topk8 -v1 PBE-SHA1-3DES -outform DER -out "$KEYS_DIR/$ROLE.pk8" -passout stdin
```

APEX and AVB keys use RSA-4096 and encrypted PKCS#8 PEM output:

```text
openssl genrsa -traditional -out "$SECURE_TEMP/$KEY_NAME.raw.pem" 4096
openssl pkcs8 -in "$SECURE_TEMP/$KEY_NAME.raw.pem" -topk8 -out "$KEYS_DIR/$KEY_NAME.pem" -passout stdin
avbtool extract_public_key --key "$KEYS_DIR/$KEY_NAME.pem" --output "$KEYS_DIR/public/$KEY_NAME.avbpubkey"
```

For every non-presigned APEX, derive the matching container `.x509.pem` and `.pk8` from the same RSA-4096 key. Write schema-version-1 `keyset.json` containing key names and public SHA-256 fingerprints. Write Android password-manager entries to `passwords`. Implement `avb_password_helper.py PASSWORD_FILE` so `avbtool` can obtain the matching encrypted PEM passphrase through its existing `TMP__KEY_FILE_NAME` contract; the helper emits only the requested passphrase to its child pipe and never logs it. Use permissions `0700` for directories and `0600` for private files. Atomically rename the complete staging directory.

Add:

```gitignore
.android-certs/
signing-private/
ANDROID_PW_FILE
*.passwords
```

to `.gitignore`.

- [ ] **Step 4: Validate**

```bash
python3 -m unittest tests.test_generate_release_keys tests.test_repository -v
python3 -m unittest discover -s tests -v
```

Expected: all pass and fixture passphrases never appear.

- [ ] **Step 5: Commit**

```bash
git add .gitignore scripts/ubuntu/generate_release_keys.py scripts/ubuntu/avb_password_helper.py tests/test_generate_release_keys.py
git commit -m "signing: generate protected fleur release keys"
```

---

### Task 4: Post-Build Signing Orchestrator

**Files:**
- Create: `scripts/ubuntu/sign_release.py`
- Create: `tests/test_sign_release.py`

**Interfaces:**
- CLI: `sign_release.py --target-files PATH --android-root PATH --keys-dir PATH --output-dir PATH [--dry-run]`.
- Produces: signed target-files, Recovery OTA, fastboot image ZIP, public-key bundle, `signing-report.json`, and `SHA256SUMS`.

- [ ] **Step 1: Write failing deterministic command tests**

```python
commands = build_signing_commands(inventory, paths)
self.assertIn("--tag_changes", commands.sign_target_files)
self.assertIn("-test-keys,+release-keys", commands.sign_target_files)
self.assertIn("--avb_boot_key", commands.sign_target_files)
self.assertIn(str(paths.keys_dir / "avb_boot.pem"), commands.sign_target_files)
self.assertIn("--extra_apks", commands.sign_target_files)
self.assertIn("--extra_apex_payload_key", commands.sign_target_files)
self.assertEqual(commands.ota_from_target_files[-2:], [str(paths.signed_target_files), str(paths.ota_zip)])
self.assertEqual(commands.img_from_target_files[-2:], [str(paths.signed_target_files), str(paths.fastboot_zip)])
```

Assert `PRESIGNED` APEXes receive no override, every other APEX receives container and payload overrides, collisions fail, and commands contain no password.

- [ ] **Step 2: Verify failure**

```bash
python3 -m unittest tests.test_sign_release -v
```

Expected: FAIL because the orchestrator is missing.

- [ ] **Step 3: Implement signing commands**

Resolve host tools from `paths.android_root / "out/host/linux-x86/bin"`. Put `ANDROID_PW_FILE=str(paths.keys_dir / "passwords")` and `ANDROID_SECURE_STORAGE_CMD=f"python3 {repo_root / 'scripts/ubuntu/avb_password_helper.py'} {paths.keys_dir / 'passwords'}"` only in child-process environments. Construct `sign_target_files_apks` with:

```text
-o
-d "$KEYS_DIR"
--tag_changes -test-keys,+release-keys
--avb_boot_algorithm SHA256_RSA4096
--avb_boot_key "$KEYS_DIR/avb_boot.pem"
--avb_vbmeta_algorithm SHA256_RSA4096
--avb_vbmeta_key "$KEYS_DIR/avb_vbmeta.pem"
--avb_vbmeta_system_algorithm SHA256_RSA4096
--avb_vbmeta_system_key "$KEYS_DIR/avb_vbmeta_system.pem"
--avb_vbmeta_vendor_algorithm SHA256_RSA4096
--avb_vbmeta_vendor_key "$KEYS_DIR/avb_vbmeta_vendor.pem"
```

For every non-presigned source certificate stem from `apkcerts.txt`, append `-k source_stem=$KEYS_DIR/generated_role`. For every non-presigned APEX filename from `apexkeys.txt`, append both `--extra_apks apex_filename=$KEYS_DIR/container_role` and `--extra_apex_payload_key apex_filename=$KEYS_DIR/payload_role.pem`; do not emit either override for a `PRESIGNED` APEX. Then run:

```text
ota_from_target_files -k "$KEYS_DIR/releasekey" --block --backup=true "$SIGNED_TARGET_FILES" "$SIGNED_OTA"
img_from_target_files "$SIGNED_TARGET_FILES" "$SIGNED_FASTBOOT"
```

Record that fleur has `ab_update=true` and `virtual_ab=true`; after generation, verification must still require `payload.bin` and must reject a legacy non-payload OTA.

Use temporary names and atomic rename after zero exit status. Export only public material. The report includes input/output hashes, public fingerprints, tool paths, sanitized option names, and timestamps.
Name the outputs exactly from `output_dir.name` (the UTC build ID): `lineage_fleur-SIGNED-target_files.zip`, `lineage-23.2-{output_dir.name}-SIGNED-fleur.zip`, `lineage_fleur-SIGNED-img.zip`, `public-keys/`, `signing-report.json`, and `SHA256SUMS`. Reject an output directory whose name is not a UTC `YYYYMMDDTHHMMSSZ` identifier.

- [ ] **Step 4: Validate**

```bash
python3 -m unittest tests.test_sign_release -v
python3 -m unittest discover -s tests -v
```

Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add scripts/ubuntu/sign_release.py tests/test_sign_release.py
git commit -m "signing: produce signed OTA and fastboot packages"
```

---

### Task 5: Signed Release Verification

**Files:**
- Create: `scripts/ubuntu/verify_signed_release.py`
- Create: `tests/test_signed_release.py`
- Modify: `scripts/ubuntu/verify_artifacts.py`
- Modify: `tests/test_artifacts.py`

**Interfaces:**
- CLI: `verify_signed_release.py --unsigned-target-files PATH --signed-target-files PATH --ota PATH --fastboot PATH --public-keys PATH --android-root PATH --firmware-manifest PATH --report PATH`.
- Produces: exit status, findings, and sanitized `verification-report.json`.

- [ ] **Step 1: Write failing verification-policy tests**

```python
with self.assertRaisesRegex(VerificationError, "test-keys"):
    verify_build_tags({"ro.product.build.tags": "test-keys"})
with self.assertRaisesRegex(VerificationError, "pre-device"):
    verify_ota_metadata("pre-device=wrong\n")
with self.assertRaisesRegex(VerificationError, "marketname"):
    verify_sku_properties({"build_fleur.prop": "ro.product.odm.model=fleur\n"})
with self.assertRaisesRegex(VerificationError, "AVB"):
    verify_avb_fingerprints({"boot": "old"}, {"boot": "new"})
```

Add a passing fixture with all four SKU mappings, `release-keys`, `pre-device=fleur`, firmware partitions, and matching public fingerprints.

- [ ] **Step 2: Verify failure**

```bash
python3 -m unittest tests.test_signed_release -v
```

Expected: FAIL because the verifier is missing.

- [ ] **Step 3: Implement layered verification**

The verifier must:

1. run `unzip -t` on every ZIP;
2. compare signed and unsigned partition lists and firmware hashes;
3. inspect signed `apkcerts.txt`, `apexkeys.txt`, and `misc_info.txt`;
4. reject standard Android test certificate paths while explicitly reporting permitted `PRESIGNED` entries;
5. run `apksigner verify --print-certs` on representative extracted APKs;
6. verify every non-presigned APEX container and payload with `apksigner`, `deapexer`, and `avbtool info_image`;
7. verify AVB public-key digests for `boot`, `vbmeta`, `vbmeta_system`, and `vbmeta_vendor`;
8. verify OTA metadata, payload properties, `fleur`, SKU property files, Android partitions, and firmware partitions/hashes;
9. verify the OTA whole-file signature with a local checkout of LineageOS `update_verifier` whose `HEAD` must equal pinned commit `9ffcf56a0fe152467da2971f0e6b2b79a42f7890` from its `main` branch; reject an absent or differently pinned verifier instead of downloading mutable code during release verification;
10. compare `android-info.txt` and required fastboot images with signed target-files.

Write only public fingerprints, hashes, sizes, pass/fail findings, and sanitized paths.

- [ ] **Step 4: Validate**

```bash
python3 -m unittest tests.test_signed_release tests.test_artifacts -v
python3 -m unittest discover -s tests -v
shellcheck -x -P scripts/ubuntu scripts/ubuntu/*.sh scripts/ubuntu/lib/*.sh
```

Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add scripts/ubuntu/verify_signed_release.py scripts/ubuntu/verify_artifacts.py \
  tests/test_signed_release.py tests/test_artifacts.py
git commit -m "signing: verify signed fleur release artifacts"
```

---

### Task 6: Incremental Target-Files Runner and Documentation

**Files:**
- Create: `scripts/ubuntu/build_target_files.sh`
- Modify: `tests/test_scripts.py`
- Modify: `README.md`
- Modify: `docs/build-and-install.md`
- Modify: `docs/troubleshooting.md`

**Interfaces:**
- CLI: `build_target_files.sh [--dry-run] [--verbose] [--jobs N] [workspace]`.
- Produces: updated target-files and otatools plus timestamped log/metadata without cleaning.

- [ ] **Step 1: Add failing runner contract tests**

Assert dry-run output contains:

```text
source build/envsetup.sh
breakfast fleur
m target-files-package otatools -j8
```

Assert the script contains none of `m clean`, `installclean`, `rm -rf out`, or `ccache -C`.

- [ ] **Step 2: Verify failure**

```bash
python3 -m unittest tests.test_scripts.ScriptTest -v
```

Expected: FAIL because the runner is absent.

- [ ] **Step 3: Implement the runner**

Follow `build.sh`, source `lib/common.sh`, require ext4, set `SOONG_UI_NINJA_ARGS=-v` only for `--verbose`, zero ccache statistics without deleting cache, and execute:

```bash
m target-files-package otatools "-j$jobs"
```

Record start/end UTC, exit code, target-files path, size, SHA-256, manifest snapshot, memory/swap, disk, ccache summary, log path, and metadata path.

- [ ] **Step 4: Document the operator flow**

Document SKU mapping, unchanged codename, one-time key generation, key custody, incremental build, signing, verification, clean install, optional key migration, lost-key recovery, and the prohibition on publishing secrets.

- [ ] **Step 5: Validate and commit**

```bash
python3 -m unittest discover -s tests -v
bash -n scripts/ubuntu/build_target_files.sh
shellcheck -x -P scripts/ubuntu scripts/ubuntu/*.sh scripts/ubuntu/lib/*.sh
git add scripts/ubuntu/build_target_files.sh tests/test_scripts.py \
  README.md docs/build-and-install.md docs/troubleshooting.md
git commit -m "docs: add signed fleur release workflow"
```

---

### Task 7: Apply Identity Patch and Build New Target-Files

**Files:**
- Modify in Android tree: `device/xiaomi/fleur/sku/build_{fleur,miel,fleurp,mielp}.prop`
- Create locally: build log, metadata, and refreshed target-files under ignored output paths.

**Interfaces:**
- Consumes: patch 0006, Android tree, existing `out`, ccache, and `-j8`.
- Produces: refreshed unsigned target-files containing the approved SKU mapping.

- [ ] **Step 1: Verify preconditions without cleaning**

```bash
cd /home/administrator/src/flowerbed
python3 -m unittest discover -s tests -v
scripts/ubuntu/apply_patches.sh /home/administrator/android/lineage-23.2
git -C /home/administrator/android/lineage-23.2/device/xiaomi/fleur diff --check
```

Expected: all tests pass and all six patches are applied or already applied.

- [ ] **Step 2: Run the visible incremental build**

```bash
scripts/ubuntu/build_target_files.sh --verbose --jobs 8 /home/administrator/android/lineage-23.2
```

Expected: exit 0. On failure, preserve `out` and ccache, diagnose the first causal error, and resume incrementally.

- [ ] **Step 3: Verify built properties**

```bash
TARGET_FILES=/home/administrator/android/lineage-23.2/out/target/product/fleur/obj/PACKAGING/target_files_intermediates/lineage_fleur-target_files.zip
test -f "$TARGET_FILES"
unzip -p "$TARGET_FILES" ODM/etc/build_fleur.prop
unzip -p "$TARGET_FILES" ODM/etc/build_miel.prop
unzip -p "$TARGET_FILES" ODM/etc/build_fleurp.prop
unzip -p "$TARGET_FILES" ODM/etc/build_mielp.prop
unzip -p "$TARGET_FILES" META/misc_info.txt | grep '^avb_'
```

Expected: approved mappings exist; target and partition identity remain `fleur`.

- [ ] **Step 4: Record input checksum and source revisions**

```bash
sha256sum "$TARGET_FILES"
repo manifest -r > /home/administrator/src/flowerbed/manifests/snapshots/"$(date -u +%Y%m%dT%H%M%SZ)"-signed-release.xml
```

---

### Task 8: Generate Keys, Sign, Verify, and Export

**Files:**
- Create privately: `/home/administrator/.android-certs/fleur-release/`
- Create locally: `/home/administrator/android/lineage-23.2/out/signed-fleur/$BUILD_ID/`
- Copy verified public artifacts to: `C:\output\lineage-23.2-$BUILD_ID-SIGNED-fleur\`

**Interfaces:**
- Consumes: refreshed target-files and Tasks 2-6 tooling.
- Produces: two signed ZIPs, public cert bundle, checksums, and sanitized reports.

- [ ] **Step 1: Generate the key lineage in the visible Ubuntu terminal**

```bash
cd /home/administrator/src/flowerbed
TARGET_FILES=/home/administrator/android/lineage-23.2/out/target/product/fleur/obj/PACKAGING/target_files_intermediates/lineage_fleur-target_files.zip
BUILD_ID="$(date -u +%Y%m%dT%H%M%SZ)"
SIGNED_OUTPUT="/home/administrator/android/lineage-23.2/out/signed-fleur/$BUILD_ID"
python3 scripts/ubuntu/generate_release_keys.py \
  --target-files "$TARGET_FILES" \
  --android-root /home/administrator/android/lineage-23.2 \
  --keys-dir /home/administrator/.android-certs/fleur-release \
  --subject '/C=GE/ST=Tbilisi/L=Tbilisi/O=flowerbed/OU=Android/CN=fleur release/emailAddress=android@localhost'
```

Expected: the user enters and confirms the passphrase directly in Ubuntu; it never appears in logs. Existing valid keys are reused.

- [ ] **Step 2: Sign from one target-files ZIP**

```bash
python3 scripts/ubuntu/sign_release.py \
  --target-files "$TARGET_FILES" \
  --android-root /home/administrator/android/lineage-23.2 \
  --keys-dir /home/administrator/.android-certs/fleur-release \
  --output-dir "$SIGNED_OUTPUT"
```

Expected: original artifacts remain unchanged.

- [ ] **Step 3: Verify**

```bash
SIGNED_TARGET_FILES="$SIGNED_OUTPUT/lineage_fleur-SIGNED-target_files.zip"
SIGNED_OTA="$SIGNED_OUTPUT/lineage-23.2-$BUILD_ID-SIGNED-fleur.zip"
SIGNED_FASTBOOT="$SIGNED_OUTPUT/lineage_fleur-SIGNED-img.zip"
PUBLIC_KEYS="$SIGNED_OUTPUT/public-keys"
python3 scripts/ubuntu/verify_signed_release.py \
  --unsigned-target-files "$TARGET_FILES" \
  --signed-target-files "$SIGNED_TARGET_FILES" \
  --ota "$SIGNED_OTA" \
  --fastboot "$SIGNED_FASTBOOT" \
  --public-keys "$PUBLIC_KEYS" \
  --android-root /home/administrator/android/lineage-23.2 \
  --firmware-manifest sources/firmware.json \
  --report "$SIGNED_OUTPUT/verification-report.json"
```

Expected: all checks pass; any failure blocks export.

- [ ] **Step 4: Export only verified public artifacts**

Copy the Recovery OTA, fastboot ZIP, public certificates/AVB keys, `SHA256SUMS`, signing report, verification report, and pinned manifest to `C:\output\lineage-23.2-$BUILD_ID-SIGNED-fleur\`. Recompute Windows SHA-256 and compare. Assert no `.pk8`, private `.pem`, `passwords`, or private `keyset.json` is exported.

---

### Task 9: Final Review, Wiki, and Publication

**Files:**
- Modify: Russian GitHub Wiki signing guide and navigation.
- Modify: sanitized release report and source snapshot references.

**Interfaces:**
- Consumes: verified artifacts, reports, final Git diff, public fingerprints.
- Produces: reviewed repository/Wiki commits and exact artifact handoff.

- [ ] **Step 1: Run final checks**

```bash
python3 -m unittest discover -s tests -v
shellcheck -x -P scripts/ubuntu scripts/ubuntu/*.sh scripts/ubuntu/lib/*.sh
git diff --check
git status --short
```

Expected: tests pass and only intended paths remain.

- [ ] **Step 2: Inspect staged content for secrets**

```bash
git diff --cached --name-status
git diff --cached
git grep -nE 'BEGIN (RSA |ENCRYPTED )?PRIVATE KEY|[[[[^]]+]]]' -- ':!docs/superpowers/plans/*'
```

Expected: no private key, password, IMEI, serial number, binary artifact, or unrelated log is staged.

- [ ] **Step 3: Update the Russian Wiki**

Cover market-name selection, unchanged codename, release-key custody, signing, verification, clean installation, optional migration, lost-key recovery, and self-signed versus official LineageOS.

- [ ] **Step 4: Commit repository and Wiki separately**

Stage exact paths only and use repository-consistent messages. Preserve existing logs, binaries, caches, and unrelated changes.

- [ ] **Step 5: Push after remote verification**

Verify `origin` is `https://github.com/noteMASTER11/flowerbed.git`, inspect the outgoing commit range, push source/documentation and Wiki commits, then verify remote hashes and pages. Never upload private keys or label artifacts device-validated before hardware testing.

- [ ] **Step 6: Report handoff**

Report Windows paths, sizes, SHA-256 hashes, public signing fingerprints, source commit, checks performed, migration requirements, and remaining hardware-validation limitations.
