# LineageOS 23.2 for fleur Implementation Plan

> **For implementers:** Execute the tasks sequentially and stop at the stated verification checkpoints. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build, verify, device-test, and publish a reproducible unofficial LineageOS 23.2 ZIP for Xiaomi `fleur` from pinned source revisions.

**Architecture:** Build natively inside the Ubuntu WSL2 ext4 filesystem. The repository provides a pinned local manifest, small fail-fast shell entry points, Python verification tools, provenance records, and operator documentation; the Android source tree, logs, device data, and binary artifacts remain outside Git. The pinned vendor tree contributes eleven firmware partitions to the standard Virtual A/B payload. The pipeline progresses through source validation, sync, compilation, static payload and firmware checks, explicit-approval device testing, and release publication.

**Tech Stack:** Ubuntu WSL2, Bash, Python 3 standard library, Git, Git LFS, Android `repo`, LineageOS 23.2 build system, `ccache`, ADB/Fastboot, GitHub CLI, GitHub Actions.

**Spec:** `docs/superpowers/specs/2026-08-27-lineageos-23-2-fleur-build-design.md`

## Global Constraints

- Target `LineageOS/android` branch `lineage-23.2`.
- Initial build uses the unmodified `mt6781-devs` kernel, without KernelSU, SUSFS, Magisk, GApps, spoofing, or performance patches.
- Android sources and build output must reside inside the Ubuntu ext4 filesystem, never under `/mnt/c` or `/mnt/d`.
- The build product is `lineage_fleur-userdebug`; use `breakfast fleur` followed by `m bacon`.
- Candidate device-specific revisions are pinned by full Git SHA in `manifests/fleur-lineage-23.2.xml`.
- Retain the firmware images and `AB_OTA_PARTITIONS` declarations from the pinned `z3rh0/proprietary_vendor_xiaomi_fleur` commit; do not wrap or rewrite the generated OTA ZIP.
- The payload must contain `audio_dsp`, `gz`, `lk`, `logo`, `md1img`, `pi_img`, `preloader_raw`, `scp`, `spmfw`, `sspm`, and `tee`.
- Export a complete `repo manifest -r` snapshot for every build attempt whose result is reported.
- Long-running commands must stream to the visible terminal and a timestamped log simultaneously.
- Do not commit ROM ZIPs, Android source trees, build output, logs containing private paths or device data, IMEI data, serial numbers, tokens, cookies, signing keys, or backups.
- Any wipe, sideload, partition flash, or recovery action requires explicit user confirmation immediately before execution.
- A ZIP remains `experimental` until it boots on a physical `fleur` and passes the smoke test.
- Repository-owned source and documentation are English.
- Host-specific machine administration remains private and outside this repository.

---

## Planned File Map

| File | Responsibility |
| --- | --- |
| `README.md` | Entry point, status, supported devices, safety boundary, and command index. |
| `.gitignore` | Exclude local build, log, artifact, cache, and private-device data. |
| `manifests/fleur-lineage-23.2.xml` | Candidate pinned device/vendor/kernel/hardware/sepolicy revisions. |
| `manifests/snapshots/.gitkeep` | Keep the directory used for successful revision-pinned repo snapshots. |
| `sources/provenance.json` | Structured source-set evidence and recency classification. |
| `sources/firmware.json` | Pinned firmware partition hashes and Global/India provenance discrepancy. |
| `scripts/ubuntu/lib/common.sh` | Shared logging, command checks, workspace guards, and path resolution. |
| `scripts/ubuntu/bootstrap.sh` | Print or install Ubuntu build packages and initialize `repo`/`ccache`. |
| `scripts/ubuntu/sync.sh` | Initialize LineageOS 23.2, install the local manifest, sync, and export a snapshot. |
| `scripts/ubuntu/build.sh` | Select `fleur`, run the build visibly, and record build metadata. |
| `scripts/ubuntu/verify_artifacts.py` | Validate OTA ZIP structure/metadata, inspect and extract payload firmware, compare hashes, and generate SHA-256 records. |
| `scripts/ubuntu/collect_device_logs.sh` | Collect non-destructive preflight and boot diagnostics into an ignored private directory. |
| `scripts/render_provenance.py` | Validate provenance JSON and render its public Markdown table. |
| `docs/source-provenance.md` | Human-readable source map generated from structured data. |
| `docs/build-and-install.md` | Reproducible build commands and gated install procedure. |
| `docs/device-validation.md` | ADB and physical smoke-test protocol. |
| `docs/troubleshooting.md` | Evidence-first handling for sync, build, boot, and recovery failures. |
| `reports/build-report.md` | Sanitized result of the successful build. |
| `reports/device-validation.md` | Sanitized physical-device validation result. |
| `tests/test_manifest.py` | Exact manifest repository/path/revision contract. |
| `tests/test_provenance.py` | Provenance schema, statuses, evidence URLs, and renderer tests. |
| `tests/test_scripts.py` | Dry-run and fail-fast behavior of shell entry points. |
| `tests/test_artifacts.py` | OTA metadata, payload, firmware partition/hash, target-device, and checksum tests. |
| `.github/workflows/validate.yml` | Run unit tests, XML validation, Bash syntax checks, and ShellCheck. |

## Task 1: Establish the Public Repository Contract

**Files:**
- Create: `README.md`
- Create: `.gitignore`
- Create: `tests/test_repository.py`
- Create: `manifests/snapshots/.gitkeep`

**Interfaces:**
- Consumes: Approved design in `docs/superpowers/specs/2026-08-27-lineageos-23-2-fleur-build-design.md`.
- Produces: Repository safety contract and ignored local paths used by every later task.

- [ ] **Step 1: Write the failing repository contract test**

```python
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


class RepositoryContractTest(unittest.TestCase):
    def test_readme_declares_target_and_experimental_gate(self):
        text = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn("LineageOS 23.2", text)
        self.assertIn("fleur", text)
        self.assertIn("experimental until device validation passes", text.lower())

    def test_private_and_large_outputs_are_ignored(self):
        patterns = set((ROOT / ".gitignore").read_text(encoding="utf-8").splitlines())
        self.assertTrue({"artifacts/", "logs/", "reports/private/", ".cache/"} <= patterns)

    def test_no_public_host_administration_script(self):
        public_scripts = [path.as_posix() for path in (ROOT / "scripts").rglob("*") if path.is_file()]
        self.assertFalse(any("move-wsl" in path.lower() for path in public_scripts))


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run the test and verify that repository files are missing**

Run: `python3 -m unittest tests.test_repository -v`

Expected: FAIL because `README.md` and `.gitignore` do not exist.

- [ ] **Step 3: Create the minimal repository contract**

`README.md` must state:

```markdown
# flowerbed

Reproducible build and validation tooling for an unofficial LineageOS 23.2 build for Xiaomi Redmi Note 11S 4G and POCO M4 Pro 4G (`fleur`).

The ROM is experimental until device validation passes. No build from this repository is official LineageOS software.

## Safety

Building is non-destructive. Flashing, sideloading, formatting data, and changing partitions are separate operations that require an unlocked bootloader, a verified backup, and explicit action-time approval.

## Repository contents

- `manifests/`: pinned device source revisions and successful build snapshots.
- `scripts/ubuntu/`: environment, sync, build, artifact, and diagnostic tools.
- `docs/`: provenance, build, validation, and troubleshooting records.
- `reports/`: sanitized build and device-validation results.
```

`.gitignore` must contain:

```gitignore
artifacts/
logs/
reports/private/
.cache/
__pycache__/
*.pyc
*.log
*.img
*.zip
*.tar
*.tar.gz
*.tar.xz
*.vhd
*.vhdx
```

Create `manifests/snapshots/.gitkeep` as an empty tracked file.

- [ ] **Step 4: Run the repository contract test**

Run: `python3 -m unittest tests.test_repository -v`

Expected: 3 tests PASS.

- [ ] **Step 5: Commit the repository contract**

```bash
git add README.md .gitignore tests/test_repository.py manifests/snapshots/.gitkeep
git commit -m "chore: establish fleur build repository contract"
```

## Task 2: Add the Exact Candidate Source Manifest

**Files:**
- Create: `manifests/fleur-lineage-23.2.xml`
- Create: `tests/test_manifest.py`

**Interfaces:**
- Consumes: Candidate revisions approved in the design specification.
- Produces: `manifests/fleur-lineage-23.2.xml`, consumed by `scripts/ubuntu/sync.sh`.

- [ ] **Step 1: Write the failing manifest test**

```python
from pathlib import Path
import re
import unittest
import xml.etree.ElementTree as ET


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "manifests" / "fleur-lineage-23.2.xml"
EXPECTED = {
    "device/xiaomi/fleur": ("mt6781-devs/android_device_xiaomi_fleur", "45289f6f6e94fc90870d27477d42a89c735fcff5"),
    "vendor/xiaomi/fleur": ("z3rh0/proprietary_vendor_xiaomi_fleur", "9430b0e8c9e7915fcac5257c21d1c539acaf94c6"),
    "kernel/xiaomi/mt6781": ("mt6781-devs/android_kernel_xiaomi_mt6781", "9996b68a1808b38f2f9e7798b26479e721bc2a84"),
    "hardware/mediatek": ("mt6781-devs/android_hardware_mediatek", "8d18fc6d5b3a63fe2abf9e935947f71c484db291"),
    "device/mediatek/sepolicy_vndr": ("mt6781-devs/android_device_mediatek_sepolicy_vndr", "dc6d099b7a1b85a38151b80e675684888ef22683"),
}


class ManifestTest(unittest.TestCase):
    def test_exact_projects_and_full_sha_pins(self):
        root = ET.parse(MANIFEST).getroot()
        projects = {item.attrib["path"]: (item.attrib["name"], item.attrib["revision"]) for item in root.findall("project")}
        self.assertEqual(EXPECTED, projects)
        for _, revision in projects.values():
            self.assertRegex(revision, re.compile(r"^[0-9a-f]{40}$"))

    def test_github_remote_is_https(self):
        root = ET.parse(MANIFEST).getroot()
        remote = root.find("remote[@name='github']")
        self.assertIsNotNone(remote)
        self.assertEqual("https://github.com/", remote.attrib["fetch"])


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run the test and verify that the manifest is absent**

Run: `python3 -m unittest tests.test_manifest -v`

Expected: FAIL with `FileNotFoundError` for `manifests/fleur-lineage-23.2.xml`.

- [ ] **Step 3: Add the candidate manifest**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<manifest>
  <remote name="github" fetch="https://github.com/" />
  <project path="device/xiaomi/fleur" name="mt6781-devs/android_device_xiaomi_fleur" remote="github" revision="45289f6f6e94fc90870d27477d42a89c735fcff5" />
  <project path="vendor/xiaomi/fleur" name="z3rh0/proprietary_vendor_xiaomi_fleur" remote="github" revision="9430b0e8c9e7915fcac5257c21d1c539acaf94c6" />
  <project path="kernel/xiaomi/mt6781" name="mt6781-devs/android_kernel_xiaomi_mt6781" remote="github" revision="9996b68a1808b38f2f9e7798b26479e721bc2a84" />
  <project path="hardware/mediatek" name="mt6781-devs/android_hardware_mediatek" remote="github" revision="8d18fc6d5b3a63fe2abf9e935947f71c484db291" />
  <project path="device/mediatek/sepolicy_vndr" name="mt6781-devs/android_device_mediatek_sepolicy_vndr" remote="github" revision="dc6d099b7a1b85a38151b80e675684888ef22683" />
</manifest>
```

- [ ] **Step 4: Validate the manifest**

Run: `python3 -m unittest tests.test_manifest -v && xmllint --noout manifests/fleur-lineage-23.2.xml`

Expected: 2 tests PASS and `xmllint` exits 0.

- [ ] **Step 5: Verify that every pinned revision is remotely reachable**

Run:

```bash
check_dir="$(mktemp -d)"
trap 'rm -rf -- "$check_dir"' EXIT
while read -r repository revision; do
  rm -rf -- "$check_dir/repository"
  git init -q "$check_dir/repository"
  git -C "$check_dir/repository" fetch -q --depth=1 "https://github.com/${repository}.git" "$revision"
  test "$(git -C "$check_dir/repository" rev-parse FETCH_HEAD)" = "$revision"
done <<'EOF'
mt6781-devs/android_device_xiaomi_fleur 45289f6f6e94fc90870d27477d42a89c735fcff5
z3rh0/proprietary_vendor_xiaomi_fleur 9430b0e8c9e7915fcac5257c21d1c539acaf94c6
mt6781-devs/android_kernel_xiaomi_mt6781 9996b68a1808b38f2f9e7798b26479e721bc2a84
mt6781-devs/android_hardware_mediatek 8d18fc6d5b3a63fe2abf9e935947f71c484db291
mt6781-devs/android_device_mediatek_sepolicy_vndr dc6d099b7a1b85a38151b80e675684888ef22683
EOF
```

Expected: exit 0 only when every exact SHA is reachable and fetchable from its remote. During source sync, `repo` performs the definitive object checkout verification.

- [ ] **Step 6: Commit the manifest**

```bash
git add manifests/fleur-lineage-23.2.xml tests/test_manifest.py
git commit -m "build: pin LineageOS 23.2 fleur source set"
```

## Task 3: Record and Validate Source Provenance

**Files:**
- Create: `sources/provenance.json`
- Create: `sources/firmware.json`
- Create: `scripts/render_provenance.py`
- Create: `tests/test_provenance.py`
- Create: `docs/source-provenance.md`

**Interfaces:**
- Consumes: GitHub repositories, releases, commit history, the Xiaomi Firmware Updater `fleur` archive, XDA results, and the 4PDA `fleur` firmware topic inspected on 2026-08-27.
- Produces: Validated structured evidence, pinned firmware hashes, and a deterministic Markdown source map.

- [ ] **Step 1: Write the failing provenance tests**

```python
from pathlib import Path
import importlib.util
import json
import unittest


ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "sources" / "provenance.json"
FIRMWARE = ROOT / "sources" / "firmware.json"
EXPECTED_FIRMWARE = {
    "audio_dsp", "gz", "lk", "logo", "md1img", "pi_img",
    "preloader_raw", "scp", "spmfw", "sspm", "tee",
}


class ProvenanceTest(unittest.TestCase):
    def test_records_have_supported_status_and_https_evidence(self):
        payload = json.loads(DATA.read_text(encoding="utf-8"))
        self.assertEqual(1, payload["schemaVersion"])
        self.assertGreaterEqual(len(payload["sourceSets"]), 3)
        allowed = {"verified-current", "candidate-current", "historical", "modified", "unknown"}
        for item in payload["sourceSets"]:
            self.assertIn(item["status"], allowed)
            self.assertTrue(item["evidence"])
            self.assertTrue(all(url.startswith("https://") for url in item["evidence"]))
            self.assertEqual(len(item["repositories"]), len({repo["path"] for repo in item["repositories"]}))

    def test_renderer_is_deterministic(self):
        spec = importlib.util.spec_from_file_location("render_provenance", ROOT / "scripts" / "render_provenance.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        first = module.render(DATA, FIRMWARE)
        second = module.render(DATA, FIRMWARE)
        self.assertEqual(first, second)
        self.assertIn("mt6781-devs/android_device_xiaomi_fleur", first)
        self.assertIn("StasGr12/Infinity-X-Fleur", first)
        self.assertIn("OS1.0.10.0.TKEINXM", first)
        self.assertIn("preloader_raw", first)

    def test_firmware_registry_is_exact_and_pinned(self):
        payload = json.loads(FIRMWARE.read_text(encoding="utf-8"))
        self.assertEqual(1, payload["schemaVersion"])
        self.assertEqual("fleur", payload["device"])
        self.assertEqual("9430b0e8c9e7915fcac5257c21d1c539acaf94c6", payload["vendorRevision"])
        partitions = {item["name"]: item for item in payload["partitions"]}
        self.assertEqual(EXPECTED_FIRMWARE, set(partitions))
        self.assertTrue(all(len(item["sha256"]) == 64 for item in partitions.values()))
        self.assertEqual(10, sum(item["xfuPrefixMatch"] is True for item in partitions.values()))
        self.assertIsNone(partitions["logo"]["xfuPrefixMatch"])
        self.assertEqual("OS1.0.10.0.TKEINXM", payload["archivePackage"]["version"])
        self.assertEqual(64, len(payload["archivePackage"]["sha256"]))


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run the tests and verify missing data and renderer failures**

Run: `python3 -m unittest tests.test_provenance -v`

Expected: FAIL because `sources/provenance.json` and `scripts/render_provenance.py` do not exist.

- [ ] **Step 3: Create the structured provenance registry**

Use this exact top-level shape:

```json
{
  "schemaVersion": 1,
  "retrievedAt": "2026-08-27",
  "sourceSets": [
    {
      "id": "lineage-23.2-baseline",
      "rom": "LineageOS 23.2 candidate baseline",
      "status": "candidate-current",
      "repositories": [
        {"path": "device/xiaomi/fleur", "repository": "mt6781-devs/android_device_xiaomi_fleur", "revision": "45289f6f6e94fc90870d27477d42a89c735fcff5"},
        {"path": "vendor/xiaomi/fleur", "repository": "z3rh0/proprietary_vendor_xiaomi_fleur", "revision": "9430b0e8c9e7915fcac5257c21d1c539acaf94c6"},
        {"path": "kernel/xiaomi/mt6781", "repository": "mt6781-devs/android_kernel_xiaomi_mt6781", "revision": "9996b68a1808b38f2f9e7798b26479e721bc2a84"},
        {"path": "hardware/mediatek", "repository": "mt6781-devs/android_hardware_mediatek", "revision": "8d18fc6d5b3a63fe2abf9e935947f71c484db291"},
        {"path": "device/mediatek/sepolicy_vndr", "repository": "mt6781-devs/android_device_mediatek_sepolicy_vndr", "revision": "dc6d099b7a1b85a38151b80e675684888ef22683"}
      ],
      "evidence": [
        "https://github.com/mt6781-devs/android_device_xiaomi_fleur",
        "https://github.com/z3rh0/proprietary_vendor_xiaomi_fleur"
      ],
      "notes": "Clean candidate baseline; build and device validation not yet established."
    },
    {
      "id": "infinity-x-3.12-v3",
      "rom": "Project Infinity X 3.12 v3",
      "status": "modified",
      "repositories": [
        {"path": "device/xiaomi/fleur", "repository": "mt6781-devs/android_device_xiaomi_fleur", "revision": "lineage-23.2"},
        {"path": "vendor/xiaomi/fleur", "repository": "z3rh0/proprietary_vendor_xiaomi_fleur", "revision": "lineage-23.2"},
        {"path": "kernel/xiaomi/mt6781", "repository": "StasGr12/android_kernel_xiaomi_mt6781", "revision": "lineage-23.2-ksun-susfs"}
      ],
      "evidence": [
        "https://github.com/StasGr12/Infinity-X-Fleur",
        "https://github.com/StasGr12/Infinity-X-Fleur/releases/tag/v3.12-v3"
      ],
      "notes": "Recent device evidence with KernelSU/SUSFS; not used for the clean baseline."
    },
    {
      "id": "lineage-20-historical",
      "rom": "LineageOS 20 historical tree",
      "status": "historical",
      "repositories": [
        {"path": "device/xiaomi/fleur", "repository": "xiaomi-mt6781-fleur-dev/android_device_xiaomi_fleur", "revision": "lineage-20.0"}
      ],
      "evidence": [
        "https://github.com/xiaomi-mt6781-fleur-dev/android_device_xiaomi_fleur"
      ],
      "notes": "Historical dependency and partition-layout reference only."
    }
  ]
}
```

Create `sources/firmware.json` with this exact contract and the hashes measured from the pinned vendor tree:

```json
{
  "schemaVersion": 1,
  "device": "fleur",
  "vendorRepository": "z3rh0/proprietary_vendor_xiaomi_fleur",
  "vendorRevision": "9430b0e8c9e7915fcac5257c21d1c539acaf94c6",
  "archivePackage": {
    "version": "OS1.0.10.0.TKEINXM",
    "region": "India",
    "filename": "fw_fleur_miui_FLEURINGlobal_OS1.0.10.0.TKEINXM_8680e64fbe_13.0.zip",
    "url": "https://github.com/XiaomiFirmwareUpdaterReleases/firmware_xiaomi_fleur/releases/download/stable-28.12.2024/fw_fleur_miui_FLEURINGlobal_OS1.0.10.0.TKEINXM_8680e64fbe_13.0.zip",
    "sha256": "ece414deac942f8fc55bcb8f1ece0b386feca4a0088cc1bf125fe59c87844fc6"
  },
  "partitions": [
    {"name": "audio_dsp", "file": "radio/audio_dsp.img", "size": 822000, "sha256": "ada0e592f8aebe7fd5ef62298397b2fcbd2d5dfc9557e80b7d6c2df074833238", "xfuPrefixMatch": true},
    {"name": "gz", "file": "radio/gz.img", "size": 2877248, "sha256": "10115cb17768ed54f8f4c8f654b15d6bc6a622f4a42a8a6c84c1f381b934e489", "xfuPrefixMatch": true},
    {"name": "lk", "file": "radio/lk.img", "size": 1688704, "sha256": "5ae6e6ba6267532b8d766a3ee12f92b902eec2e5b0f94839fbac2ba699b5c44c", "xfuPrefixMatch": true},
    {"name": "logo", "file": "radio/logo.img", "size": 4140736, "sha256": "f34e0bcd2a07c5c39b7e27299e7e9ce4a39a044f83f9c98b9a687bb471a1e88b", "xfuPrefixMatch": null},
    {"name": "md1img", "file": "radio/md1img.img", "size": 53395200, "sha256": "e3383a8e7a1eb471f3b85469ceec75051d4a3cdb9991fbe02764a9ffdf005c9e", "xfuPrefixMatch": true},
    {"name": "pi_img", "file": "radio/pi_img.img", "size": 5328, "sha256": "3d5ac0658abbf10da2b1578d21a73defae3cc4c169cc5b552add368acadec0e7", "xfuPrefixMatch": true},
    {"name": "preloader_raw", "file": "radio/preloader_raw.img", "size": 360920, "sha256": "8e3755f74ebcb05849715e217d425fa559a4904f246945d89e5078836aa055df", "xfuPrefixMatch": true},
    {"name": "scp", "file": "radio/scp.img", "size": 871456, "sha256": "a3d16cb458b2975e62e5fe689f36445f06ca24c06bcf500cc4d3e8ea85aec740", "xfuPrefixMatch": true},
    {"name": "spmfw", "file": "radio/spmfw.img", "size": 16672, "sha256": "dc3c8ef2b18a160a1210aea0485082c0806fd4b1f7a1bfd2bd267179214e846b", "xfuPrefixMatch": true},
    {"name": "sspm", "file": "radio/sspm.img", "size": 676720, "sha256": "b2859cd77c1392766f0b46c91aec573f341ddb51d21db8455f2de14b345bce36", "xfuPrefixMatch": true},
    {"name": "tee", "file": "radio/tee.img", "size": 2614496, "sha256": "92366b832392468411018ce4e46a41bcdba430b6de06d57d2d34b39d911defaf", "xfuPrefixMatch": true}
  ],
  "metadataDiscrepancy": "The device-tree comment names Global V816.0.9.0.TKEMIXM, while ten current vendor images match the archived India OS1.0.10.0.TKEINXM package after trailing-padding normalization; logo.img is present only in the pinned vendor comparison set."
}
```

Add further source sets only when a repository or release provides traceable device/vendor/kernel evidence. In the generated report, record these bounded negative findings rather than fabricating source sets: no current XDA `fleur` LineageOS 23.x source/build thread was located; the 4PDA topic header inspected at page offset `st=2620` lists current Android 16 ROMs but not LineageOS 23.x, and the topic search returned no LineageOS 23.1 result. Also link the complete `fleur` firmware archive and state that the standalone XFU script writes ten A/B firmware partitions directly without mounting them.

- [ ] **Step 4: Implement deterministic rendering**

`scripts/render_provenance.py` must expose `render(path: Path, firmware_path: Path) -> str`, sort source sets by `id`, sort repositories by `path`, and render columns `ID`, `ROM`, `Status`, `Repositories`, `Evidence`, and `Notes`. After the source-set table it renders the firmware version, pinned vendor revision, archive checksum, eleven partition hashes, metadata discrepancy, and bounded XDA/4PDA findings. Its CLI accepts `--firmware`, writes to stdout unless `--output` is supplied, and performs no network access.

```python
def render(path: Path, firmware_path: Path) -> str:
    payload = json.loads(path.read_text(encoding="utf-8"))
    firmware = json.loads(firmware_path.read_text(encoding="utf-8"))
    rows = []
    for item in sorted(payload["sourceSets"], key=lambda value: value["id"]):
        repos = "<br>".join(
            f"`{repo['path']}` → `{repo['repository']}@{repo['revision']}`"
            for repo in sorted(item["repositories"], key=lambda value: value["path"])
        )
        evidence = "<br>".join(f"[source {index}]({url})" for index, url in enumerate(item["evidence"], 1))
        rows.append(f"| `{item['id']}` | {item['rom']} | `{item['status']}` | {repos} | {evidence} | {item['notes']} |")
    return "\n".join([
        "# fleur source provenance",
        "",
        f"Retrieved: {payload['retrievedAt']}",
        "",
        "| ID | ROM | Status | Repositories | Evidence | Notes |",
        "| --- | --- | --- | --- | --- | --- |",
        *rows,
        "",
        "## Firmware payload",
        "",
        f"Pinned vendor: `{firmware['vendorRepository']}@{firmware['vendorRevision']}`",
        f"Archive match: `{firmware['archivePackage']['version']}` ({firmware['archivePackage']['region']})",
        "",
    ])
```

- [ ] **Step 5: Render and test the report**

Run:

```bash
python3 scripts/render_provenance.py sources/provenance.json --firmware sources/firmware.json --output docs/source-provenance.md
python3 -m unittest tests.test_provenance -v
git diff --exit-code -- docs/source-provenance.md || true
```

Expected: 2 tests PASS. Re-running the renderer produces no diff.

- [ ] **Step 6: Commit provenance records**

```bash
git add sources/provenance.json sources/firmware.json scripts/render_provenance.py tests/test_provenance.py docs/source-provenance.md
git commit -m "docs: map fleur ROM source provenance"
```

## Task 4: Implement Shared Guards and Ubuntu Bootstrap

**Files:**
- Create: `scripts/ubuntu/lib/common.sh`
- Create: `scripts/ubuntu/bootstrap.sh`
- Create: `tests/test_scripts.py`

**Interfaces:**
- Produces: `log`, `die`, `require_command`, `require_ext4_workspace`, and `resolve_repo_root` for all Bash entry points.
- Produces: `bootstrap.sh --print-packages`, `--dry-run`, and normal install modes.

- [ ] **Step 1: Write failing common/bootstrap tests**

```python
from pathlib import Path
import subprocess
import unittest


ROOT = Path(__file__).resolve().parents[1]


def run_script(relative, *args):
    return subprocess.run(
        ["bash", str(ROOT / relative), *args],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )


class ScriptTest(unittest.TestCase):
    def test_bootstrap_prints_required_packages_without_sudo(self):
        result = run_script("scripts/ubuntu/bootstrap.sh", "--print-packages")
        self.assertEqual(0, result.returncode, result.stdout)
        for package in (
            "bc", "bison", "build-essential", "ccache", "curl", "flex",
            "g++-multilib", "gcc-multilib", "git", "git-lfs", "gnupg",
            "gperf", "imagemagick", "lib32readline-dev", "lib32z1-dev",
            "libelf-dev", "liblz4-tool", "libncurses-dev", "libssl-dev",
            "libxml2", "libxml2-utils", "lzop", "pngcrush", "repo",
            "rsync", "schedtool", "squashfs-tools", "xsltproc", "zip",
            "zlib1g-dev",
        ):
            self.assertIn(package, result.stdout.split())

    def test_bootstrap_dry_run_does_not_install(self):
        result = run_script("scripts/ubuntu/bootstrap.sh", "--dry-run")
        self.assertEqual(0, result.returncode, result.stdout)
        self.assertIn("DRY-RUN sudo apt-get install", result.stdout)


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run tests and verify missing-script failures**

Run: `python3 -m unittest tests.test_scripts -v`

Expected: 2 tests FAIL because the scripts do not exist.

- [ ] **Step 3: Implement shared guards**

`common.sh` must contain:

```bash
#!/usr/bin/env bash
set -Eeuo pipefail

log() { printf '[%s] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"; }
die() { log "ERROR: $*" >&2; exit 1; }
require_command() { command -v "$1" >/dev/null 2>&1 || die "Missing command: $1"; }
resolve_repo_root() { cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd -P; }
require_ext4_workspace() {
  local path="$1" normalized filesystem
  normalized="$(realpath -m -- "$path")"
  [[ "$normalized" != /mnt/* ]] || die "Workspace must not be under /mnt"
  [[ -d "$normalized" ]] || die "Workspace does not exist: $normalized"
  filesystem="$(stat -f -c %T "$normalized")"
  [[ "$filesystem" == "ext2/ext3" || "$filesystem" == "ext2/ext3/ext4" ]] || die "Workspace must be on ext4, found: $filesystem"
}
```

- [ ] **Step 4: Implement bootstrap print/dry-run/install modes**

The package array must contain exactly the packages asserted by the test plus `python3`, `python-is-python3`, and `software-properties-common`. `--print-packages` prints one name per line. `--dry-run` prints the exact `add-apt-repository -y universe`, `apt-get update`, `apt-get install`, Git LFS, `repo`, and `ccache` commands. Normal mode enables Ubuntu Universe, refreshes package metadata, installs the explicit array with `sudo`, verifies `repo version`, `git lfs version`, and `ccache --version`, then exits nonzero if any tool is unavailable. If Ubuntu 26.04 has renamed or removed a package, preserve the failed `apt` evidence and update the array and its test together; do not silently omit a dependency.

- [ ] **Step 5: Run script validation**

Run:

```bash
python3 -m unittest tests.test_scripts -v
bash -n scripts/ubuntu/lib/common.sh scripts/ubuntu/bootstrap.sh
shellcheck scripts/ubuntu/lib/common.sh scripts/ubuntu/bootstrap.sh
```

Expected: tests PASS; Bash and ShellCheck exit 0.

- [ ] **Step 6: Commit bootstrap tooling**

```bash
git add scripts/ubuntu/lib/common.sh scripts/ubuntu/bootstrap.sh tests/test_scripts.py
git commit -m "build: add guarded Ubuntu bootstrap"
```

## Task 5: Implement Reproducible Source Sync

**Files:**
- Create: `scripts/ubuntu/sync.sh`
- Modify: `tests/test_scripts.py`

**Interfaces:**
- Consumes: `manifests/fleur-lineage-23.2.xml` and shared guards.
- Produces: initialized source tree, `.repo/local_manifests/fleur-lineage-23.2.xml`, and `manifests/snapshots/<UTC timestamp>.xml`.

- [ ] **Step 1: Add failing sync dry-run tests**

```python
    def test_sync_dry_run_contains_branch_manifest_and_snapshot(self):
        result = run_script("scripts/ubuntu/sync.sh", "--dry-run", "/tmp/flowerbed-lineage-test")
        self.assertEqual(0, result.returncode, result.stdout)
        self.assertIn("repo init -u https://github.com/LineageOS/android.git -b lineage-23.2", result.stdout)
        self.assertIn("fleur-lineage-23.2.xml", result.stdout)
        self.assertIn("repo sync", result.stdout)
        self.assertIn("repo manifest -r", result.stdout)

    def test_sync_rejects_windows_mount(self):
        result = run_script("scripts/ubuntu/sync.sh", "--validate-workspace", "/mnt/d/android")
        self.assertNotEqual(0, result.returncode)
        self.assertIn("must not be under /mnt", result.stdout)
```

- [ ] **Step 2: Run only the new sync tests**

Run: `python3 -m unittest tests.test_scripts.ScriptTest.test_sync_dry_run_contains_branch_manifest_and_snapshot tests.test_scripts.ScriptTest.test_sync_rejects_windows_mount -v`

Expected: FAIL because `scripts/ubuntu/sync.sh` does not exist.

- [ ] **Step 3: Implement sync modes**

`sync.sh` must:

1. Accept a workspace argument, defaulting to `${HOME}/android/lineage-23.2`.
2. In normal mode, create the workspace if absent and then reject `/mnt/*` and non-ext4 workspaces. Evaluate `--dry-run` before workspace existence or filesystem checks so its synthetic test path remains side-effect free.
3. Run `repo init -u https://github.com/LineageOS/android.git -b lineage-23.2 --git-lfs --no-clone-bundle`.
4. copy the repository manifest into `.repo/local_manifests/fleur-lineage-23.2.xml`.
5. run `repo sync -c --force-sync --optimized-fetch --prune --no-tags -j8`.
6. export `repo manifest -r` into a timestamped file under the repository's `manifests/snapshots/` directory.
7. write all output through `tee` to `logs/sync-<UTC timestamp>.log` outside the tracked tree or under an ignored path.
8. preserve the exact failing exit status with `set -o pipefail`.

The `--dry-run` mode prints each quoted command without creating or validating the workspace. The `--validate-workspace` mode runs only the path guard.

- [ ] **Step 4: Run sync tests and static checks**

Run:

```bash
python3 -m unittest tests.test_scripts -v
bash -n scripts/ubuntu/sync.sh
shellcheck scripts/ubuntu/sync.sh
```

Expected: all tests PASS and static checks exit 0.

- [ ] **Step 5: Commit sync tooling**

```bash
git add scripts/ubuntu/sync.sh tests/test_scripts.py
git commit -m "build: add reproducible LineageOS source sync"
```

## Task 6: Implement the Visible Build Runner

**Files:**
- Create: `scripts/ubuntu/build.sh`
- Modify: `tests/test_scripts.py`

**Interfaces:**
- Consumes: synced LineageOS workspace with the `fleur` local manifest.
- Produces: visible build, timestamped log, build metadata, OTA ZIP, and product images in Android `out/`.

- [ ] **Step 1: Add failing build-runner tests**

```python
    def test_build_dry_run_selects_fleur_and_bacon(self):
        result = run_script("scripts/ubuntu/build.sh", "--dry-run", "/tmp/flowerbed-lineage-test")
        self.assertEqual(0, result.returncode, result.stdout)
        self.assertIn("source build/envsetup.sh", result.stdout)
        self.assertIn("breakfast fleur", result.stdout)
        self.assertIn("m bacon -j", result.stdout)
        self.assertIn("USE_CCACHE=1", result.stdout)

    def test_build_rejects_zero_jobs(self):
        result = run_script("scripts/ubuntu/build.sh", "--dry-run", "--jobs", "0", "/tmp/flowerbed-lineage-test")
        self.assertNotEqual(0, result.returncode)
        self.assertIn("jobs must be a positive integer", result.stdout.lower())
```

- [ ] **Step 2: Run the new tests**

Run: `python3 -m unittest tests.test_scripts.ScriptTest.test_build_dry_run_selects_fleur_and_bacon tests.test_scripts.ScriptTest.test_build_rejects_zero_jobs -v`

Expected: FAIL because `scripts/ubuntu/build.sh` does not exist.

- [ ] **Step 3: Implement the build runner**

`build.sh` must:

- accept `--jobs N`, defaulting to 8;
- validate a positive integer job count;
- evaluate `--dry-run` before workspace existence, source-tree, filesystem, `ccache`, or Android tool checks;
- verify `build/envsetup.sh`, `device/xiaomi/fleur`, `vendor/xiaomi/fleur`, and `kernel/xiaomi/mt6781` exist;
- export `USE_CCACHE=1`, `CCACHE_EXEC="$(command -v ccache)"`, `BUILD_USERNAME=flowerbed`, and `BUILD_HOSTNAME=wsl2-builder`;
- run `ccache -M 100G` and `ccache -z` before the build;
- run `source build/envsetup.sh`, `breakfast fleur`, and `m bacon -jN` in one Bash process;
- stream stdout/stderr through `tee` to a timestamped log;
- record start/end UTC, job count, WSL kernel, Ubuntu release, Git revision snapshot path, exit code, and `ccache -s` in an ignored metadata file;
- return the build's true exit code.

- [ ] **Step 4: Run build-runner checks**

Run:

```bash
python3 -m unittest tests.test_scripts -v
bash -n scripts/ubuntu/build.sh
shellcheck scripts/ubuntu/build.sh
```

Expected: all tests PASS and static checks exit 0.

- [ ] **Step 5: Commit the build runner**

```bash
git add scripts/ubuntu/build.sh tests/test_scripts.py
git commit -m "build: add visible fleur build runner"
```

## Task 7: Implement OTA ZIP, Payload Firmware, and Checksum Verification

**Files:**
- Create: `scripts/ubuntu/verify_artifacts.py`
- Create: `tests/test_artifacts.py`

**Interfaces:**
- Consumes: OTA ZIP, optional `boot.img`, `sources/firmware.json`, and for full verification the synced Android tree with the official `payload_info.py` script and built `ota_extractor` host tool.
- Produces: JSON verification report on stdout, extracted-and-verified firmware evidence in a temporary directory, and a `SHA256SUMS` file beside the artifacts.

- [ ] **Step 1: Write failing artifact tests with synthetic ZIP and firmware fixtures**

Test the CLI structure checks plus importable pure functions. The test module must cover:

```python
EXPECTED_FIRMWARE = {
    "audio_dsp", "gz", "lk", "logo", "md1img", "pi_img",
    "preloader_raw", "scp", "spmfw", "sspm", "tee",
}


def make_ota(path: Path, metadata: str, include_payload: bool = True):
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("META-INF/com/android/metadata", metadata)
        if include_payload:
            archive.writestr("payload.bin", b"payload")
            archive.writestr("payload_properties.txt", "FILE_HASH=fake\n")
```

Required cases:

1. accept a synthetic `fleur` A/B ZIP, return JSON, and atomically write `SHA256SUMS`;
2. reject `pre-device=rosemary`;
3. reject a missing `payload.bin`;
4. parse all eleven partition names from representative official `payload_info.py` output lines such as `Number of "audio_dsp" ops`;
5. reject a payload partition set missing `preloader_raw`;
6. accept an extracted image whose prefix equals the pinned vendor file and whose remaining bytes are zero padding, while rejecting a non-zero or changed tail.

Import `verify_artifacts.py` with `importlib.util` for the pure parser and normalized-image tests. CLI tests invoke it through `subprocess` and do not require an Android checkout.

- [ ] **Step 2: Run artifact tests and verify the missing implementation failure**

Run: `python3 -m unittest tests.test_artifacts -v`

Expected: tests FAIL because the verifier does not exist.

- [ ] **Step 3: Implement basic OTA and checksum verification**

The verifier must always:

- open the ZIP with `zipfile.ZipFile` and run `testzip()`;
- require `META-INF/com/android/metadata`, `payload.bin`, and `payload_properties.txt`;
- parse metadata as `key=value` pairs;
- require `fleur` in the comma-separated `pre-device` set;
- require `ota-type=AB`;
- calculate SHA-256 using 1 MiB chunks;
- atomically write `SHA256SUMS` with the OTA and optional boot-image digests;
- print only a JSON result to stdout on success;
- print a concise error to stderr and exit 1 on validation failure.

Without `--android-top`, JSON must state `firmware.status = "not-run"`; this mode is for unit tests and preliminary ZIP checks and is not sufficient for the pre-flash gate.

- [ ] **Step 4: Implement the full payload firmware gate**

With `--android-top <path> --firmware-manifest <path>`, the verifier must:

1. require `<android-top>/system/update_engine/scripts/payload_info.py`, `<android-top>/out/host/linux-x86/bin/ota_extractor`, and `<android-top>/vendor/xiaomi/fleur/radio`;
2. extract `payload.bin` from the OTA into a private temporary directory;
3. run the official `payload_info.py` from the Android source root and parse its manifest partition names;
4. require the exact eleven firmware names from `sources/firmware.json` to be present in that manifest;
5. run the official host tool as `ota_extractor --payload=<payload> --output_dir=<dir> --partitions=<comma-separated names>`;
6. require one extracted image for every firmware partition;
7. verify each pinned vendor file's size and SHA-256 against `sources/firmware.json`;
8. verify that each extracted image begins with the complete pinned vendor image and contains only zero padding after that prefix;
9. report the eleven names, source hashes, extracted sizes, payload-info command, and `firmware.status = "verified"` in JSON;
10. delete the temporary extraction directory on both success and failure.

Do not download, substitute, or modify firmware in the verifier. A missing host tool must fail with the exact remediation command `m ota_extractor`.

- [ ] **Step 5: Run artifact tests**

Run: `python3 -m unittest tests.test_artifacts -v`

Expected: all six required cases PASS.

- [ ] **Step 6: Commit artifact verification**

```bash
git add scripts/ubuntu/verify_artifacts.py tests/test_artifacts.py
git commit -m "test: verify fleur OTA payload firmware"
```

## Task 8: Add Non-Destructive Device Diagnostics

**Files:**
- Create: `scripts/ubuntu/collect_device_logs.sh`
- Modify: `tests/test_scripts.py`

**Interfaces:**
- Consumes: authorized ADB device and output directory under `reports/private/`.
- Produces: private preflight/boot diagnostics without flashing, wiping, rebooting, or recording the device serial.

- [ ] **Step 1: Add failing diagnostic-script tests**

Create a temporary fake `adb` executable in the test. It must return `device` for `get-state`, canned values for `shell getprop`, and sample output for `logcat -d` and `shell dmesg`. Then assert:

```python
    def test_device_collection_is_non_destructive(self):
        script = (ROOT / "scripts/ubuntu/collect_device_logs.sh").read_text(encoding="utf-8")
        forbidden = ("fastboot flash", "adb sideload", "fastboot erase", "wipe data", "adb reboot")
        self.assertFalse(any(command in script for command in forbidden))

    def test_device_collection_dry_run_lists_only_read_commands(self):
        result = run_script("scripts/ubuntu/collect_device_logs.sh", "--dry-run", "reports/private/test")
        self.assertEqual(0, result.returncode, result.stdout)
        self.assertIn("adb shell getprop", result.stdout)
        self.assertIn("adb logcat -d", result.stdout)
        self.assertNotIn("get-serialno", result.stdout)
```

- [ ] **Step 2: Run new tests and verify failure**

Run: `python3 -m unittest tests.test_scripts.ScriptTest.test_device_collection_is_non_destructive tests.test_scripts.ScriptTest.test_device_collection_dry_run_lists_only_read_commands -v`

Expected: FAIL because the diagnostic script does not exist.

- [ ] **Step 3: Implement private diagnostic collection**

The script must require `adb get-state` to equal `device`, create the requested ignored directory with mode `0700`, and collect:

```text
adb shell getprop
adb shell getprop ro.boot.hwc
adb shell getprop ro.miui.build.region
adb shell cat /proc/cmdline
adb shell cat /proc/meminfo
adb shell df -h
adb shell getenforce
adb shell settings get global device_provisioned
adb shell settings get secure user_setup_complete
adb shell dumpsys battery
adb shell dumpsys SurfaceFlinger
adb shell dumpsys media.camera
adb shell ls -l /dev/block/bootdevice/by-name
adb logcat -b all -d -v threadtime
adb shell dmesg
```

Failure of a privileged command such as `dmesg` is recorded but does not erase earlier evidence. The script must never call `adb get-serialno`, reboot, sideload, fastboot, or change settings.

- [ ] **Step 4: Run script tests and ShellCheck**

Run:

```bash
python3 -m unittest tests.test_scripts -v
bash -n scripts/ubuntu/collect_device_logs.sh
shellcheck scripts/ubuntu/collect_device_logs.sh
```

Expected: all tests PASS and static checks exit 0.

- [ ] **Step 5: Commit diagnostic tooling**

```bash
git add scripts/ubuntu/collect_device_logs.sh tests/test_scripts.py
git commit -m "test: add private fleur device diagnostics"
```

## Task 9: Document Build, Installation, Validation, and Recovery

**Files:**
- Create: `docs/build-and-install.md`
- Create: `docs/device-validation.md`
- Create: `docs/troubleshooting.md`
- Modify: `README.md`
- Modify: `tests/test_repository.py`
- Create: `.github/workflows/validate.yml`

**Interfaces:**
- Consumes: all public scripts and their tested command-line interfaces.
- Produces: exact operator workflow and automated repository validation.

- [ ] **Step 1: Extend the repository test with documentation command checks**

```python
    def test_documented_entry_points_exist(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        expected = {
            "scripts/ubuntu/bootstrap.sh",
            "scripts/ubuntu/sync.sh",
            "scripts/ubuntu/build.sh",
            "scripts/ubuntu/verify_artifacts.py",
            "scripts/ubuntu/collect_device_logs.sh",
        }
        for path in expected:
            self.assertIn(path, readme)
            self.assertTrue((ROOT / path).is_file())

    def test_install_doc_contains_destructive_gate_and_recovery(self):
        text = (ROOT / "docs" / "build-and-install.md").read_text(encoding="utf-8").lower()
        self.assertIn("explicit confirmation", text)
        self.assertIn("factory reset", text)
        self.assertIn("known-good boot image", text)
        self.assertIn("official xiaomi fastboot rom", text)
```

- [ ] **Step 2: Run the new repository tests**

Run: `python3 -m unittest tests.test_repository -v`

Expected: FAIL because the documentation files and README command references are absent.

- [ ] **Step 3: Write exact build documentation**

`docs/build-and-install.md` must document:

1. supported models and `fleur` identity;
2. ext4/free-space preflight;
3. bootstrap, sync, build, and full payload/firmware-verification commands;
4. expected output paths under `out/target/product/fleur`;
5. pre-flash inventory and backup requirements;
6. recovery image preparation;
7. a clearly marked stop requiring explicit confirmation before factory reset, boot partition flashing, or ADB sideload;
8. the embedded India `OS1.0.10.0.TKEINXM` firmware baseline, all eleven payload partitions, and the upstream metadata discrepancy;
9. sideload verification and recovery using a known-good boot image or official Xiaomi fastboot ROM.

Do not include private host paths or machine-administration commands.

- [ ] **Step 4: Write the device validation protocol**

`docs/device-validation.md` must list the exact boot properties and physical checks from the approved design, define PASS/FAIL/SKIPPED values, and state that untested items prevent a blanket “working” claim.

- [ ] **Step 5: Write evidence-first troubleshooting**

`docs/troubleshooting.md` must separate:

- `repo sync` failures;
- missing dependency or Soong namespace failures;
- compiler and linker failures;
- host out-of-memory or disk exhaustion;
- recovery/sideload failures;
- boot loop, kernel panic, and Android service crash loops.

For each category, give the exact log to preserve, the first command to run, and the condition for stopping instead of applying another patch.

- [ ] **Step 6: Add repository validation CI**

`.github/workflows/validate.yml` must run on pushes and pull requests, use Ubuntu, install `libxml2-utils` and `shellcheck`, then run:

```bash
python3 -m unittest discover -s tests -v
xmllint --noout manifests/fleur-lineage-23.2.xml
bash -n scripts/ubuntu/lib/common.sh scripts/ubuntu/*.sh
shellcheck scripts/ubuntu/lib/common.sh scripts/ubuntu/*.sh
python3 scripts/render_provenance.py sources/provenance.json --firmware sources/firmware.json --output /tmp/source-provenance.md
diff -u docs/source-provenance.md /tmp/source-provenance.md
```

- [ ] **Step 7: Run the full repository validation suite**

Run the same commands listed in CI.

Expected: all unit tests PASS, XML/Bash/ShellCheck exit 0, and the rendered provenance diff is empty.

- [ ] **Step 8: Commit documentation and CI**

```bash
git add README.md docs/build-and-install.md docs/device-validation.md docs/troubleshooting.md tests/test_repository.py .github/workflows/validate.yml
git commit -m "docs: add fleur build and validation runbook"
```

## Task 10: Bootstrap, Sync, and Run the First Full Build

**Files:**
- Create after successful sync: `manifests/snapshots/<UTC timestamp>.xml`
- Create after successful build: `reports/build-report.md`
- Modify only if evidence requires a fix: `manifests/fleur-lineage-23.2.xml`, `patches/<specific-fix>.patch`, relevant test.

**Interfaces:**
- Consumes: all repository tooling and an Ubuntu ext4 workspace with at least 500 GB free.
- Produces: build log, pinned manifest snapshot, OTA ZIP, `boot.img`, `SHA256SUMS`, and sanitized build report.

- [ ] **Step 1: Run the complete repository test suite before host execution**

Run: `python3 -m unittest discover -s tests -v && xmllint --noout manifests/fleur-lineage-23.2.xml && bash -n scripts/ubuntu/lib/common.sh scripts/ubuntu/*.sh && shellcheck scripts/ubuntu/lib/common.sh scripts/ubuntu/*.sh`

Expected: all checks PASS.

- [ ] **Step 2: Verify the private WSL workspace preconditions**

Run inside Ubuntu:

```bash
stat -f -c '%T %a %S' "$HOME"
df -h "$HOME"
free -h
nproc
```

Expected: ext4-compatible filesystem, at least 500 GB free, and the recorded memory/CPU values.

- [ ] **Step 3: Bootstrap build dependencies in the visible terminal**

Run:

```bash
cd "$HOME/src/flowerbed"
./scripts/ubuntu/bootstrap.sh 2>&1 | tee "$HOME/bootstrap-lineage-23.2-fleur.log"
```

Expected: exit 0 and verified `repo`, Git LFS, and `ccache` versions.

- [ ] **Step 4: Sync the exact source set in the visible terminal**

Run:

```bash
cd "$HOME/src/flowerbed"
./scripts/ubuntu/sync.sh "$HOME/android/lineage-23.2"
```

Expected: `repo sync` exits 0; all five device-specific repos are at the manifest SHAs; a revision-pinned snapshot is generated.

- [ ] **Step 5: Verify source paths and product discovery before compiling**

Run:

```bash
cd "$HOME/android/lineage-23.2"
repo status
test -f device/xiaomi/fleur/lineage_fleur.mk
test -f kernel/xiaomi/mt6781/arch/arm64/configs/fleur_defconfig
test -f vendor/xiaomi/fleur/BoardConfigVendor.mk
test -f vendor/xiaomi/fleur/radio/preloader_raw.img
source build/envsetup.sh
breakfast fleur
```

Expected: commands exit 0, the selected product is `lineage_fleur-userdebug` or the branch-equivalent release configuration selected by `breakfast`, and `BoardConfigVendor.mk` declares the eleven firmware partitions recorded in `sources/firmware.json`.

- [ ] **Step 6: Run the full build visibly**

Run:

```bash
cd "$HOME/src/flowerbed"
./scripts/ubuntu/build.sh --jobs 8 "$HOME/android/lineage-23.2"
```

Expected: exit 0 and an OTA ZIP plus `boot.img` under `out/target/product/fleur`.

If the build fails, stop this task. Preserve the first causal error, full log, manifest snapshot, host resource state, and exact command. Use systematic debugging to create one failing reproduction and one isolated fix; update this plan with the concrete fix task before changing source.

- [ ] **Step 7: Build the official payload extraction host tool**

Run in the same visible build environment:

```bash
cd "$HOME/android/lineage-23.2"
source build/envsetup.sh
breakfast fleur
m ota_extractor -j8
```

Expected: `out/host/linux-x86/bin/ota_extractor` exists and exits successfully with `--help`.

- [ ] **Step 8: Verify the produced artifacts and embedded firmware**

Run:

```bash
product_out="$HOME/android/lineage-23.2/out/target/product/fleur"
ota_zip="$(find "$product_out" -maxdepth 1 -type f -name 'lineage-23.2-*-fleur.zip' -print -quit)"
python3 "$HOME/src/flowerbed/scripts/ubuntu/verify_artifacts.py" "$ota_zip" \
  --boot-image "$product_out/boot.img" \
  --android-top "$HOME/android/lineage-23.2" \
  --firmware-manifest "$HOME/src/flowerbed/sources/firmware.json"
unzip -t "$ota_zip"
```

Expected: verifier exits 0, ZIP integrity passes, JSON reports `firmware.status = "verified"` and all eleven expected partition names, and `SHA256SUMS` is written.

- [ ] **Step 9: Write the sanitized successful build report**

Record actual values for:

- build UTC and elapsed time;
- Ubuntu, WSL kernel, CPU, memory, and job count;
- snapshot filename and SHA-256;
- OTA and boot-image filenames, sizes, and hashes;
- `ccache` statistics;
- static verification commands and results;
- embedded firmware version/provenance, eleven verified payload partitions, and pinned vendor commit;
- status `experimental — awaiting device validation`.

Do not copy absolute home paths or raw logs into the public report.

- [ ] **Step 10: Commit the verified build record**

```bash
git add manifests/snapshots reports/build-report.md
git commit -m "build: record first successful fleur artifact"
```

## Task 11: Validate the ZIP on the Physical Device

**Files:**
- Create locally and keep ignored: `reports/private/<UTC timestamp>/...`
- Create after testing: `reports/device-validation.md`
- Modify if a verified device fix is required: isolated patch, regression check, provenance notes.

**Interfaces:**
- Consumes: statically verified OTA ZIP, `boot.img`, known-good recovery material, and user-provided physical `fleur` access.
- Produces: boot evidence, functional smoke-test result, known-issue list, and release eligibility decision.

- [ ] **Step 1: Collect non-destructive inventory over ADB**

Run:

```bash
cd "$HOME/src/flowerbed"
./scripts/ubuntu/collect_device_logs.sh "reports/private/$(date -u +%Y%m%dT%H%M%SZ)-preflash"
adb shell getprop ro.product.device
adb shell getprop ro.build.fingerprint
adb shell getprop ro.boot.slot_suffix
```

Expected: ADB state is `device`, codename is compatible with `fleur`, and current state is recorded privately.

- [ ] **Step 2: Verify recovery prerequisites without changing the device**

Confirm that the bootloader is unlocked, the exact model/region is known, personal data is backed up, a known-good boot image is available, and the correct official Xiaomi fastboot ROM has been identified. Verify that every expected firmware partition has both `_a` and `_b` by-name nodes matching the payload partition scheme. Do not mount, flash, wipe, reboot, or sideload in this step.

- [ ] **Step 3: Stop for action-time user confirmation**

Present the exact proposed commands, partitions, artifact hashes, expected data-loss effect, and recovery path. Continue only after the user explicitly approves that specific flash/sideload operation.

- [ ] **Step 4: Install using the confirmed recovery procedure**

Use only the approved command sequence. Stream fastboot and ADB sideload output to a private timestamped log. Verify every command exit status before proceeding to the next partition or reset step.

Expected: sideload completes successfully and the device reboots into the new system.

- [ ] **Step 5: Verify boot acceptance over ADB**

Run:

```bash
timeout 10m adb wait-for-device
timeout 10m bash -c 'until [[ "$(adb shell getprop sys.boot_completed | tr -d "\r")" == 1 ]]; do sleep 2; done'
adb shell getprop ro.lineage.version
adb shell getprop ro.product.device
adb shell getprop ro.build.fingerprint
adb shell getenforce
adb shell service list
adb logcat -b all -d -v threadtime
```

Expected: `sys.boot_completed=1`, `ro.lineage.version` begins with `23.2`, device is `fleur`, ADB remains connected, and no persistent critical crash loop is present.

- [ ] **Step 6: Run the physical smoke-test checklist**

Record PASS/FAIL/SKIPPED for Wi-Fi, hotspot, Bluetooth pairing/audio, mobile data, calls, SMS, VoLTE, speaker, earpiece, microphones, cameras appropriate to the exact model, NFC, fingerprint, display refresh/brightness, rotation/proximity/sensors, charging, thermal behavior, encryption, reboot, and recovery.

Expected: every required item is PASS. A SKIPPED or FAIL item must be stated as a limitation and prevents a blanket `working` claim.

- [ ] **Step 7: Handle a boot or functional failure evidence-first**

If the device fails, collect recovery log, sideload log, fastboot slot state, `logcat`, `pstore`/ramoops, kernel log, and tombstones available without further destructive action. Stop before a second flash. Add one concrete diagnostic/fix task to this plan based on the first causal failure.

- [ ] **Step 8: Write and verify the sanitized validation report**

`reports/device-validation.md` must include ROM hash, device model without serial/IMEI, firmware baseline, boot result, each smoke-test result, log collection time, known issues, and recovery outcome. Run the repository test suite again before committing.

- [ ] **Step 9: Commit the device-validation result**

```bash
git add reports/device-validation.md docs/source-provenance.md sources/provenance.json
git commit -m "test: record fleur device validation"
```

## Task 12: Publish the Reproducible Repository and Verified Release

**Files:**
- Modify: `README.md`
- Modify: `reports/build-report.md`
- Modify: `reports/device-validation.md`
- Create from verified artifacts: release notes file under ignored `artifacts/`.

**Interfaces:**
- Consumes: clean Git history, passing repository checks, verified artifact hashes, and successful device report.
- Produces: pushed `main` branch and GitHub Release containing the OTA ZIP, `boot.img`, and `SHA256SUMS`.

- [ ] **Step 1: Update public status from experimental only if validation passed**

Change README status to `device-validated` only when the device report contains no unresolved required FAIL/SKIPPED item. Otherwise retain `experimental` and publish no stable-sounding release.

- [ ] **Step 2: Run final repository verification**

Run:

```bash
python3 -m unittest discover -s tests -v
xmllint --noout manifests/fleur-lineage-23.2.xml
bash -n scripts/ubuntu/lib/common.sh scripts/ubuntu/*.sh
shellcheck scripts/ubuntu/lib/common.sh scripts/ubuntu/*.sh
python3 scripts/render_provenance.py sources/provenance.json --firmware sources/firmware.json --output /tmp/source-provenance.md
diff -u docs/source-provenance.md /tmp/source-provenance.md
git diff --check
git status --short
```

Expected: all checks PASS and `git status` shows only the intended final status files, if any.

- [ ] **Step 3: Commit final public status if changed**

```bash
git add README.md reports/build-report.md reports/device-validation.md
git commit -m "docs: finalize fleur release status"
```

Skip the commit when there is no diff.

Then run `git status --short` and require an empty result before pushing.

- [ ] **Step 4: Push the reviewed repository history**

Run: `git push -u origin main`

Expected: push exits 0 and GitHub `main` resolves to the verified local HEAD.

- [ ] **Step 5: Generate release tag and notes from verified reports**

```bash
product_out="$HOME/android/lineage-23.2/out/target/product/fleur"
ota_zip="$(find "$product_out" -maxdepth 1 -type f -name 'lineage-23.2-*-fleur.zip' -print -quit)"
test -n "$ota_zip" && test -f "$ota_zip"
test -f "$product_out/boot.img"
test -f "$product_out/SHA256SUMS"
release_tag="lineage-23.2-fleur-$(date -u +%Y%m%d)"
notes_file="artifacts/${release_tag}-notes.md"
mkdir -p artifacts
{
  printf '# Unofficial LineageOS 23.2 for fleur\n\n'
  printf 'Device validation: PASS\n\n'
  sed -n '/## Artifact/,/## /p' reports/build-report.md
  sed -n '/## Summary/,/## /p' reports/device-validation.md
} >"$notes_file"
printf 'product_out=%q\nota_zip=%q\nrelease_tag=%q\nnotes_file=%q\n' \
  "$product_out" "$ota_zip" "$release_tag" "$notes_file" >artifacts/release.env
```

- [ ] **Step 6: Publish the GitHub Release**

Run only for a device-validated build:

```bash
source artifacts/release.env
gh release create "$release_tag" \
  "$ota_zip" \
  "$product_out/boot.img" \
  "$product_out/SHA256SUMS" \
  --repo noteMASTER11/flowerbed \
  --title "Unofficial LineageOS 23.2 for fleur ($(date -u +%Y-%m-%d))" \
  --notes-file "$notes_file"
```

Expected: release creation exits 0 and all three uploaded assets match local sizes and SHA-256 values.

- [ ] **Step 7: Verify publication from GitHub**

Run:

```bash
source artifacts/release.env
gh repo view noteMASTER11/flowerbed --json defaultBranchRef,url,viewerPermission
gh release view "$release_tag" --repo noteMASTER11/flowerbed --json tagName,isDraft,isPrerelease,url,assets
```

Expected: default branch is `main`, permission remains `ADMIN`, release is not a draft, and asset names/sizes match the local verified artifacts.
