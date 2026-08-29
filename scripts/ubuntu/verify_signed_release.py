#!/usr/bin/env python3
"""Fail-closed verification for post-build signed LineageOS fleur releases."""

from __future__ import annotations

import argparse
import base64
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import stat
import struct
import subprocess
import tarfile
import tempfile
from typing import Iterator, Mapping, Sequence
import zipfile

try:
    from scripts.ubuntu.build_provenance import (
        BuildProvenanceError,
        validate_final_build_provenance,
    )
    from scripts.ubuntu.generate_release_keys import build_key_plan
    from scripts.ubuntu.signing_metadata import load_signing_inventory
except ModuleNotFoundError:
    from build_provenance import BuildProvenanceError, validate_final_build_provenance
    from generate_release_keys import build_key_plan
    from signing_metadata import load_signing_inventory

try:
    from scripts.ubuntu.verify_artifacts import (
        load_firmware_manifest,
        parse_payload_partitions,
        sha256_file,
        verify_payload_firmware,
        verify_zip_with_unzip,
    )
except ModuleNotFoundError:  # Direct execution from scripts/ubuntu.
    from verify_artifacts import (
        load_firmware_manifest,
        parse_payload_partitions,
        sha256_file,
        verify_payload_firmware,
        verify_zip_with_unzip,
    )


class VerificationError(RuntimeError):
    """Raised when an artifact cannot be proven to satisfy release policy."""


EXPECTED_SKUS = {
    "build_fleur.prop": "Redmi Note 11S",
    "build_miel.prop": "Redmi Note 11S",
    "build_fleurp.prop": "POCO M4 Pro",
    "build_mielp.prop": "POCO M4 Pro",
}
EXPECTED_SKU_PATHS = {
    name: f"ODM/etc/{name}" for name in EXPECTED_SKUS
}
REQUIRED_AVB_PARTITIONS = ("boot", "vbmeta", "vbmeta_system", "vbmeta_vendor")
REQUIRED_FASTBOOT_IMAGES = ("boot", "dtbo", "vbmeta", "vbmeta_system", "vbmeta_vendor", "super")
REQUIRED_ANDROID_PAYLOAD_PARTITIONS = (
    "boot",
    "dtbo",
    "odm",
    "product",
    "system",
    "system_ext",
    "vbmeta",
    "vbmeta_system",
    "vbmeta_vendor",
    "vendor",
)
PINNED_UPDATE_VERIFIER_COMMIT = "9ffcf56a0fe152467da2971f0e6b2b79a42f7890"
TEST_KEY_PREFIXES = (
    "build/make/target/product/security/",
    "external/avb/test/",
)
MISC_KEY_LIST_PROPERTIES = ("extra_ota_keys", "extra_recovery_keys")
AVB_KEY_PATH_PROPERTY = re.compile(r"avb_[A-Za-z0-9_]+_key_path\Z")
FASTBOOT_ALLOWED_MEMBERS = {
    "android-info.txt",
    *(f"{partition}.img" for partition in REQUIRED_FASTBOOT_IMAGES),
}
ANDROID_TOOL_NAMES = (
    "apksigner", "deapexer", "avbtool", "debugfs_static", "fsck.erofs",
    "ota_extractor",
)
HEX_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


def _sha256_descriptor(descriptor: int) -> str:
    digest = hashlib.sha256()
    offset = 0
    while True:
        chunk = os.pread(descriptor, 1024 * 1024, offset)
        if not chunk:
            return digest.hexdigest()
        digest.update(chunk)
        offset += len(chunk)


def _path_evidence(path: Path) -> dict[str, object]:
    path = Path(path)
    return {
        "filename": path.name,
        "sha256": sha256_file(path),
        "size": path.stat().st_size,
    }


class _FileSnapshot:
    def __init__(self, paths, sources, descriptors, identities, hashes):
        self.paths = paths
        self.sources = sources
        self.descriptors = descriptors
        self.identities = identities
        self.hashes = hashes

    def verify(self) -> None:
        for label, source in self.sources.items():
            try:
                named = source.lstat()
                descriptor = os.fstat(self.descriptors[label])
            except OSError as error:
                raise VerificationError(f"verification input changed: {label}") from error
            identity = (descriptor.st_dev, descriptor.st_ino, descriptor.st_size)
            named_identity = (named.st_dev, named.st_ino, named.st_size)
            if stat.S_ISLNK(named.st_mode) or identity != self.identities[label] or named_identity != identity:
                raise VerificationError(f"verification input changed: {label}")
            if _sha256_descriptor(self.descriptors[label]) != self.hashes[label]:
                raise VerificationError(f"verification input changed: {label}")


class _AndroidToolchainSnapshot:
    def __init__(
        self,
        root: Path,
        files: _FileSnapshot,
        android_root: Path,
        execution,
    ):
        self.root = root
        self.host_tools = root / "bin"
        self.payload_scripts = root / "payload-scripts"
        self.files = files
        self.android_root = android_root
        self.source_inventory = dict(files.sources)
        self.execution = execution

    def verify(self) -> None:
        self.execution.verify()
        self.files.verify()
        if _android_toolchain_inputs(self.android_root) != self.source_inventory:
            raise VerificationError("Android toolchain inventory changed during verification")


class _ExecutionTree:
    def __init__(self, root: Path):
        self.root = Path(root)
        self.directories, self.files = self._inventory()

    def _inventory(self):
        directories: set[str] = set()
        files: dict[str, tuple[int, int, int, int, str]] = {}
        for directory, names, filenames in os.walk(self.root, followlinks=False):
            base = Path(directory)
            for name in names:
                path = base / name
                metadata = path.lstat()
                if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
                    raise VerificationError("execution copy contains an unsafe directory")
                directories.add(path.relative_to(self.root).as_posix())
            for name in filenames:
                path = base / name
                metadata = path.lstat()
                if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
                    raise VerificationError("execution copy contains an unsafe file")
                files[path.relative_to(self.root).as_posix()] = (
                    metadata.st_dev,
                    metadata.st_ino,
                    metadata.st_size,
                    stat.S_IMODE(metadata.st_mode),
                    sha256_file(path),
                )
        return directories, files

    def verify(self) -> None:
        try:
            directories, files = self._inventory()
        except (OSError, VerificationError) as error:
            raise VerificationError("execution copy changed during verification") from error
        if directories != self.directories or files != self.files:
            raise VerificationError("execution copy changed during verification")


def _make_tree_read_only(root: Path) -> None:
    for directory, _names, filenames in os.walk(root, topdown=False):
        base = Path(directory)
        for name in filenames:
            path = base / name
            mode = stat.S_IMODE(path.lstat().st_mode)
            path.chmod(0o555 if mode & 0o111 else 0o444)
        base.chmod(0o555)


def _make_tree_writable(root: Path) -> None:
    for directory, _names, filenames in os.walk(root):
        base = Path(directory)
        base.chmod(0o700)
        for name in filenames:
            path = base / name
            try:
                metadata = path.lstat()
            except OSError:
                continue
            if stat.S_ISREG(metadata.st_mode):
                path.chmod(0o600)


@contextmanager
def snapshot_regular_files(paths: Mapping[str, Path]) -> Iterator[_FileSnapshot]:
    descriptors: dict[str, int] = {}
    sources = {label: Path(path) for label, path in paths.items()}
    identities: dict[str, tuple[int, int, int]] = {}
    hashes: dict[str, str] = {}
    with tempfile.TemporaryDirectory(prefix="flowerbed-verify-inputs-") as directory:
        snapshots: dict[str, Path] = {}
        try:
            for index, (label, source) in enumerate(sorted(sources.items())):
                if source.is_symlink():
                    raise VerificationError(f"verification input is a symlink: {label}")
                try:
                    descriptor = os.open(
                        source,
                        os.O_RDONLY
                        | getattr(os, "O_CLOEXEC", 0)
                        | getattr(os, "O_NOFOLLOW", 0),
                    )
                except OSError as error:
                    raise VerificationError(f"verification input is unavailable: {label}") from error
                metadata = os.fstat(descriptor)
                if not stat.S_ISREG(metadata.st_mode):
                    os.close(descriptor)
                    raise VerificationError(f"verification input is not regular: {label}")
                descriptors[label] = descriptor
                identities[label] = (metadata.st_dev, metadata.st_ino, metadata.st_size)
                hashes[label] = _sha256_descriptor(descriptor)
                destination = Path(directory) / f"{index:02d}" / source.name
                destination.parent.mkdir()
                with destination.open("wb") as output:
                    offset = 0
                    while True:
                        chunk = os.pread(descriptor, 1024 * 1024, offset)
                        if not chunk:
                            break
                        output.write(chunk)
                        offset += len(chunk)
                os.chmod(destination, stat.S_IMODE(metadata.st_mode))
                if sha256_file(destination) != hashes[label]:
                    raise VerificationError(f"verification input snapshot failed: {label}")
                snapshots[label] = destination
            snapshot = _FileSnapshot(snapshots, sources, descriptors, identities, hashes)
            yield snapshot
        finally:
            for descriptor in descriptors.values():
                os.close(descriptor)


@contextmanager
def snapshot_android_toolchain(android_root: Path) -> Iterator[_AndroidToolchainSnapshot]:
    android_root = Path(android_root)
    inputs = _android_toolchain_inputs(android_root)
    with snapshot_regular_files(inputs) as files, tempfile.TemporaryDirectory(
        prefix="flowerbed-android-toolchain-"
    ) as directory:
        root = Path(directory)
        host_tools = root / "bin"
        payload_scripts = root / "payload-scripts"
        host_tools.mkdir()
        payload_scripts.mkdir()
        for label, snapshot_path in files.paths.items():
            kind, name = label.split(":", 1)
            destination = (host_tools if kind == "tool" else payload_scripts) / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(snapshot_path, destination)
        _make_tree_read_only(root)
        execution = _ExecutionTree(root)
        snapshot = _AndroidToolchainSnapshot(
            root, files, android_root, execution
        )
        try:
            yield snapshot
            snapshot.verify()
        finally:
            _make_tree_writable(root)


def _android_toolchain_inputs(android_root: Path) -> dict[str, Path]:
    android_root = Path(android_root)
    source_tools = android_root / "out/host/linux-x86/bin"
    source_scripts = android_root / "system/update_engine/scripts"
    inputs: dict[str, Path] = {}
    for name in ANDROID_TOOL_NAMES:
        path = source_tools / name
        if path.is_symlink():
            raise VerificationError(f"Android verification tool is a symlink: {name}")
        if not path.is_file() or not os.access(path, os.X_OK):
            raise VerificationError(f"Android verification tool is unavailable or not executable: {name}")
        inputs[f"tool:{name}"] = path
    optional_sparse = source_tools / "simg2img"
    if optional_sparse.exists() or optional_sparse.is_symlink():
        if optional_sparse.is_symlink():
            raise VerificationError("Android verification tool is a symlink: simg2img")
        if not optional_sparse.is_file() or not os.access(optional_sparse, os.X_OK):
            raise VerificationError("Android verification tool is unavailable or not executable: simg2img")
        inputs["tool:simg2img"] = optional_sparse
    if source_scripts.is_symlink() or not source_scripts.is_dir():
        raise VerificationError("payload script import root is unavailable or a symlink")
    for directory, names, filenames in os.walk(source_scripts, followlinks=False):
        base = Path(directory)
        for name in names:
            if (base / name).is_symlink():
                raise VerificationError(f"payload import root contains symlink: {name}")
        for name in filenames:
            path = base / name
            if path.is_symlink():
                raise VerificationError(f"payload import root contains symlink: {name}")
            inputs[f"script:{path.relative_to(source_scripts).as_posix()}"] = path
    if "script:payload_info.py" not in inputs:
        raise VerificationError("payload_info.py is unavailable")
    return inputs


def run_isolated_python_tool(
    script: Path,
    import_root: Path,
    arguments: Sequence[str | Path],
    *,
    cwd: Path,
    runner=None,
) -> str:
    if runner is None:
        runner = _default_runner
    loader = (
        "import runpy,sys; root=sys.argv.pop(1); script=sys.argv.pop(1); "
        "sys.path.insert(0,root); runpy.run_path(script,run_name='__main__')"
    )
    return runner(
        [os.sys.executable, "-I", "-c", loader, import_root, script, *arguments],
        cwd=cwd,
    )


def _parse_properties(text: str, label: str) -> dict[str, str]:
    properties: dict[str, str] = {}
    for line_number, line in enumerate(text.splitlines(), start=1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            raise VerificationError(f"{label} line {line_number} is not key=value")
        key, value = (item.strip() for item in line.split("=", 1))
        if not key:
            raise VerificationError(f"{label} line {line_number} has an empty property key")
        if key in properties and properties[key] != value:
            raise VerificationError(f"{label} has conflicting property {key}")
        properties[key] = value
    return properties


def verify_build_tags(properties: Mapping[str, str]) -> str:
    """Require an unambiguous release-keys build identity."""
    values = {
        properties[name]
        for name in ("ro.build.tags", "ro.system.build.tags", "ro.product.build.tags")
        if name in properties
    }
    if not values:
        raise VerificationError("build tags are missing")
    if any("test-keys" in value.split(",") for value in values):
        raise VerificationError("signed build still reports test-keys")
    if len(values) != 1 or "release-keys" not in next(iter(values)).split(","):
        raise VerificationError("build tags do not consistently report release-keys")
    return next(iter(values))


def verify_target_build_properties(properties: Mapping[str, str]) -> str:
    """Require the signed target-files device and release build tags."""
    if properties.get("ro.product.system.device") != "fleur":
        raise VerificationError("signed target-files device is not fleur")
    return verify_build_tags(properties)


def verify_ota_metadata(text: str) -> dict[str, str]:
    metadata = _parse_properties(text, "OTA metadata")
    devices = set(filter(None, metadata.get("pre-device", "").split(",")))
    if devices != {"fleur"}:
        raise VerificationError("OTA pre-device must be exactly fleur")
    if metadata.get("ota-type") != "AB":
        raise VerificationError("OTA metadata must declare ota-type=AB")
    return metadata


def verify_sku_properties(properties: Mapping[str, str]) -> dict[str, str]:
    if set(properties) != set(EXPECTED_SKUS):
        missing = sorted(set(EXPECTED_SKUS) - set(properties))
        extra = sorted(set(properties) - set(EXPECTED_SKUS))
        raise VerificationError(
            "SKU marketname files are incomplete "
            f"(missing={','.join(missing) or '<none>'}, extra={','.join(extra) or '<none>'})"
        )
    result: dict[str, str] = {}
    for filename, expected in EXPECTED_SKUS.items():
        parsed = _parse_properties(properties[filename], filename)
        if parsed.get("ro.product.marketname") != expected:
            raise VerificationError(f"{filename} has the wrong marketname")
        if parsed.get("ro.product.odm.model") != expected:
            raise VerificationError(f"{filename} has the wrong ODM model")
        result[filename] = expected
    return result


def verify_avb_fingerprints(
    actual: Mapping[str, str], expected: Mapping[str, str]
) -> dict[str, str]:
    required = set(REQUIRED_AVB_PARTITIONS)
    if set(actual) != required or set(expected) != required:
        raise VerificationError("AVB public fingerprints are incomplete")
    for partition in REQUIRED_AVB_PARTITIONS:
        if actual[partition] != expected[partition]:
            raise VerificationError(f"AVB public fingerprint mismatch for {partition}")
    return {partition: actual[partition] for partition in REQUIRED_AVB_PARTITIONS}


def _metadata_records(
    text: str, label: str, *, allowed_empty_fields: Sequence[str] = ()
):
    allowed_empty = set(allowed_empty_fields)
    for line_number, line in enumerate(text.splitlines(), start=1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            tokens = shlex.split(line, comments=False, posix=True)
        except ValueError as error:
            raise VerificationError(f"{label} line {line_number} is malformed") from error
        fields: dict[str, str] = {}
        for token in tokens:
            if "=" not in token:
                raise VerificationError(f"{label} line {line_number} is malformed")
            key, value = token.split("=", 1)
            if (
                not key
                or (not value and key not in allowed_empty)
                or key in fields
            ):
                raise VerificationError(f"{label} line {line_number} is malformed")
            fields[key] = value
        yield fields


def _canonical_key_path(value: str) -> str:
    if not value or "\x00" in value:
        raise VerificationError("key path is invalid")
    components = []
    for component in value.replace("\\", "/").split("/"):
        if component in {"", "."}:
            continue
        if component == "..":
            raise VerificationError("standard Android test certificate path traversal is forbidden")
        components.append(component)
    return "/".join(components)


def _reject_test_key_path(value: str) -> None:
    if value == "PRESIGNED":
        return
    normalized = _canonical_key_path(value).lower()
    components = normalized.split("/")
    stems = [re.sub(r"(?:\.x509\.pem|\.pk8|\.pem|\.avbpubkey)$", "", item) for item in components]
    if (
        "testkey" in stems
        or any(prefix.rstrip("/") in normalized for prefix in TEST_KEY_PREFIXES)
    ):
        raise VerificationError(f"standard Android test certificate path remains: {value}")


def _normalized_key_stem(value: str) -> str:
    normalized = _canonical_key_path(value)
    for suffix in (".x509.pem", ".avbpubkey", ".pk8", ".pem"):
        if normalized.endswith(suffix):
            return normalized[: -len(suffix)]
    return normalized


def _verify_misc_signing_key_paths(misc: Mapping[str, str]) -> None:
    default_certificate = misc.get("default_system_dev_certificate")
    if not default_certificate:
        raise VerificationError(
            "misc_info.txt has invalid default_system_dev_certificate"
        )
    _reject_test_key_path(default_certificate)

    for name in MISC_KEY_LIST_PROPERTIES:
        for value in misc.get(name, "").split():
            _reject_test_key_path(value)

    for name, value in misc.items():
        if AVB_KEY_PATH_PROPERTY.fullmatch(name):
            if not value:
                raise VerificationError(
                    f"misc_info.txt has invalid AVB key path {name}"
                )
            _reject_test_key_path(value)


def verify_signing_metadata_paths(apkcerts: str, apexkeys: str, misc_info: str) -> list[str]:
    """Validate preserved package metadata and reject test keys in rewritten misc data."""
    for fields in _metadata_records(
        apkcerts, "apkcerts.txt", allowed_empty_fields=("private_key",)
    ):
        if not fields.get("name") or not fields.get("certificate") or "private_key" not in fields:
            raise VerificationError("apkcerts.txt has an incomplete record")
        certificate = fields["certificate"]
        private_key = fields["private_key"]
        if certificate == "PRESIGNED":
            if private_key not in ("", "PRESIGNED"):
                raise VerificationError("apkcerts.txt mixes PRESIGNED and key paths")
            continue
        if not private_key:
            raise VerificationError("apkcerts.txt has an empty private_key")
        if _normalized_key_stem(certificate) != _normalized_key_stem(private_key):
            raise VerificationError("apkcerts.txt has mismatched certificate/private key stems")

    presigned: list[str] = []
    for fields in _metadata_records(apexkeys, "apexkeys.txt"):
        values = [
            fields.get(name, "")
            for name in (
                "public_key",
                "private_key",
                "container_certificate",
                "container_private_key",
            )
        ]
        if not fields.get("name") or any(not value for value in values):
            raise VerificationError("apexkeys.txt has an incomplete record")
        if any(value == "PRESIGNED" for value in values):
            if any(value != "PRESIGNED" for value in values):
                raise VerificationError("apexkeys.txt mixes PRESIGNED and key paths")
            presigned.append(fields["name"])
        else:
            if _normalized_key_stem(values[0]) != _normalized_key_stem(values[1]):
                raise VerificationError("apexkeys.txt has mismatched payload key stems")
            if _normalized_key_stem(values[2]) != _normalized_key_stem(values[3]):
                raise VerificationError("apexkeys.txt has mismatched container key stems")

    misc = _parse_properties(misc_info, "misc_info.txt")
    _verify_misc_signing_key_paths(misc)
    for partition in REQUIRED_AVB_PARTITIONS:
        key_name = f"avb_{partition}_key_path"
        algorithm_name = f"avb_{partition}_algorithm"
        key_path = misc.get(key_name)
        if not key_path or _key_role(key_path) != f"avb_{partition}":
            raise VerificationError(f"misc_info.txt has invalid AVB key for {partition}")
        if misc.get(algorithm_name) != "SHA256_RSA4096":
            raise VerificationError(
                f"misc_info.txt has invalid AVB algorithm for {partition}"
            )
    return sorted(presigned)


def verify_presigned_allowlist(
    actual_apk: Sequence[str],
    actual_apex: Sequence[str],
    approved: Mapping[str, object],
) -> dict[str, list[str]]:
    expected = {
        kind: sorted(value)
        for kind, value in approved.items()
        if kind in {"apk", "apex"} and isinstance(value, list)
        and all(isinstance(item, str) for item in value)
    }
    if set(expected) != {"apk", "apex"}:
        raise VerificationError("approved PRESIGNED allowlist is invalid")
    actual = {"apk": sorted(actual_apk), "apex": sorted(actual_apex)}
    if actual != expected:
        raise VerificationError("PRESIGNED inventory differs from approved allowlist")
    return actual


def verify_kernel_boot_provenance(
    unsigned_boot: Mapping[str, str],
    signed_boot: Mapping[str, str],
    record: Mapping[str, object],
) -> dict[str, object]:
    if record.get("project") != "kernel/xiaomi/mt6781":
        raise VerificationError("kernel provenance project is not mt6781")
    source_file = record.get("file")
    if (
        not isinstance(source_file, str)
        or not source_file
        or Path(source_file).is_absolute()
        or ".." in Path(source_file).parts
    ):
        raise VerificationError("kernel provenance source file is invalid")
    for field in ("base_commit", "patch_sha256", "hardware_tested_fixed_boot_sha256"):
        value = record.get(field)
        expected_length = 40 if field == "base_commit" else 64
        if not isinstance(value, str) or not re.fullmatch(
            rf"[0-9a-f]{{{expected_length}}}", value
        ):
            raise VerificationError(f"kernel provenance {field.replace('_', ' ')} is invalid")
    rejected = record.get("rejected_pre_fix_boot_sha256")
    rejected_content = record.get("rejected_pre_fix_boot_content_sha256")
    if not isinstance(rejected, str) or not HEX_SHA256.fullmatch(rejected):
        raise VerificationError("kernel provenance has no valid rejected pre-fix boot SHA-256")
    if not isinstance(rejected_content, str) or not HEX_SHA256.fullmatch(rejected_content):
        raise VerificationError(
            "kernel provenance has no valid rejected normalized pre-fix boot SHA-256"
        )
    for label, evidence in (("unsigned", unsigned_boot), ("signed", signed_boot)):
        raw = evidence.get("raw_sha256")
        content = evidence.get("content_sha256")
        if not raw or not content:
            raise VerificationError(f"cannot associate {label} boot with kernel provenance")
        if raw == rejected:
            raise VerificationError(f"{label} boot matches the rejected pre-fix boot SHA-256")
        if content == rejected_content:
            raise VerificationError(
                f"{label} boot matches the rejected normalized pre-fix boot content"
            )
    if unsigned_boot["content_sha256"] != signed_boot["content_sha256"]:
        raise VerificationError("signed boot content does not match refreshed unsigned target-files")
    if record.get("cfi_remains_enabled") is not True:
        raise VerificationError("kernel provenance does not preserve CFI")
    return {
        "project": record.get("project"),
        "file": source_file,
        "base_commit": record.get("base_commit"),
        "patch_sha256": record.get("patch_sha256"),
        "rejected_pre_fix_boot_sha256": rejected,
        "rejected_pre_fix_boot_content_sha256": rejected_content,
        "hardware_tested_reference_sha256": record.get("hardware_tested_fixed_boot_sha256"),
        "boot_content_sha256": signed_boot["content_sha256"],
        "unsigned_boot_sha256": unsigned_boot["raw_sha256"],
        "signed_boot_sha256": signed_boot["raw_sha256"],
        "cfi_remains_enabled": True,
    }


def verify_kernel_source_provenance(
    record: Mapping[str, object], patch: Path, application_script: Path
) -> dict[str, object]:
    if sha256_file(patch) != record.get("patch_sha256"):
        raise VerificationError("kernel-fix patch does not match its provenance record")
    if record.get("application_script") != "scripts/ubuntu/apply_patches.sh":
        raise VerificationError("kernel-fix application script provenance is invalid")
    if sha256_file(application_script) != record.get("application_script_sha256"):
        raise VerificationError("kernel-fix application script does not match provenance")
    registration = (
        '"kernel/xiaomi/mt6781|patches/android_kernel_xiaomi_mt6781/'
        '0001-mdpm-cfi-function-pointer-signature.patch"'
    )
    text = application_script.read_text(encoding="utf-8")
    if text.count(registration) != 1:
        raise VerificationError("kernel-fix application registration is missing or ambiguous")
    return {
        "patch_sha256": record.get("patch_sha256"),
        "application_script_sha256": record.get("application_script_sha256"),
        "application_registered": True,
    }


def _archive_members(
    archive: zipfile.ZipFile,
    *,
    allow_symlinks: bool = False,
    symlink_manifest: dict[str, tuple[int, int, bytes]] | None = None,
) -> dict[str, zipfile.ZipInfo]:
    members: dict[str, zipfile.ZipInfo] = {}
    for member in archive.infolist():
        name = member.filename
        parts = name.split("/")
        file_type = (member.external_attr >> 16) & 0o170000
        if (
            not name
            or "\x00" in name
            or "\\" in name
            or name.startswith("/")
            or re.match(r"^[A-Za-z]:", name)
            or ".." in parts
            or parts[-1] == "."
            or any(part in {"", "."} for part in parts[:-1])
        ):
            raise VerificationError(f"archive has unsafe member {name!r}")
        if member.filename in members:
            raise VerificationError(f"archive has duplicate member {member.filename}")
        members[member.filename] = member
        if file_type == stat.S_IFLNK:
            if not allow_symlinks:
                raise VerificationError(f"archive has symlink member {name}")
            if symlink_manifest is not None:
                symlink_manifest[name] = (
                    member.create_system,
                    member.external_attr,
                    archive.read(member),
                )
        elif file_type not in (0, stat.S_IFREG, stat.S_IFDIR):
            raise VerificationError(f"archive has special-file member {name}")
    return members


def validate_zip_members(path: Path, *, allow_symlinks: bool = False) -> list[str]:
    path = Path(path)
    if path.is_symlink() or not path.is_file() or path.stat().st_size == 0:
        raise VerificationError(f"invalid ZIP: {path.name}")
    try:
        with zipfile.ZipFile(path) as archive:
            members = _archive_members(archive, allow_symlinks=allow_symlinks)
            if archive.testzip() is not None:
                raise VerificationError(f"archive is corrupt: {path.name}")
            return sorted(members)
    except zipfile.BadZipFile as error:
        raise VerificationError(f"invalid ZIP: {Path(path).name}") from error


def _target_files_symlink_manifest(path: Path) -> dict[str, tuple[int, int, bytes]]:
    path = Path(path)
    if path.is_symlink() or not path.is_file() or path.stat().st_size == 0:
        raise VerificationError(f"invalid target-files ZIP: {path.name}")
    manifest: dict[str, tuple[int, int, bytes]] = {}
    try:
        with zipfile.ZipFile(path) as archive:
            _archive_members(
                archive,
                allow_symlinks=True,
                symlink_manifest=manifest,
            )
            if archive.testzip() is not None:
                raise VerificationError(f"target-files archive is corrupt: {path.name}")
    except zipfile.BadZipFile as error:
        raise VerificationError(f"invalid target-files ZIP: {path.name}") from error
    return manifest


def validate_target_files_symlink_manifest(
    unsigned_target_files: Path,
    signed_target_files: Path,
) -> None:
    expected = _target_files_symlink_manifest(unsigned_target_files)
    actual = _target_files_symlink_manifest(signed_target_files)
    if actual != expected:
        raise VerificationError(
            "signed target-files symlink manifest differs from unsigned target-files"
        )


def _partition_members(members: Mapping[str, zipfile.ZipInfo], prefix: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for name in members:
        if name.startswith(prefix) and name.endswith(".img") and "/" not in name[len(prefix):]:
            result[name[len(prefix):-4]] = name
    return result


def _sha256_member(archive: zipfile.ZipFile, member: str) -> str:
    digest = hashlib.sha256()
    with archive.open(member) as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def compare_target_files(
    unsigned_path: Path,
    signed_path: Path,
    expected_firmware_hashes: Mapping[str, str],
) -> dict[str, object]:
    with zipfile.ZipFile(unsigned_path) as unsigned, zipfile.ZipFile(signed_path) as signed:
        unsigned_members = _archive_members(unsigned, allow_symlinks=True)
        signed_members = _archive_members(signed, allow_symlinks=True)
        unsigned_android = _partition_members(unsigned_members, "IMAGES/")
        signed_android = _partition_members(signed_members, "IMAGES/")
        unsigned_firmware = _partition_members(unsigned_members, "RADIO/")
        signed_firmware = _partition_members(signed_members, "RADIO/")
        if set(unsigned_android) != set(signed_android):
            raise VerificationError("signed and unsigned Android partition lists differ")
        if set(unsigned_firmware) != set(signed_firmware):
            raise VerificationError("signed and unsigned firmware partition lists differ")
        if set(signed_firmware) != set(expected_firmware_hashes):
            raise VerificationError("target-files firmware partition list differs from manifest")
        firmware_hashes: dict[str, str] = {}
        for partition in sorted(signed_firmware):
            unsigned_hash = _sha256_member(unsigned, unsigned_firmware[partition])
            signed_hash = _sha256_member(signed, signed_firmware[partition])
            expected_hash = expected_firmware_hashes[partition]
            if unsigned_hash != signed_hash or signed_hash != expected_hash:
                raise VerificationError(f"firmware hash mismatch for {partition}")
            firmware_hashes[partition] = signed_hash
    return {
        "android_partitions": sorted(signed_android),
        "firmware_partitions": sorted(signed_firmware),
        "firmware_sha256": firmware_hashes,
    }


def target_metadata_hashes(target_files: Path) -> dict[str, str]:
    required = (
        "META/apkcerts.txt",
        "META/apexkeys.txt",
        "META/misc_info.txt",
        "META/otakeys.txt",
        "SYSTEM/build.prop",
    )
    with zipfile.ZipFile(target_files) as archive:
        _archive_members(archive, allow_symlinks=True)
        return {
            name: hashlib.sha256(_read_unique_bytes(archive, name)).hexdigest()
            for name in required
        }


def key_plan_evidence(plan) -> dict[str, object]:
    return {
        "android_mappings": [
            {
                "source_stem": item.source_stem,
                "destination_role": item.destination_role,
            }
            for item in plan.android_mappings
        ],
        "android_roles": list(plan.android_roles),
        "apex_roles": list(plan.apex_names),
        "avb_roles": [f"avb_{name}" for name in plan.avb_roles],
    }


def presigned_inventory(inventory) -> dict[str, list[str]]:
    return {
        "apk": sorted(
            item.name
            for item in inventory.apk_certificates
            if item.certificate == "PRESIGNED"
        ),
        "apex": sorted(item.name for item in inventory.apexes if item.presigned),
    }


def verify_signer_report(
    report: Mapping[str, object],
    paths: Mapping[str, Path],
    expected_metadata: Mapping[str, str],
    expected_key_plan: Mapping[str, object],
    expected_presigned: Mapping[str, object],
    expected_public_fingerprints: Mapping[str, str],
    expected_build_provenance: Mapping[str, object],
) -> dict[str, object]:
    if report.get("schema_version") != 2 or report.get("device") != "fleur":
        raise VerificationError("signer report schema/device is invalid")
    input_record = report.get("input")
    if not isinstance(input_record, dict):
        raise VerificationError("signer report input binding is missing")
    if set(input_record) != {"filename", "sha256", "size"}:
        raise VerificationError("signer report input binding is not exact")
    actual_input = _path_evidence(paths["unsigned_target_files"])
    if any(input_record.get(name) != actual_input[name] for name in ("filename", "sha256", "size")):
        raise VerificationError("signer report does not bind unsigned target-files")
    outputs = report.get("outputs")
    if not isinstance(outputs, dict):
        raise VerificationError("signer report output bindings are missing")
    output_labels = ("signed_target_files", "ota", "fastboot")
    expected_names = {paths[label].name for label in output_labels}
    if set(outputs) != expected_names:
        raise VerificationError("signer report output inventory is invalid")
    bound_outputs: dict[str, str] = {}
    for label in output_labels:
        evidence = _path_evidence(paths[label])
        record = outputs.get(paths[label].name)
        if not isinstance(record, dict) or set(record) != {"sha256", "size"} or any(
            record.get(name) != evidence[name] for name in ("sha256", "size")
        ):
            raise VerificationError(f"signer report does not bind {label}")
        bound_outputs[label] = str(evidence["sha256"])
    if report.get("input_metadata_sha256") != dict(expected_metadata):
        raise VerificationError("signer report input metadata binding is invalid")
    if report.get("key_plan") != dict(expected_key_plan):
        raise VerificationError("signer report key plan is invalid")
    if report.get("presigned_allowlist") != dict(expected_presigned):
        raise VerificationError("signer report PRESIGNED allowlist is invalid")
    if report.get("public_fingerprints") != dict(expected_public_fingerprints):
        raise VerificationError("signer report public-key fingerprints are invalid")
    if report.get("build_provenance") != dict(expected_build_provenance):
        raise VerificationError("signer report build provenance binding is invalid")
    return {
        "input_sha256": actual_input["sha256"],
        "report_bound_outputs": bound_outputs,
        "input_metadata_sha256": dict(expected_metadata),
        "key_plan": dict(expected_key_plan),
        "presigned_allowlist": dict(expected_presigned),
        "public_fingerprints": dict(expected_public_fingerprints),
        "build_provenance": dict(expected_build_provenance),
    }


def build_provenance_evidence(path: Path, record: Mapping[str, object]) -> dict[str, object]:
    evidence = _path_evidence(path)
    return {
        **evidence,
        "session_nonce": record["session_nonce"],
        "application_evidence_sha256": record["pre_build"]["application_evidence_sha256"],
        "unsigned_target_files": record["unsigned_target_files"],
    }


def _exact_android_key_mapping(plan) -> dict[str, str]:
    mapping: dict[str, str] = {}
    source_spellings: dict[str, str] = {}
    role_spellings: dict[str, str] = {}
    for item in plan.android_mappings:
        source = _canonical_key_path(item.source_stem)
        role = _canonical_key_path(item.destination_role)
        previous_source = source_spellings.get(source)
        if previous_source is not None and previous_source != item.source_stem:
            raise VerificationError(
                "canonical Android source-stem collision in key plan"
            )
        previous_role = role_spellings.get(role)
        if previous_role is not None and previous_role != item.destination_role:
            raise VerificationError(
                "canonical Android destination-role collision in key plan"
            )
        if source in mapping:
            raise VerificationError("duplicate Android source stem in key plan")
        source_spellings[source] = item.source_stem
        role_spellings[role] = item.destination_role
        mapping[source] = role
    return mapping


def verify_signed_key_plan(
    unsigned_target_files: Path,
    signed_target_files: Path,
    unsigned_inventory,
    plan,
) -> None:
    metadata_members = ("META/apkcerts.txt", "META/apexkeys.txt")
    try:
        with zipfile.ZipFile(unsigned_target_files) as unsigned, zipfile.ZipFile(
            signed_target_files
        ) as signed:
            for member in metadata_members:
                if _read_unique_bytes(unsigned, member) != _read_unique_bytes(signed, member):
                    raise VerificationError(
                        f"signed signing metadata was not preserved: {member}"
                    )
    except zipfile.BadZipFile as error:
        raise VerificationError("target-files signing metadata archive is invalid") from error

    inventory = load_signing_inventory(signed_target_files)
    if inventory.apk_certificates != unsigned_inventory.apk_certificates:
        raise VerificationError("signed APK metadata was not preserved logically")
    if inventory.apexes != unsigned_inventory.apexes:
        raise VerificationError("signed APEX metadata was not preserved logically")
    _exact_android_key_mapping(plan)
    avb_roles = {f"avb_{name}" for name in plan.avb_roles}
    if {f"avb_{item.partition}" for item in inventory.avb_keys} != avb_roles:
        raise VerificationError("signed AVB key roles differ from key plan")


def verify_payload_properties(
    text: str, payload: bytes | None = None
) -> dict[str, object]:
    properties = _parse_properties(text, "payload_properties.txt")
    required = ("FILE_HASH", "FILE_SIZE", "METADATA_HASH", "METADATA_SIZE")
    for name in required:
        if name not in properties:
            raise VerificationError(f"payload_properties.txt is missing {name}")
    result: dict[str, object] = {}
    for name in ("FILE_HASH", "METADATA_HASH"):
        value = properties[name]
        if not re.fullmatch(r"[A-Za-z0-9+/]{43}=", value):
            raise VerificationError(f"payload_properties.txt has invalid {name}")
        result[name] = value
    for name in ("FILE_SIZE", "METADATA_SIZE"):
        try:
            value = int(properties[name])
        except ValueError as error:
            raise VerificationError(f"payload_properties.txt has invalid {name}") from error
        if value <= 0:
            raise VerificationError(f"payload_properties.txt has invalid {name}")
        result[name] = value
    if payload is not None:
        actual_hash = base64.b64encode(hashlib.sha256(payload).digest()).decode("ascii")
        if result["FILE_HASH"] != actual_hash:
            raise VerificationError("payload_properties.txt FILE_HASH does not match payload.bin")
        if result["FILE_SIZE"] != len(payload):
            raise VerificationError("payload_properties.txt FILE_SIZE does not match payload.bin")
        if len(payload) < 24 or payload[:4] != b"CrAU":
            raise VerificationError("payload.bin has an invalid update payload header")
        try:
            _, version, manifest_size, signature_size = struct.unpack(
                ">4sQQI", payload[:24]
            )
        except struct.error as error:
            raise VerificationError("payload.bin has an invalid update payload header") from error
        if version != 2:
            raise VerificationError("payload.bin uses an unsupported payload version")
        metadata_size = 24 + manifest_size
        if metadata_size + signature_size > len(payload) or result["METADATA_SIZE"] != metadata_size:
            raise VerificationError(
                "payload_properties.txt METADATA_SIZE does not match payload.bin"
            )
        metadata_hash = base64.b64encode(
            hashlib.sha256(payload[:metadata_size]).digest()
        ).decode("ascii")
        if result["METADATA_HASH"] != metadata_hash:
            raise VerificationError(
                "payload_properties.txt METADATA_HASH does not match payload.bin"
            )
    return result


def _default_runner(
    command: Sequence[str | Path], *, cwd: Path | None = None, timeout: int = 600
) -> str:
    try:
        result = subprocess.run(
            [str(item) for item in command],
            cwd=cwd,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=timeout,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise VerificationError(f"verification command could not run: {Path(command[0]).name}") from error
    if result.returncode != 0:
        raise VerificationError(
            f"verification command failed: {Path(command[0]).name}: {result.stdout.strip()}"
        )
    return result.stdout


def verify_ota_whole_file_signature(
    repository: Path,
    ota: Path,
    public_key: Path,
    *,
    runner=_default_runner,
) -> dict[str, str]:
    repository = Path(repository)
    if not repository.is_dir() or not (repository / "update_verifier.py").is_file():
        raise VerificationError("pinned LineageOS update_verifier checkout is unavailable")
    revision = runner(["git", "rev-parse", "HEAD"], cwd=repository).strip()
    if revision != PINNED_UPDATE_VERIFIER_COMMIT:
        raise VerificationError(
            "LineageOS update_verifier checkout is not at the pinned revision"
        )
    main_revision = runner(
        ["git", "rev-parse", "refs/heads/main"], cwd=repository
    ).strip()
    if main_revision != PINNED_UPDATE_VERIFIER_COMMIT:
        raise VerificationError(
            "LineageOS update_verifier main branch is not at the pinned revision"
        )
    status = runner(
        ["git", "status", "--porcelain=v1", "--untracked-files=all"],
        cwd=repository,
    )
    if status.strip():
        raise VerificationError("LineageOS update_verifier checkout is not completely clean")
    with tempfile.TemporaryDirectory(prefix="flowerbed-update-verifier-") as directory:
        root = Path(directory)
        archive_path = root / "source.tar"
        runner(
            [
                "git",
                "archive",
                "--format=tar",
                f"--output={archive_path}",
                revision,
            ],
            cwd=repository,
        )
        export_sha256 = sha256_file(archive_path)
        try:
            with tarfile.open(archive_path) as archive:
                for member in archive.getmembers():
                    parts = Path(member.name).parts
                    if member.issym() or member.islnk() or Path(member.name).is_absolute() or ".." in parts:
                        raise VerificationError("update_verifier export contains unsafe members")
                export = root / "export"
                export.mkdir()
                archive.extractall(export, filter="data")
        except (OSError, tarfile.TarError) as error:
            raise VerificationError("cannot create isolated update_verifier export") from error
        script = export / "update_verifier.py"
        if not script.is_file():
            raise VerificationError("isolated update_verifier export is incomplete")
        _make_tree_read_only(export)
        execution = _ExecutionTree(export)
        isolated_loader = (
            "import runpy,sys; sys.argv.pop(0); root=sys.argv.pop(0); "
            "sys.path.insert(0,root); runpy.run_path(sys.argv[0],run_name='__main__')"
        )
        try:
            output = runner(
                [
                    os.sys.executable,
                    "-I",
                    "-c",
                    isolated_loader,
                    export,
                    script,
                    public_key,
                    ota,
                ],
                cwd=export,
            )
            execution.verify()
            if "verified successfully" not in output:
                raise VerificationError("OTA whole-file signature was not verified successfully")
        finally:
            _make_tree_writable(export)
    if runner(["git", "rev-parse", "HEAD"], cwd=repository).strip() != revision:
        raise VerificationError("update_verifier checkout changed during verification")
    if runner(
        ["git", "rev-parse", "refs/heads/main"], cwd=repository
    ).strip() != revision:
        raise VerificationError("update_verifier main branch changed during verification")
    if runner(
        ["git", "status", "--porcelain=v1", "--untracked-files=all"],
        cwd=repository,
    ).strip():
        raise VerificationError("update_verifier checkout changed during verification")
    return {
        "revision": revision,
        "status": "verified",
        "execution": "isolated-clean-export",
        "export_sha256": export_sha256,
    }


def _read_unique_bytes(archive: zipfile.ZipFile, name: str) -> bytes:
    matches = [member for member in archive.infolist() if member.filename == name]
    if len(matches) != 1:
        raise VerificationError(f"archive must contain exactly one {name}")
    return archive.read(matches[0])


def verify_fastboot_against_target_files(
    signed_target_files: Path, fastboot: Path
) -> dict[str, object]:
    with zipfile.ZipFile(signed_target_files) as target, zipfile.ZipFile(fastboot) as images:
        target_members = _archive_members(target, allow_symlinks=True)
        fastboot_members = _archive_members(images)
        files = set(fastboot_members)
        if files != FASTBOOT_ALLOWED_MEMBERS:
            missing = sorted(FASTBOOT_ALLOWED_MEMBERS - files)
            extra = sorted(files - FASTBOOT_ALLOWED_MEMBERS)
            raise VerificationError(
                "fastboot member inventory differs from policy "
                f"(missing={missing}, unexpected={extra})"
            )
        target_info = _read_unique_bytes(target, "OTA/android-info.txt")
        fastboot_info = _read_unique_bytes(images, "android-info.txt")
        if target_info != fastboot_info:
            raise VerificationError("fastboot android-info.txt differs from signed target-files")
        try:
            android_info = fastboot_info.decode("utf-8")
        except UnicodeDecodeError as error:
            raise VerificationError("fastboot android-info.txt is not UTF-8") from error
        products = []
        for line in android_info.splitlines():
            line = line.strip()
            if line.startswith("require product="):
                products.append(line.split("=", 1)[1])
        if products != ["fleur"]:
            raise VerificationError("fastboot android-info.txt must require product=fleur")
        hashes: dict[str, str] = {}
        for partition in REQUIRED_FASTBOOT_IMAGES:
            target_bytes = _read_unique_bytes(target, f"IMAGES/{partition}.img")
            fastboot_bytes = _read_unique_bytes(images, f"{partition}.img")
            if target_bytes != fastboot_bytes:
                raise VerificationError(
                    f"fastboot {partition}.img differs from signed target-files"
                )
            hashes[partition] = hashlib.sha256(fastboot_bytes).hexdigest()
    return {
        "android_info_sha256": hashlib.sha256(fastboot_info).hexdigest(),
        "images": sorted(hashes),
        "image_sha256": hashes,
    }


def extract_boot_evidence(
    target_files: Path,
    avbtool: Path,
    *,
    runner=_default_runner,
) -> dict[str, str]:
    """Hash raw boot and its content after removal of its AVB signature footer."""
    try:
        with zipfile.ZipFile(target_files) as archive:
            boot = _read_unique_bytes(archive, "IMAGES/boot.img")
    except (OSError, zipfile.BadZipFile) as error:
        raise VerificationError("cannot extract boot from target-files") from error
    with tempfile.TemporaryDirectory(prefix="flowerbed-boot-proof-") as directory:
        image = Path(directory) / "boot.img"
        image.write_bytes(boot)
        try:
            runner([avbtool, "erase_footer", "--image", image], cwd=Path(directory))
        except VerificationError as error:
            raise VerificationError("cannot normalize boot AVB footer") from error
        if not image.is_file() or image.stat().st_size == 0:
            raise VerificationError("cannot associate normalized boot content")
        content_hash = sha256_file(image)
    return {
        "raw_sha256": hashlib.sha256(boot).hexdigest(),
        "content_sha256": content_hash,
    }


def _key_role(value: str) -> str:
    name = value.replace("\\", "/").rsplit("/", 1)[-1]
    for suffix in (".x509.pem", ".pk8", ".avbpubkey", ".pem"):
        if name.endswith(suffix):
            return name[: -len(suffix)]
    return name


def _find_unique_by_basename(
    archive: zipfile.ZipFile, basename: str
) -> zipfile.ZipInfo:
    matches = [
        member
        for member in archive.infolist()
        if not member.is_dir() and Path(member.filename).name == basename
    ]
    if len(matches) != 1:
        raise VerificationError(
            f"target-files must contain exactly one package named {basename}; found {len(matches)}"
        )
    return matches[0]


def _certificate_fingerprint(
    certificate: Path, *, runner=_default_runner
) -> str:
    output = runner(
        ["openssl", "x509", "-in", certificate, "-noout", "-fingerprint", "-sha256"]
    )
    match = re.search(r"Fingerprint=([0-9A-Fa-f:]{64,95})", output)
    if not match:
        raise VerificationError(f"cannot read public certificate fingerprint for {certificate.name}")
    fingerprint = match.group(1).replace(":", "").lower()
    if not HEX_SHA256.fullmatch(fingerprint):
        raise VerificationError(f"invalid public certificate fingerprint for {certificate.name}")
    return fingerprint


def _apksigner_fingerprint(
    package: Path, apksigner: Path, *, runner=_default_runner
) -> str:
    output = runner([apksigner, "verify", "--print-certs", package])
    matches = re.findall(
        r"certificate SHA-256 digest:\s*([0-9A-Fa-f]{64})", output, re.IGNORECASE
    )
    if len(matches) != 1:
        raise VerificationError(f"cannot determine one signer fingerprint for {package.name}")
    return matches[0].lower()


def _verify_avb_public_key(
    image: Path,
    role: str,
    public_keys: Path,
    avbtool: Path,
    *,
    runner=_default_runner,
) -> str:
    public_blob = Path(public_keys) / f"{role}.avbpubkey"
    public_pem = Path(public_keys) / f"{role}.public.pem"
    if not public_blob.is_file() or public_blob.is_symlink():
        raise VerificationError(f"missing AVB public key blob for {role}")
    if not public_pem.is_file() or public_pem.is_symlink():
        raise VerificationError(f"missing AVB public PEM for {role}")
    runner([avbtool, "verify_image", "--key", public_pem, "--image", image])
    info = runner([avbtool, "info_image", "--image", image])
    match = re.search(r"Public key \(sha1\):\s*([0-9A-Fa-f]{40})", info)
    if not match:
        raise VerificationError(f"avbtool did not report embedded public key for {role}")
    expected_sha1 = hashlib.sha1(public_blob.read_bytes()).hexdigest()
    if match.group(1).lower() != expected_sha1:
        raise VerificationError(f"AVB embedded public key mismatch for {role}")
    return sha256_file(public_blob)


def verify_package_signatures(
    signed_target_files: Path,
    apkcerts: str,
    apexkeys: str,
    plan,
    public_keys: Path,
    host_tools: Path,
    *,
    runner=_default_runner,
) -> dict[str, object]:
    """Verify installed packages against their exact destination key roles."""
    apk_records = list(
        _metadata_records(
            apkcerts, "apkcerts.txt", allowed_empty_fields=("private_key",)
        )
    )
    apex_records = list(_metadata_records(apexkeys, "apexkeys.txt"))
    android_mapping = _exact_android_key_mapping(plan)
    apex_roles = set(plan.apex_names)
    public_keys = Path(public_keys)
    apksigner = Path(host_tools) / "apksigner"
    deapexer = Path(host_tools) / "deapexer"
    avbtool = Path(host_tools) / "avbtool"
    debugfs = Path(host_tools) / "debugfs_static"
    fsck_erofs = Path(host_tools) / "fsck.erofs"
    apk_representatives: list[str] = []
    presigned_apk: list[str] = []
    verified_apex: list[str] = []
    presigned_apex: list[str] = []
    fingerprints: dict[str, str] = {}

    with zipfile.ZipFile(signed_target_files) as archive, tempfile.TemporaryDirectory(
        prefix="flowerbed-package-proof-"
    ) as directory:
        root = Path(directory)
        members = _archive_members(archive, allow_symlinks=True)
        by_basename: dict[str, list[zipfile.ZipInfo]] = {}
        for member in members.values():
            if not member.is_dir():
                by_basename.setdefault(Path(member.filename).name, []).append(member)

        representatives: dict[
            str, list[tuple[str, zipfile.ZipInfo]]
        ] = {}
        apk_names: set[str] = set()
        for fields in apk_records:
            certificate = fields.get("certificate")
            package_name = fields.get("name")
            private_key = fields.get("private_key")
            if not certificate or not package_name or private_key is None:
                raise VerificationError("apkcerts.txt has an incomplete record")
            if package_name in apk_names:
                raise VerificationError(f"apkcerts.txt repeats package {package_name}")
            apk_names.add(package_name)
            if certificate == "PRESIGNED":
                if private_key not in ("", "PRESIGNED"):
                    raise VerificationError(f"APK {package_name} mixes PRESIGNED and release keys")
                presigned_apk.append(package_name)
                continue
            if not private_key or _normalized_key_stem(certificate) != _normalized_key_stem(
                private_key
            ):
                raise VerificationError(f"APK {package_name} has mismatched signing keys")
            matches = by_basename.get(package_name, [])
            if not matches:
                continue
            if len(matches) != 1:
                raise VerificationError(
                    f"target-files must contain exactly one package named {package_name}; "
                    f"found {len(matches)}"
                )
            source = _canonical_key_path(_normalized_key_stem(certificate))
            role = android_mapping.get(source)
            if role is None:
                raise VerificationError(
                    f"installed APK {package_name} has no destination key mapping"
                )
            representatives.setdefault(role, []).append((package_name, matches[0]))
        for role in sorted(representatives):
            package_name, member = min(representatives[role], key=lambda item: item[0])
            package = root / f"apk-{len(apk_representatives)}-{package_name}"
            package.write_bytes(archive.read(member))
            certificate = public_keys / f"{role}.x509.pem"
            if not certificate.is_file():
                raise VerificationError(f"missing public certificate for APK role {role}")
            expected = _certificate_fingerprint(certificate, runner=runner)
            actual = _apksigner_fingerprint(package, apksigner, runner=runner)
            if actual != expected:
                raise VerificationError(f"APK signer fingerprint mismatch for {package_name}")
            apk_representatives.append(package_name)
            fingerprints[f"apk:{role}"] = actual

        apex_names_seen: set[str] = set()
        for fields in apex_records:
            name = fields.get("name", "")
            values = [
                fields.get(field, "")
                for field in (
                    "public_key",
                    "private_key",
                    "container_certificate",
                    "container_private_key",
                )
            ]
            if not name or any(not value for value in values):
                raise VerificationError("apexkeys.txt has an incomplete record")
            if name in apex_names_seen:
                raise VerificationError(f"apexkeys.txt repeats package {name}")
            apex_names_seen.add(name)
            if all(value == "PRESIGNED" for value in values):
                presigned_apex.append(name)
                continue
            if any(value == "PRESIGNED" for value in values):
                raise VerificationError(f"APEX {name} mixes PRESIGNED and release keys")
            if _normalized_key_stem(values[0]) != _normalized_key_stem(values[1]):
                raise VerificationError(f"APEX {name} has mismatched payload signing keys")
            if _normalized_key_stem(values[2]) != _normalized_key_stem(values[3]):
                raise VerificationError(f"APEX {name} has mismatched container signing keys")
            matches = by_basename.get(name, [])
            if not matches:
                continue
            if len(matches) != 1:
                raise VerificationError(
                    f"target-files must contain exactly one package named {name}; "
                    f"found {len(matches)}"
                )
            member = matches[0]
            role = name.removesuffix(".apex")
            if role not in apex_roles:
                raise VerificationError(f"installed APEX {name} is outside destination key plan")
            apex_path = root / f"apex-{len(verified_apex)}-{name}"
            apex_path.write_bytes(archive.read(member))
            certificate = public_keys / f"{role}.x509.pem"
            if not certificate.is_file() or certificate.is_symlink():
                raise VerificationError(f"missing APEX container public certificate for {name}")
            expected_container = _certificate_fingerprint(certificate, runner=runner)
            actual_container = _apksigner_fingerprint(apex_path, apksigner, runner=runner)
            if actual_container != expected_container:
                raise VerificationError(f"APEX container fingerprint mismatch for {name}")
            payload_key = public_keys / f"{role}.avbpubkey"
            if not payload_key.is_file():
                raise VerificationError(f"missing APEX payload public key for {name}")
            extracted_payload = root / f"deapexed-{len(verified_apex)}"
            runner(
                [
                    deapexer,
                    "--debugfs_path",
                    debugfs,
                    "--fsckerofs_path",
                    fsck_erofs,
                    "extract",
                    apex_path,
                    extracted_payload,
                ]
            )
            if not extracted_payload.is_dir() or not any(extracted_payload.iterdir()):
                raise VerificationError(f"deapexer did not extract payload for {name}")
            try:
                with zipfile.ZipFile(apex_path) as apex_archive:
                    payload = _read_unique_bytes(apex_archive, "apex_payload.img")
            except zipfile.BadZipFile as error:
                raise VerificationError(f"APEX container is not a ZIP for {name}") from error
            payload_path = root / f"payload-{len(verified_apex)}.img"
            payload_path.write_bytes(payload)
            payload_fingerprint = _verify_avb_public_key(
                payload_path,
                role,
                public_keys,
                avbtool,
                runner=runner,
            )
            verified_apex.append(name)
            fingerprints[f"apex-container:{name}"] = actual_container
            fingerprints[f"apex-payload:{name}"] = payload_fingerprint

    return {
        "apk_representatives": sorted(apk_representatives),
        "presigned_apk": sorted(presigned_apk),
        "verified_apex": sorted(verified_apex),
        "presigned_apex": sorted(presigned_apex),
        "public_fingerprints": dict(sorted(fingerprints.items())),
    }


def verify_avb_images(
    signed_target_files: Path,
    public_keys: Path,
    avbtool: Path,
    *,
    runner=_default_runner,
) -> dict[str, str]:
    fingerprints: dict[str, str] = {}
    with zipfile.ZipFile(signed_target_files) as archive, tempfile.TemporaryDirectory(
        prefix="flowerbed-avb-proof-"
    ) as directory:
        root = Path(directory)
        members = _archive_members(archive, allow_symlinks=True)
        images = _partition_members(members, "IMAGES/")
        for partition, member in images.items():
            (root / f"{partition}.img").write_bytes(archive.read(member))
        for partition in REQUIRED_AVB_PARTITIONS:
            image = root / f"{partition}.img"
            if not image.is_file():
                raise VerificationError(f"signed target-files is missing AVB image {partition}")
            fingerprints[partition] = _verify_avb_public_key(
                image,
                f"avb_{partition}",
                Path(public_keys),
                avbtool,
                runner=runner,
            )
    return fingerprints


def verify_payload_partition_set(
    actual: set[str], expected: set[str]
) -> list[str]:
    mandatory = set(REQUIRED_ANDROID_PAYLOAD_PARTITIONS)
    absent_mandatory = sorted(mandatory - expected | mandatory - actual)
    if absent_mandatory:
        raise VerificationError(
            "mandatory Android payload partitions are missing: "
            + ", ".join(absent_mandatory)
        )
    missing = sorted(expected - actual)
    extra = sorted(actual - expected)
    if missing:
        raise VerificationError(
            "OTA payload is missing required partitions: " + ", ".join(missing)
        )
    if extra:
        raise VerificationError(
            "OTA payload has unexpected partitions: " + ", ".join(extra)
        )
    return sorted(actual)


def _target_ota_partitions(archive: zipfile.ZipFile) -> set[str]:
    text = _read_unique_text(archive, "META/ab_partitions.txt")
    partitions: list[str] = []
    for line in text.splitlines():
        name = line.strip()
        if not name:
            continue
        if not re.fullmatch(r"[a-z0-9_]+", name) or name in partitions:
            raise VerificationError("signed target-files has invalid AB partition inventory")
        partitions.append(name)
    if not partitions:
        raise VerificationError("signed target-files has no AB partition inventory")
    return set(partitions)


def verify_ota_partition_binding(
    signed_target_files: Path,
    extracted_dir: Path,
    actual_partitions: set[str],
    *,
    sparse_converter: Path | None,
    runner=_default_runner,
) -> dict[str, object]:
    with zipfile.ZipFile(signed_target_files) as target, tempfile.TemporaryDirectory(
        prefix="flowerbed-ota-partitions-"
    ) as directory:
        _archive_members(target, allow_symlinks=True)
        expected = _target_ota_partitions(target)
        verify_payload_partition_set(actual_partitions, expected)
        extracted_files = {
            path.stem: path
            for path in Path(extracted_dir).iterdir()
            if path.is_file() and path.suffix == ".img"
        }
        if set(extracted_files) != expected:
            raise VerificationError("ota_extractor output inventory differs from payload")
        hashes: dict[str, str] = {}
        temp_root = Path(directory)
        for partition in sorted(expected):
            candidates = [
                name
                for name in (f"IMAGES/{partition}.img", f"RADIO/{partition}.img")
                if name in {member.filename for member in target.infolist()}
            ]
            if len(candidates) != 1:
                raise VerificationError(
                    f"signed target-files cannot bind OTA partition {partition}"
                )
            expected_bytes = _read_unique_bytes(target, candidates[0])
            expected_path = temp_root / f"expected-{partition}.img"
            expected_path.write_bytes(expected_bytes)
            if expected_bytes[:4] == b"\x3a\xff\x26\xed":
                if sparse_converter is None:
                    raise VerificationError(
                        f"sparse converter is required for OTA partition {partition}"
                    )
                raw_path = temp_root / f"expected-{partition}.raw.img"
                runner([sparse_converter, expected_path, raw_path], cwd=temp_root)
                expected_path = raw_path
            actual_path = extracted_files[partition]
            actual_bytes = actual_path.read_bytes()
            expected_content = expected_path.read_bytes()
            if candidates[0].startswith("RADIO/"):
                matches = actual_bytes.startswith(expected_content) and not any(
                    actual_bytes[len(expected_content):]
                )
            else:
                matches = actual_bytes == expected_content
            if not matches:
                raise VerificationError(
                    f"OTA partition {partition} differs from signed target-files"
                )
            hashes[partition] = hashlib.sha256(expected_content).hexdigest()
    return {"partitions": sorted(expected), "sha256": hashes}


def _required_tool(path: Path, label: str) -> Path:
    path = Path(path)
    if not path.is_file():
        raise VerificationError(f"required verification tool is unavailable: {label}")
    return path


def _read_unique_text(archive: zipfile.ZipFile, name: str) -> str:
    try:
        return _read_unique_bytes(archive, name).decode("utf-8")
    except UnicodeDecodeError as error:
        raise VerificationError(f"archive member is not UTF-8: {name}") from error


def _read_sku_files(archive: zipfile.ZipFile) -> dict[str, str]:
    result: dict[str, str] = {}
    for basename in EXPECTED_SKUS:
        expected_path = EXPECTED_SKU_PATHS[basename]
        matches = [
            member for member in archive.infolist()
            if member.filename == expected_path and not member.is_dir()
        ]
        if len(matches) != 1:
            raise VerificationError(
                f"signed target-files must contain exact SKU path {expected_path}"
            )
        member = matches[0]
        try:
            result[basename] = archive.read(member).decode("utf-8")
        except UnicodeDecodeError as error:
            raise VerificationError(f"SKU property file is not UTF-8: {basename}") from error
    return result


def _manifest_firmware_hashes(manifest: Mapping[str, object]) -> dict[str, str]:
    result: dict[str, str] = {}
    for partition in manifest.get("partitions", []):
        if not isinstance(partition, dict):
            raise VerificationError("firmware manifest has an invalid partition record")
        name = partition.get("name")
        digest = partition.get("sha256")
        if not isinstance(name, str) or not isinstance(digest, str):
            raise VerificationError("firmware manifest has incomplete partition hashes")
        result[name] = digest
    if not result:
        raise VerificationError("firmware manifest has no partitions")
    return result


def _extract_ota_boot_and_partitions(
    archive: zipfile.ZipFile,
    host_tools: Path,
    payload_scripts: Path,
    signed_target_files: Path,
    sparse_converter: Path | None,
    *,
    runner=_default_runner,
) -> tuple[bytes, set[str], dict[str, object]]:
    payload_info = _required_tool(
        Path(payload_scripts) / "payload_info.py",
        "payload_info.py",
    )
    extractor = _required_tool(
        Path(host_tools) / "ota_extractor",
        "ota_extractor",
    )
    with tempfile.TemporaryDirectory(prefix="flowerbed-ota-proof-") as directory:
        root = Path(directory)
        payload = root / "payload.bin"
        payload.write_bytes(_read_unique_bytes(archive, "payload.bin"))
        info = run_isolated_python_tool(
            payload_info, Path(payload_scripts), [payload], cwd=Path(payload_scripts), runner=runner
        )
        partitions = parse_payload_partitions(info)
        if not partitions:
            raise VerificationError("payload_info.py returned no OTA partitions")
        images = root / "images"
        images.mkdir()
        runner(
            [
                extractor,
                f"--payload={payload}",
                f"--output_dir={images}",
                "--partitions=" + ",".join(sorted(partitions)),
            ],
            cwd=Path(host_tools),
        )
        boot = images / "boot.img"
        if not boot.is_file() or boot.stat().st_size == 0:
            raise VerificationError("ota_extractor did not produce boot.img")
        binding = verify_ota_partition_binding(
            signed_target_files,
            images,
            partitions,
            sparse_converter=sparse_converter,
            runner=runner,
        )
        return boot.read_bytes(), partitions, binding


def _find_update_verifier(android_root: Path) -> Path:
    candidates = (
        Path(android_root) / "external/update_verifier",
        Path(android_root) / "update_verifier",
    )
    found = [path for path in candidates if path.is_dir()]
    if len(found) != 1:
        raise VerificationError("exactly one pinned LineageOS update_verifier checkout is required")
    return found[0]


def _ota_public_key(
    release_certificate: Path,
    destination: Path,
    *,
    runner=_default_runner,
) -> Path:
    if not release_certificate.is_file():
        raise VerificationError("releasekey public certificate is unavailable")
    output = runner(["openssl", "x509", "-in", release_certificate, "-pubkey", "-noout"])
    if "BEGIN PUBLIC KEY" not in output or "END PUBLIC KEY" not in output:
        raise VerificationError("cannot extract OTA public key from releasekey certificate")
    destination.write_text(output, encoding="ascii")
    return destination


def _zip_evidence(path: Path, *, allow_symlinks: bool = False) -> dict[str, object]:
    validate_zip_members(path, allow_symlinks=allow_symlinks)
    try:
        if allow_symlinks:
            result = subprocess.run(
                ["unzip", "-t", str(path)],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
            )
            if result.returncode != 0:
                raise ValueError(
                    f"unzip -t rejected {Path(path).name}: {result.stdout.strip()}"
                )
            return {
                "status": "verified",
                "name": Path(path).name,
                "size": Path(path).stat().st_size,
                "sha256": sha256_file(path),
            }
        return verify_zip_with_unzip(path)
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        raise VerificationError(f"ZIP integrity check failed for {Path(path).name}: {error}") from error


def fingerprint_public_bundle(directory: Path) -> dict[str, str]:
    directory = Path(directory)
    if not directory.is_dir() or directory.is_symlink():
        raise VerificationError("public key bundle is unavailable")
    fingerprints: dict[str, str] = {}
    for path in sorted(directory.iterdir()):
        if path.is_symlink():
            raise VerificationError(f"public key bundle contains symlink: {path.name}")
        if not path.is_file():
            raise VerificationError(f"public key bundle contains non-file: {path.name}")
        fingerprints[path.name] = sha256_file(path)
    if not fingerprints:
        raise VerificationError("public key bundle is empty")
    return fingerprints


@contextmanager
def snapshot_public_bundle(directory: Path):
    source = Path(directory)
    initial = fingerprint_public_bundle(source)
    file_map = {f"public:{name}": source / name for name in initial}
    with snapshot_regular_files(file_map) as snapshot, tempfile.TemporaryDirectory(
        prefix="flowerbed-public-keys-"
    ) as temporary:
        copied = Path(temporary)
        for name in initial:
            shutil.copyfile(snapshot.paths[f"public:{name}"], copied / name)
        yield copied, initial
        snapshot.verify()
        if fingerprint_public_bundle(source) != initial:
            raise VerificationError("public key bundle changed during verification")


def _verify_release_snapshotted(
    args: argparse.Namespace,
    *,
    runner=_default_runner,
    firmware_verifier=None,
) -> dict[str, object]:
    """Verify all signed release artifacts and publish one sanitized report."""
    paths = {
        "unsigned_target_files": Path(args.unsigned_target_files),
        "signed_target_files": Path(args.signed_target_files),
        "ota": Path(args.ota),
        "fastboot": Path(args.fastboot),
    }
    public_keys = Path(args.public_keys)
    android_root = Path(args.android_root)
    manifest_path = Path(args.firmware_manifest)
    for label, path in paths.items():
        if not path.is_file() or path.is_symlink():
            raise VerificationError(f"{label} is unavailable")
    if not public_keys.is_dir() or public_keys.is_symlink():
        raise VerificationError("public key bundle is unavailable")

    validate_target_files_symlink_manifest(
        paths["unsigned_target_files"],
        paths["signed_target_files"],
    )
    zip_evidence = {
        label: _zip_evidence(
            path,
            allow_symlinks=label in {"unsigned_target_files", "signed_target_files"},
        )
        for label, path in paths.items()
    }
    try:
        manifest = load_firmware_manifest(manifest_path)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        raise VerificationError(f"firmware manifest is invalid: {error}") from error
    expected_firmware_hashes = _manifest_firmware_hashes(manifest)
    kernel_record_path = Path(args.kernel_record)
    kernel_patch_path = Path(args.kernel_patch)
    kernel_application_path = Path(args.kernel_application)
    try:
        kernel_record = json.loads(kernel_record_path.read_text(encoding="utf-8"))
        build_record = validate_final_build_provenance(
            Path(args.build_provenance),
            paths["unsigned_target_files"],
            kernel_record,
            kernel_patch_path,
            kernel_application_path,
        )
    except (OSError, json.JSONDecodeError, BuildProvenanceError) as error:
        raise VerificationError(f"build provenance is invalid: {error}") from error
    expected_build_provenance = build_provenance_evidence(
        Path(args.build_provenance), build_record
    )
    try:
        unsigned_inventory = load_signing_inventory(paths["unsigned_target_files"])
        unsigned_plan = build_key_plan(unsigned_inventory)
    except Exception as error:
        raise VerificationError("unsigned target-files signing inventory is invalid") from error
    metadata_hashes = target_metadata_hashes(paths["unsigned_target_files"])
    expected_key_plan = key_plan_evidence(unsigned_plan)
    approved_presigned = presigned_inventory(unsigned_inventory)
    try:
        signer_report = json.loads(Path(args.signing_report).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise VerificationError("signer report is invalid") from error
    signing_evidence = verify_signer_report(
        signer_report,
        paths,
        metadata_hashes,
        expected_key_plan,
        approved_presigned,
        fingerprint_public_bundle(public_keys),
        expected_build_provenance,
    )
    verify_signed_key_plan(
        paths["unsigned_target_files"],
        paths["signed_target_files"],
        unsigned_inventory,
        unsigned_plan,
    )
    target_relationship = compare_target_files(
        paths["unsigned_target_files"],
        paths["signed_target_files"],
        expected_firmware_hashes,
    )

    with zipfile.ZipFile(paths["signed_target_files"]) as signed_target:
        apkcerts = _read_unique_text(signed_target, "META/apkcerts.txt")
        apexkeys = _read_unique_text(signed_target, "META/apexkeys.txt")
        misc_info = _read_unique_text(signed_target, "META/misc_info.txt")
        build_prop = _parse_properties(
            _read_unique_text(signed_target, "SYSTEM/build.prop"),
            "SYSTEM/build.prop",
        )
        build_tags = verify_target_build_properties(build_prop)
        sku_mapping = verify_sku_properties(_read_sku_files(signed_target))
        presigned = verify_signing_metadata_paths(apkcerts, apexkeys, misc_info)

    host_tools = Path(args.host_tools)
    payload_scripts = Path(args.payload_scripts)
    package_evidence = verify_package_signatures(
        paths["signed_target_files"],
        apkcerts,
        apexkeys,
        unsigned_plan,
        public_keys,
        host_tools,
        runner=runner,
    )
    if package_evidence["presigned_apex"] != presigned:
        raise VerificationError("PRESIGNED APEX inventory changed during verification")
    verify_presigned_allowlist(
        package_evidence["presigned_apk"],
        package_evidence["presigned_apex"],
        approved_presigned,
    )
    avbtool = _required_tool(host_tools / "avbtool", "avbtool")
    avb_fingerprints = verify_avb_images(
        paths["signed_target_files"], public_keys, avbtool, runner=runner
    )

    unsigned_boot = extract_boot_evidence(
        paths["unsigned_target_files"], avbtool, runner=runner
    )
    signed_boot = extract_boot_evidence(
        paths["signed_target_files"], avbtool, runner=runner
    )
    build_boot = build_record["unsigned_target_files"]
    if (
        build_boot.get("boot_raw_sha256") != unsigned_boot["raw_sha256"]
        or build_boot.get("boot_content_sha256") != unsigned_boot["content_sha256"]
    ):
        raise VerificationError(
            "build provenance boot hashes do not match verifier-extracted unsigned boot"
        )
    source_provenance = verify_kernel_source_provenance(
        kernel_record, kernel_patch_path, kernel_application_path
    )
    kernel_evidence = verify_kernel_boot_provenance(
        unsigned_boot, signed_boot, kernel_record
    )
    kernel_evidence["source_application"] = source_provenance

    with zipfile.ZipFile(paths["ota"]) as ota_archive:
        ota_metadata = verify_ota_metadata(
            _read_unique_text(ota_archive, "META-INF/com/android/metadata")
        )
        payload_bytes = _read_unique_bytes(ota_archive, "payload.bin")
        payload_properties = verify_payload_properties(
            _read_unique_text(ota_archive, "payload_properties.txt"),
            payload_bytes,
        )
        ota_boot, payload_partitions, partition_binding = _extract_ota_boot_and_partitions(
            ota_archive,
            host_tools,
            payload_scripts,
            paths["signed_target_files"],
            host_tools / "simg2img" if (host_tools / "simg2img").is_file() else None,
            runner=runner,
        )
        with zipfile.ZipFile(paths["signed_target_files"]) as signed_target:
            expected_payload_partitions = _target_ota_partitions(signed_target)
        missing_firmware = sorted(
            set(expected_firmware_hashes) - expected_payload_partitions
        )
        if missing_firmware:
            raise VerificationError(
                "signed target-files AB inventory omits pinned firmware partitions: "
                + ", ".join(missing_firmware)
            )
        verified_partitions = verify_payload_partition_set(
            payload_partitions, expected_payload_partitions
        )
        if firmware_verifier is None:
            bound_hashes = partition_binding["sha256"]
            if any(bound_hashes.get(name) != digest for name, digest in expected_firmware_hashes.items()):
                raise VerificationError("OTA firmware hashes differ from pinned manifest")
            firmware_evidence = {
                "status": "verified",
                "partitions": [
                    {"name": name, "sha256": expected_firmware_hashes[name]}
                    for name in sorted(expected_firmware_hashes)
                ],
            }
        else:
            try:
                firmware_evidence = firmware_verifier(
                    ota_archive, android_root, manifest_path
                )
            except (OSError, ValueError, subprocess.SubprocessError) as error:
                raise VerificationError(f"OTA firmware verification failed: {error}") from error
    ota_boot_hash = hashlib.sha256(ota_boot).hexdigest()
    if ota_boot_hash != signed_boot["raw_sha256"]:
        raise VerificationError("OTA boot does not match signed target-files boot")

    fastboot_evidence = verify_fastboot_against_target_files(
        paths["signed_target_files"], paths["fastboot"]
    )
    if fastboot_evidence["image_sha256"]["boot"] != signed_boot["raw_sha256"]:
        raise VerificationError("fastboot boot does not match signed target-files boot")

    with tempfile.TemporaryDirectory(prefix="flowerbed-ota-signature-") as directory:
        ota_public_key = _ota_public_key(
            public_keys / "releasekey.x509.pem",
            Path(directory) / "ota.public.pem",
            runner=runner,
        )
        whole_file = verify_ota_whole_file_signature(
            _find_update_verifier(android_root),
            paths["ota"],
            ota_public_key,
            runner=runner,
        )

    public_fingerprints = fingerprint_public_bundle(public_keys)
    findings = [
        {"name": name, "status": "pass"}
        for name in (
            "zip-integrity",
            "target-files-partitions",
            "release-build-tags",
            "sku-product-identity",
            "package-signatures",
            "apex-signatures",
            "avb-signatures",
            "kernel-boot-provenance",
            "ota-payload-and-firmware",
            "ota-whole-file-signature",
            "fastboot-target-files-binding",
        )
    ]
    result: dict[str, object] = {
        "schema_version": 1,
        "status": "pass",
        "device": "fleur",
        "artifacts": {
            label: {
                "name": evidence["name"],
                "sha256": evidence["sha256"],
                "size": evidence["size"],
            }
            for label, evidence in zip_evidence.items()
        },
        "build_tags": build_tags,
        "sku_mapping": sku_mapping,
        "target_files": target_relationship,
        "signing_provenance": signing_evidence,
        "packages": package_evidence,
        "avb_public_fingerprints": avb_fingerprints,
        "public_bundle_fingerprints": public_fingerprints,
        "kernel_provenance": kernel_evidence,
        "ota": {
            "pre_device": ota_metadata["pre-device"],
            "ota_type": ota_metadata["ota-type"],
            "payload_properties": payload_properties,
            "partitions": verified_partitions,
            "partition_binding": partition_binding,
            "boot_sha256": ota_boot_hash,
            "firmware": firmware_evidence,
            "whole_file_signature": whole_file,
        },
        "fastboot": fastboot_evidence,
        "findings": findings,
    }
    return result


def verify_release(
    args: argparse.Namespace,
    *,
    runner=_default_runner,
    firmware_verifier=None,
) -> dict[str, object]:
    report_path = Path(args.report)
    if report_path.exists() or report_path.is_symlink():
        raise VerificationError("verification report already exists")
    repository = Path(__file__).resolve().parents[2]
    original_paths = {
        "unsigned_target_files": Path(args.unsigned_target_files),
        "signed_target_files": Path(args.signed_target_files),
        "ota": Path(args.ota),
        "fastboot": Path(args.fastboot),
        "firmware_manifest": Path(args.firmware_manifest),
        "signing_report": Path(args.signing_report),
        "build_provenance": Path(args.build_provenance),
        "kernel_record": repository / "sources/kernel-fix.json",
        "kernel_patch": repository
        / "patches/android_kernel_xiaomi_mt6781/0001-mdpm-cfi-function-pointer-signature.patch",
        "kernel_application": repository / "scripts/ubuntu/apply_patches.sh",
    }
    with snapshot_regular_files(original_paths) as snapshot, snapshot_public_bundle(
        Path(args.public_keys)
    ) as (public_snapshot, public_fingerprints), snapshot_android_toolchain(
        Path(args.android_root)
    ) as toolchain:
        snapshot_args = argparse.Namespace(**vars(args))
        for label, path in snapshot.paths.items():
            setattr(snapshot_args, label, path)
        snapshot_args.public_keys = public_snapshot
        snapshot_args.host_tools = toolchain.host_tools
        snapshot_args.payload_scripts = toolchain.payload_scripts
        result = _verify_release_snapshotted(
            snapshot_args,
            runner=runner,
            firmware_verifier=firmware_verifier,
        )
        result["public_bundle_fingerprints"] = public_fingerprints
        snapshot.verify()
        toolchain.verify()
    write_sanitized_report(report_path, result)
    return result


def _validate_sanitized(value: object, *, key: str = "") -> None:
    if isinstance(value, dict):
        for child_key, child in value.items():
            _validate_sanitized(child, key=str(child_key))
    elif isinstance(value, list):
        for child in value:
            _validate_sanitized(child, key=key)
    elif isinstance(value, str):
        if "path" in key.lower() or "private" in key.lower() or value.startswith(("/", "\\\\")):
            raise VerificationError("verification report is not sanitized")
        if re.search(r"[A-Za-z]:[\\/]", value):
            raise VerificationError("verification report is not sanitized")


def write_sanitized_report(path: Path, report: Mapping[str, object]) -> None:
    _validate_sanitized(report)
    path = Path(path)
    if path.exists() or path.is_symlink():
        raise VerificationError("verification report already exists")
    payload = (json.dumps(report, indent=2, sort_keys=True) + "\n").encode("utf-8")
    temporary = path.parent / f".{path.name}.tmp"
    if temporary.exists() or temporary.is_symlink():
        raise VerificationError("temporary verification report already exists")
    descriptor = None
    try:
        descriptor = os.open(
            temporary,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            0o644,
        )
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written == 0:
                raise VerificationError("short write while publishing verification report")
            view = view[written:]
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None
        os.replace(temporary, path)
    except BaseException:
        if descriptor is not None:
            os.close(descriptor)
        temporary.unlink(missing_ok=True)
        raise


def main(argv: Sequence[str] | None = None, *, verifier=verify_release) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--unsigned-target-files", required=True, type=Path)
    parser.add_argument("--signed-target-files", required=True, type=Path)
    parser.add_argument("--ota", required=True, type=Path)
    parser.add_argument("--fastboot", required=True, type=Path)
    parser.add_argument("--public-keys", required=True, type=Path)
    parser.add_argument("--android-root", required=True, type=Path)
    parser.add_argument("--firmware-manifest", required=True, type=Path)
    parser.add_argument("--signing-report", required=True, type=Path)
    parser.add_argument("--build-provenance", required=True, type=Path)
    parser.add_argument("--report", required=True, type=Path)
    args = parser.parse_args(argv)
    report = verifier(args)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except VerificationError as error:
        print(f"ERROR: {error}", file=os.sys.stderr)
        raise SystemExit(1)
