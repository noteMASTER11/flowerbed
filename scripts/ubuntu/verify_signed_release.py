#!/usr/bin/env python3
"""Fail-closed verification for post-build signed LineageOS fleur releases."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import tempfile
from typing import Mapping, Sequence
import zipfile

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
HEX_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


def _parse_properties(text: str, label: str) -> dict[str, str]:
    properties: dict[str, str] = {}
    for line_number, line in enumerate(text.splitlines(), start=1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            raise VerificationError(f"{label} line {line_number} is not key=value")
        key, value = (item.strip() for item in line.split("=", 1))
        if not key or not value:
            raise VerificationError(f"{label} line {line_number} has an empty property")
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


def _metadata_records(text: str, label: str):
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
            if not key or not value or key in fields:
                raise VerificationError(f"{label} line {line_number} is malformed")
            fields[key] = value
        yield fields


def _reject_test_key_path(value: str) -> None:
    normalized = value.removesuffix(".x509.pem").removesuffix(".pk8").removesuffix(".pem")
    if value != "PRESIGNED" and normalized.startswith(TEST_KEY_PREFIXES):
        raise VerificationError(f"standard Android test certificate path remains: {value}")


def verify_signing_metadata_paths(apkcerts: str, apexkeys: str, misc_info: str) -> list[str]:
    """Reject standard test key paths and enumerate explicitly permitted APEXes."""
    for fields in _metadata_records(apkcerts, "apkcerts.txt"):
        for name in ("certificate", "private_key"):
            if name not in fields:
                raise VerificationError(f"apkcerts.txt is missing {name}")
            _reject_test_key_path(fields[name])

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
            for value in values:
                _reject_test_key_path(value)

    misc = _parse_properties(misc_info, "misc_info.txt")
    for value in misc.values():
        _reject_test_key_path(value)
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
    if not isinstance(rejected, str) or not HEX_SHA256.fullmatch(rejected):
        raise VerificationError("kernel provenance has no valid rejected pre-fix boot SHA-256")
    for label, evidence in (("unsigned", unsigned_boot), ("signed", signed_boot)):
        raw = evidence.get("raw_sha256")
        content = evidence.get("content_sha256")
        if not raw or not content:
            raise VerificationError(f"cannot associate {label} boot with kernel provenance")
        if raw == rejected:
            raise VerificationError(f"{label} boot matches the rejected pre-fix boot SHA-256")
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
        "hardware_tested_reference_sha256": record.get("hardware_tested_fixed_boot_sha256"),
        "boot_content_sha256": signed_boot["content_sha256"],
        "unsigned_boot_sha256": unsigned_boot["raw_sha256"],
        "signed_boot_sha256": signed_boot["raw_sha256"],
        "cfi_remains_enabled": True,
    }


def _archive_members(archive: zipfile.ZipFile) -> dict[str, zipfile.ZipInfo]:
    members: dict[str, zipfile.ZipInfo] = {}
    for member in archive.infolist():
        if member.filename in members:
            raise VerificationError(f"archive has duplicate member {member.filename}")
        members[member.filename] = member
    return members


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
        unsigned_members = _archive_members(unsigned)
        signed_members = _archive_members(signed)
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
    script = repository / "update_verifier.py"
    if not repository.is_dir() or not script.is_file():
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
    output = runner([os.sys.executable, script, public_key, ota], cwd=repository)
    if "verified successfully" not in output:
        raise VerificationError("OTA whole-file signature was not verified successfully")
    return {"revision": revision, "status": "verified"}


def _read_unique_bytes(archive: zipfile.ZipFile, name: str) -> bytes:
    matches = [member for member in archive.infolist() if member.filename == name]
    if len(matches) != 1:
        raise VerificationError(f"archive must contain exactly one {name}")
    return archive.read(matches[0])


def verify_fastboot_against_target_files(
    signed_target_files: Path, fastboot: Path
) -> dict[str, object]:
    with zipfile.ZipFile(signed_target_files) as target, zipfile.ZipFile(fastboot) as images:
        target_info = _read_unique_bytes(target, "OTA/android-info.txt")
        fastboot_info = _read_unique_bytes(images, "android-info.txt")
        if target_info != fastboot_info:
            raise VerificationError("fastboot android-info.txt differs from signed target-files")
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
    name = Path(value).name
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
    public_keys: Path,
    host_tools: Path,
    *,
    runner=_default_runner,
) -> dict[str, object]:
    """Verify one APK per certificate and every non-presigned APEX."""
    apk_records = list(_metadata_records(apkcerts, "apkcerts.txt"))
    apex_records = list(_metadata_records(apexkeys, "apexkeys.txt"))
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
        representatives: dict[str, Mapping[str, str]] = {}
        for fields in apk_records:
            certificate = fields.get("certificate")
            package_name = fields.get("name")
            if not certificate or not package_name:
                raise VerificationError("apkcerts.txt has an incomplete record")
            if certificate == "PRESIGNED":
                if fields.get("private_key") != "PRESIGNED":
                    raise VerificationError(f"APK {package_name} mixes PRESIGNED and release keys")
                presigned_apk.append(package_name)
                continue
            representatives.setdefault(_key_role(certificate), fields)
        for role in sorted(representatives):
            fields = representatives[role]
            package_name = fields["name"]
            member = _find_unique_by_basename(archive, package_name)
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
            if all(value == "PRESIGNED" for value in values):
                presigned_apex.append(name)
                continue
            if any(value == "PRESIGNED" for value in values):
                raise VerificationError(f"APEX {name} mixes PRESIGNED and release keys")
            member = _find_unique_by_basename(archive, name)
            apex_path = root / f"apex-{len(verified_apex)}-{name}"
            apex_path.write_bytes(archive.read(member))
            container_role = _key_role(fields["container_certificate"])
            certificate = public_keys / f"{container_role}.x509.pem"
            expected_container = _certificate_fingerprint(certificate, runner=runner)
            actual_container = _apksigner_fingerprint(apex_path, apksigner, runner=runner)
            if actual_container != expected_container:
                raise VerificationError(f"APEX container fingerprint mismatch for {name}")
            payload_role = _key_role(fields["public_key"])
            payload_key = public_keys / f"{payload_role}.avbpubkey"
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
                payload_role,
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
        members = _archive_members(archive)
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
    actual: set[str], expected_firmware: set[str]
) -> list[str]:
    expected = set(REQUIRED_ANDROID_PAYLOAD_PARTITIONS) | set(expected_firmware)
    missing = sorted(expected - actual)
    if missing:
        raise VerificationError(
            "OTA payload is missing required partitions: " + ", ".join(missing)
        )
    return sorted(actual)


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
        member = _find_unique_by_basename(archive, basename)
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
    android_root: Path,
    *,
    runner=_default_runner,
) -> tuple[bytes, set[str]]:
    payload_info = _required_tool(
        Path(android_root) / "system/update_engine/scripts/payload_info.py",
        "payload_info.py",
    )
    extractor = _required_tool(
        Path(android_root) / "out/host/linux-x86/bin/ota_extractor",
        "ota_extractor",
    )
    with tempfile.TemporaryDirectory(prefix="flowerbed-ota-proof-") as directory:
        root = Path(directory)
        payload = root / "payload.bin"
        payload.write_bytes(_read_unique_bytes(archive, "payload.bin"))
        info = runner([os.sys.executable, payload_info, payload], cwd=Path(android_root))
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
                "--partitions=boot",
            ],
            cwd=Path(android_root),
        )
        boot = images / "boot.img"
        if not boot.is_file() or boot.stat().st_size == 0:
            raise VerificationError("ota_extractor did not produce boot.img")
        return boot.read_bytes(), partitions


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


def _zip_evidence(path: Path) -> dict[str, object]:
    try:
        return verify_zip_with_unzip(path)
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        raise VerificationError(f"ZIP integrity check failed for {Path(path).name}: {error}") from error


def verify_release(
    args: argparse.Namespace,
    *,
    runner=_default_runner,
    firmware_verifier=verify_payload_firmware,
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
    report_path = Path(args.report)
    if report_path.exists() or report_path.is_symlink():
        raise VerificationError("verification report already exists")
    for label, path in paths.items():
        if not path.is_file() or path.is_symlink():
            raise VerificationError(f"{label} is unavailable")
    if not public_keys.is_dir() or public_keys.is_symlink():
        raise VerificationError("public key bundle is unavailable")

    zip_evidence = {label: _zip_evidence(path) for label, path in paths.items()}
    try:
        manifest = load_firmware_manifest(manifest_path)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        raise VerificationError(f"firmware manifest is invalid: {error}") from error
    expected_firmware_hashes = _manifest_firmware_hashes(manifest)
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
        if build_prop.get("ro.product.system.device") != "fleur":
            raise VerificationError("signed target-files device is not fleur")
        build_tags = verify_build_tags(build_prop)
        sku_mapping = verify_sku_properties(_read_sku_files(signed_target))
        presigned = verify_signing_metadata_paths(apkcerts, apexkeys, misc_info)

    host_tools = android_root / "out/host/linux-x86/bin"
    package_evidence = verify_package_signatures(
        paths["signed_target_files"],
        apkcerts,
        apexkeys,
        public_keys,
        host_tools,
        runner=runner,
    )
    if package_evidence["presigned_apex"] != presigned:
        raise VerificationError("PRESIGNED APEX inventory changed during verification")
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
    kernel_record_path = Path(__file__).resolve().parents[2] / "sources/kernel-fix.json"
    kernel_patch_path = (
        Path(__file__).resolve().parents[2]
        / "patches/android_kernel_xiaomi_mt6781/0001-mdpm-cfi-function-pointer-signature.patch"
    )
    try:
        kernel_record = json.loads(kernel_record_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise VerificationError("kernel-fix provenance record is unavailable") from error
    if (
        not kernel_patch_path.is_file()
        or sha256_file(kernel_patch_path) != kernel_record.get("patch_sha256")
    ):
        raise VerificationError("kernel-fix patch does not match its provenance record")
    kernel_evidence = verify_kernel_boot_provenance(
        unsigned_boot, signed_boot, kernel_record
    )

    with zipfile.ZipFile(paths["ota"]) as ota_archive:
        ota_metadata = verify_ota_metadata(
            _read_unique_text(ota_archive, "META-INF/com/android/metadata")
        )
        payload_bytes = _read_unique_bytes(ota_archive, "payload.bin")
        payload_properties = verify_payload_properties(
            _read_unique_text(ota_archive, "payload_properties.txt"),
            payload_bytes,
        )
        ota_boot, payload_partitions = _extract_ota_boot_and_partitions(
            ota_archive, android_root, runner=runner
        )
        verified_partitions = verify_payload_partition_set(
            payload_partitions, set(expected_firmware_hashes)
        )
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

    public_fingerprints = {
        path.name: sha256_file(path)
        for path in sorted(public_keys.iterdir())
        if path.is_file() and not path.is_symlink()
    }
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
        "packages": package_evidence,
        "avb_public_fingerprints": avb_fingerprints,
        "public_bundle_fingerprints": public_fingerprints,
        "kernel_provenance": kernel_evidence,
        "ota": {
            "pre_device": ota_metadata["pre-device"],
            "ota_type": ota_metadata["ota-type"],
            "payload_properties": payload_properties,
            "partitions": verified_partitions,
            "boot_sha256": ota_boot_hash,
            "firmware": firmware_evidence,
            "whole_file_signature": whole_file,
        },
        "fastboot": fastboot_evidence,
        "findings": findings,
    }
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
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
    try:
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written == 0:
                raise VerificationError("short write while publishing verification report")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    try:
        os.replace(temporary, path)
    except BaseException:
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
