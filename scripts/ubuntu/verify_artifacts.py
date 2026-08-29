#!/usr/bin/env python3
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import stat
import sys
import tempfile
import zipfile


CHUNK_SIZE = 1024 * 1024
REQUIRED_OTA_FILES = {
    "META-INF/com/android/metadata",
    "payload.bin",
    "payload_properties.txt",
}
PARTITION_PATTERN = re.compile(r'Number of "([^"]+)" ops\s*:')


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(CHUNK_SIZE), b""):
            digest.update(chunk)
    return digest.hexdigest()


def parse_metadata(raw: bytes) -> dict[str, str]:
    metadata = {}
    for line in raw.decode("utf-8").splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            metadata[key] = value
    return metadata


def parse_payload_partitions(output: str) -> set[str]:
    return set(PARTITION_PATTERN.findall(output))


def require_payload_partitions(actual: set[str], expected: set[str]) -> None:
    missing = sorted(expected - actual)
    if missing:
        raise ValueError(f"payload is missing firmware partitions: {', '.join(missing)}")


def load_firmware_manifest(path: Path) -> dict:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if payload.get("schemaVersion") != 1 or payload.get("device") != "fleur":
        raise ValueError("unsupported firmware manifest")
    names = set()
    for partition in payload.get("partitions", []):
        name = partition["name"]
        if name in names:
            raise ValueError(f"duplicate firmware partition: {name}")
        names.add(name)
        if partition["size"] <= 0 or not re.fullmatch(r"[0-9a-f]{64}", partition["sha256"]):
            raise ValueError(f"invalid firmware metadata: {name}")
    if not names:
        raise ValueError("firmware manifest has no partitions")
    return payload


def verify_normalized_image(
    extracted_path: Path,
    vendor_path: Path,
    *,
    expected_size: int,
    expected_sha256: str,
) -> dict:
    extracted_path = Path(extracted_path)
    vendor_path = Path(vendor_path)
    vendor_size = vendor_path.stat().st_size
    if vendor_size != expected_size:
        raise ValueError(
            f"vendor size mismatch for {vendor_path.name}: expected {expected_size}, found {vendor_size}"
        )
    vendor_sha256 = sha256_file(vendor_path)
    if vendor_sha256 != expected_sha256:
        raise ValueError(
            f"vendor SHA-256 mismatch for {vendor_path.name}: expected {expected_sha256}, found {vendor_sha256}"
        )
    extracted_size = extracted_path.stat().st_size
    if extracted_size < vendor_size:
        raise ValueError(f"extracted image is shorter than vendor input: {extracted_path.name}")

    with vendor_path.open("rb") as vendor, extracted_path.open("rb") as extracted:
        while True:
            vendor_chunk = vendor.read(CHUNK_SIZE)
            if not vendor_chunk:
                break
            if extracted.read(len(vendor_chunk)) != vendor_chunk:
                raise ValueError(f"payload prefix differs from vendor input: {extracted_path.name}")
        for tail in iter(lambda: extracted.read(CHUNK_SIZE), b""):
            if any(tail):
                raise ValueError(f"payload contains non-zero padding after vendor input: {extracted_path.name}")

    return {
        "sourceSize": vendor_size,
        "sourceSha256": vendor_sha256,
        "extractedSize": extracted_size,
    }


def verify_git_revision(repository: Path, expected_revision: str) -> str:
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=repository,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    if result.returncode != 0:
        raise ValueError(f"cannot read vendor revision: {result.stdout.strip()}")
    actual = result.stdout.strip()
    if actual != expected_revision:
        raise ValueError(
            f"vendor revision mismatch: expected {expected_revision}, found {actual}"
        )
    return actual


def _run_checked(command: list[str], *, cwd: Path, timeout: int = 600) -> str:
    result = subprocess.run(
        command,
        cwd=cwd,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=timeout,
    )
    if result.returncode != 0:
        raise ValueError(f"command failed ({result.returncode}): {' '.join(command)}\n{result.stdout}")
    return result.stdout


def verify_zip_with_unzip(path: Path) -> dict:
    """Verify a ZIP through both Python's reader and the platform unzip tool."""
    path = Path(path)
    if not path.is_file() or path.is_symlink():
        raise ValueError(f"ZIP does not exist as a regular file: {path}")
    try:
        with zipfile.ZipFile(path) as archive:
            names: set[str] = set()
            for member in archive.infolist():
                name = member.filename
                parts = name.split("/")
                mode = (member.external_attr >> 16) & 0o170000
                if (
                    not name
                    or "\x00" in name
                    or "\\" in name
                    or name.startswith("/")
                    or (len(name) > 1 and name[1] == ":" and name[0].isalpha())
                    or ".." in parts
                    or any(part in {"", "."} for part in parts[:-1])
                ):
                    raise ValueError(f"ZIP has unsafe member: {name!r}")
                if mode == stat.S_IFLNK:
                    raise ValueError(f"ZIP has symlink member: {name}")
                if name in names:
                    raise ValueError(f"ZIP has duplicate member: {name}")
                names.add(name)
            if archive.testzip() is not None:
                raise ValueError(f"ZIP member CRC failed: {path.name}")
    except zipfile.BadZipFile as error:
        raise ValueError(f"unzip -t rejected {path.name}: {error}") from error
    result = subprocess.run(
        ["unzip", "-t", str(path)],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    if result.returncode != 0:
        raise ValueError(f"unzip -t rejected {path.name}: {result.stdout.strip()}")
    return {
        "status": "verified",
        "name": path.name,
        "size": path.stat().st_size,
        "sha256": sha256_file(path),
    }


def verify_payload_firmware(
    archive: zipfile.ZipFile,
    android_top: Path,
    firmware_manifest_path: Path,
) -> dict:
    android_top = Path(android_top).resolve()
    payload_info = android_top / "system/update_engine/scripts/payload_info.py"
    extractor = android_top / "out/host/linux-x86/bin/ota_extractor"
    vendor_root = android_top / "vendor/xiaomi/fleur"
    if not payload_info.is_file():
        raise ValueError(f"missing official payload_info.py: {payload_info}")
    if not extractor.is_file():
        raise ValueError(f"missing ota_extractor: {extractor}; run: m ota_extractor")
    if not vendor_root.is_dir():
        raise ValueError(f"missing pinned vendor tree: {vendor_root}")

    firmware = load_firmware_manifest(firmware_manifest_path)
    vendor_revision = verify_git_revision(vendor_root, firmware["vendorRevision"])
    expected = {partition["name"] for partition in firmware["partitions"]}
    with tempfile.TemporaryDirectory(prefix="flowerbed-payload-") as directory:
        temporary = Path(directory)
        payload_path = temporary / "payload.bin"
        output_dir = temporary / "images"
        output_dir.mkdir()
        with archive.open("payload.bin") as source, payload_path.open("wb") as target:
            shutil.copyfileobj(source, target, CHUNK_SIZE)

        info_output = _run_checked(
            [sys.executable, str(payload_info), str(payload_path)],
            cwd=android_top,
        )
        actual = parse_payload_partitions(info_output)
        require_payload_partitions(actual, expected)
        names = sorted(expected)
        _run_checked(
            [
                str(extractor),
                f"--payload={payload_path}",
                f"--output_dir={output_dir}",
                f"--partitions={','.join(names)}",
            ],
            cwd=android_top,
        )

        partitions = []
        by_name = {partition["name"]: partition for partition in firmware["partitions"]}
        for name in names:
            item = by_name[name]
            extracted_path = output_dir / f"{name}.img"
            if not extracted_path.is_file():
                raise ValueError(f"ota_extractor did not produce {name}.img")
            vendor_path = vendor_root / item["file"]
            if not vendor_path.is_file():
                raise ValueError(f"missing pinned vendor image: {vendor_path}")
            result = verify_normalized_image(
                extracted_path,
                vendor_path,
                expected_size=item["size"],
                expected_sha256=item["sha256"],
            )
            partitions.append({"name": name, **result})

    return {
        "status": "verified",
        "vendorRevision": vendor_revision,
        "archiveVersion": firmware["archivePackage"]["version"],
        "partitions": partitions,
        "payloadInfo": str(payload_info.relative_to(android_top)),
    }


def _write_checksums(path: Path, entries: list[tuple[str, Path]]) -> None:
    content = "".join(f"{digest}  {item.name}\n" for digest, item in entries)
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", newline="\n", dir=path.parent, delete=False
    ) as handle:
        handle.write(content)
        temporary = Path(handle.name)
    temporary.replace(path)


def verify(args: argparse.Namespace) -> dict:
    ota = args.ota.resolve()
    if not ota.is_file():
        raise ValueError(f"OTA ZIP does not exist: {ota}")
    verify_zip_with_unzip(ota)
    try:
        with zipfile.ZipFile(ota) as archive:
            corrupt = archive.testzip()
            if corrupt:
                raise ValueError(f"corrupt ZIP member: {corrupt}")
            names = set(archive.namelist())
            missing = sorted(REQUIRED_OTA_FILES - names)
            if missing:
                raise ValueError(f"OTA ZIP is missing: {', '.join(missing)}")
            metadata = parse_metadata(archive.read("META-INF/com/android/metadata"))
            devices = set(filter(None, metadata.get("pre-device", "").split(",")))
            if "fleur" not in devices:
                raise ValueError(f"expected fleur in pre-device, found: {','.join(sorted(devices)) or '<empty>'}")
            if metadata.get("ota-type") != "AB":
                raise ValueError(f"expected ota-type=AB, found: {metadata.get('ota-type', '<empty>')}")
            firmware = {"status": "not-run"}
            if args.android_top or args.firmware_manifest:
                if not args.android_top or not args.firmware_manifest:
                    raise ValueError("--android-top and --firmware-manifest must be supplied together")
                firmware = verify_payload_firmware(
                    archive,
                    args.android_top,
                    args.firmware_manifest,
                )
    except zipfile.BadZipFile as error:
        raise ValueError(f"invalid OTA ZIP: {error}") from error

    ota_hash = sha256_file(ota)
    entries = [(ota_hash, ota)]
    boot_report = None
    if args.boot_image:
        boot = args.boot_image.resolve()
        if not boot.is_file():
            raise ValueError(f"boot image does not exist: {boot}")
        boot_hash = sha256_file(boot)
        entries.append((boot_hash, boot))
        boot_report = {"name": boot.name, "sha256": boot_hash, "size": boot.stat().st_size}
    _write_checksums(ota.parent / "SHA256SUMS", entries)
    return {
        "device": "fleur",
        "otaType": "AB",
        "name": ota.name,
        "size": ota.stat().st_size,
        "sha256": ota_hash,
        "bootImage": boot_report,
        "firmware": firmware,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify a LineageOS fleur OTA and its firmware payload")
    parser.add_argument("ota", type=Path)
    parser.add_argument("--boot-image", type=Path)
    parser.add_argument("--android-top", type=Path)
    parser.add_argument("--firmware-manifest", type=Path)
    args = parser.parse_args()
    try:
        report = verify(args)
    except (OSError, ValueError, subprocess.TimeoutExpired) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
