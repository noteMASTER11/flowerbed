#!/usr/bin/env python3
"""Build a statically verifiable SP Flash Tool V6 reference package for fleur."""

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import sys
import tempfile
import xml.etree.ElementTree as ET
import zipfile


CHUNK_SIZE = 1024 * 1024
BUILD_IMAGES = {
    "boot.img": "boot.img",
    "dtbo.img": "dtbo.img",
    "vbmeta.img": "vbmeta.img",
    "vbmeta_system.img": "vbmeta_system.img",
    "vbmeta_vendor.img": "vbmeta_vendor.img",
    "super.img": "super.img",
}
FIRMWARE_IMAGES = {
    "audio_dsp.img": "audio_dsp.img",
    "gz.img": "gz.img",
    "lk.img": "lk.img",
    "logo.img": "logo.bin",
    "md1img.img": "md1img.img",
    "pi_img.img": "pi_img.img",
    "preloader_raw.img": "preloader_raw.img",
    "scp.img": "scp.img",
    "spmfw.img": "spmfw.img",
    "sspm.img": "sspm.img",
    "tee.img": "tee.img",
}
ENABLED_PARTITIONS = {
    "vbmeta_a": "vbmeta.img",
    "vbmeta_system_a": "vbmeta_system.img",
    "vbmeta_vendor_a": "vbmeta_vendor.img",
    "md1img_a": "md1img.img",
    "spmfw_a": "spmfw.img",
    "audio_dsp_a": "audio_dsp.img",
    "pi_img_a": "pi_img.img",
    "scp_a": "scp.img",
    "sspm_a": "sspm.img",
    "gz_a": "gz.img",
    "lk_a": "lk.img",
    "boot_a": "boot.img",
    "dtbo_a": "dtbo.img",
    "tee_a": "tee.img",
    "logo_a": "logo.bin",
    "super": "super.img",
}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(CHUNK_SIZE), b""):
            digest.update(chunk)
    return digest.hexdigest()


def copy_required(source_dir: Path, mapping: dict[str, str], images_dir: Path) -> None:
    for source_name, output_name in mapping.items():
        source = source_dir / source_name
        if not source.is_file():
            raise ValueError(f"missing required image: {source}")
        shutil.copy2(source, images_dir / output_name)


def verify_firmware_manifest(manifest_path: Path, firmware_dir: Path) -> dict:
    payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    if payload.get("schemaVersion") != 1 or payload.get("device") != "fleur":
        raise ValueError("unsupported firmware manifest")
    partitions = payload.get("partitions", [])
    by_file = {Path(item["file"]).name: item for item in partitions}
    expected = set(FIRMWARE_IMAGES)
    if set(by_file) != expected:
        missing = sorted(expected - set(by_file))
        extra = sorted(set(by_file) - expected)
        raise ValueError(
            "firmware manifest file set mismatch: "
            f"missing={','.join(missing) or '<none>'}; "
            f"extra={','.join(extra) or '<none>'}"
        )
    verified = []
    for name in sorted(expected):
        image = firmware_dir / name
        if not image.is_file():
            raise ValueError(f"missing required image: {image}")
        item = by_file[name]
        actual_size = image.stat().st_size
        if actual_size != item.get("size"):
            raise ValueError(
                f"firmware size mismatch for {name}: expected {item.get('size')}, "
                f"found {actual_size}"
            )
        actual_hash = sha256_file(image)
        if actual_hash != item.get("sha256"):
            raise ValueError(
                f"firmware SHA-256 mismatch for {name}: expected {item.get('sha256')}, "
                f"found {actual_hash}"
            )
        verified.append({"file": name, "size": actual_size, "sha256": actual_hash})
    return {"manifest": str(manifest_path), "partitions": verified}


def copy_download_agent(source_dir: Path, images_dir: Path) -> dict:
    required = {"DA_BR.bin", "flash.xml", "flash.xsd"}
    missing = sorted(name for name in required if not (source_dir / name).is_file())
    if missing:
        raise ValueError(f"download agent is missing: {', '.join(missing)}")
    wrapper = ET.parse(source_dir / "flash.xml")
    root = wrapper.getroot()
    if root.tag != "flash-mode":
        raise ValueError("download agent flash.xml root is not flash-mode")
    expected = {
        "project": "fleur",
        "dagent": "DA_BR.bin",
        "scatter": "../MT6781_Android_scatter.xml",
    }
    for element, value in expected.items():
        actual = root.findtext(element)
        if actual != value:
            raise ValueError(
                f"download agent flash.xml {element} mismatch: expected {value}, found {actual}"
            )
    if (source_dir / "DA_BR.bin").stat().st_size == 0:
        raise ValueError("download agent DA_BR.bin is empty")
    destination = images_dir / "download_agent"
    destination.mkdir()
    for name in sorted(required):
        shutil.copy2(source_dir / name, destination / name)
    return {"directory": str(source_dir), "files": sorted(required)}


def adapt_download_xml(template: Path, destination: Path, images_dir: Path) -> list[dict]:
    tree = ET.parse(template)
    root = tree.getroot()
    if root.findtext("./general/config_version/platform") != "MT6781":
        raise ValueError("Download-XML platform is not MT6781")
    if root.findtext("./general/config_version/project") != "fleur":
        raise ValueError("Download-XML project is not fleur")

    enabled = []
    storage_types = root.findall("./storage_type")
    if not storage_types:
        raise ValueError("Download-XML has no storage_type entries")
    for storage in storage_types:
        storage_name = storage.get("name", "unknown")
        found = set()
        for item in storage.findall("./partition_index"):
            name = item.findtext("partition_name")
            file_element = item.find("file_name")
            download_element = item.find("is_download")
            if file_element is None or download_element is None:
                raise ValueError(f"malformed partition entry: {name or '<unnamed>'}")
            file_element.text = "NONE"
            download_element.text = "false"
            if name not in ENABLED_PARTITIONS:
                continue

            image_name = ENABLED_PARTITIONS[name]
            image = images_dir / image_name
            size_text = item.findtext("partition_size")
            if not size_text:
                raise ValueError(f"missing partition size: {name}")
            limit = int(size_text, 0)
            size = image.stat().st_size
            if size > limit:
                raise ValueError(
                    f"image exceeds partition limit: {image_name} is {size} bytes, "
                    f"{name} allows {limit} bytes"
                )
            file_element.text = image_name
            download_element.text = "true"
            found.add(name)
            enabled.append(
                {
                    "storage": storage_name,
                    "partition": name,
                    "image": image_name,
                    "size": size,
                    "limit": limit,
                }
            )

        missing = sorted(set(ENABLED_PARTITIONS) - found)
        if missing:
            raise ValueError(
                f"Download-XML storage {storage_name} is missing required partitions: "
                f"{', '.join(missing)}"
            )
    ET.indent(tree, space="  ")
    tree.write(destination, encoding="utf-8", xml_declaration=True)
    return enabled


def write_readme(path: Path) -> None:
    path.write_text(
        "LineageOS 23.2 fleur - SP Flash Tool V6 reference package\n"
        "===========================================================\n\n"
        "Status: statically verified, not device-validated.\n\n"
        "1. In SP Flash Tool V6, choose images/download_agent/flash.xml "
        "as Download-XML.\n"
        "2. Authentication is not required; leave it blank.\n"
        "3. Use Download Only mode.\n"
        "4. Verify the displayed project is fleur and the platform is MT6781.\n\n"
        "The preloader, preloader_backup, cust, rescue, userdata, B-slot, "
        "and unknown template entries are disabled. The package writes the "
        "approved A-slot images and super only. preloader_raw.img is included "
        "for pinned-firmware provenance but is deliberately not mapped to a "
        "downloadable preloader partition.\n\n"
        "Do not use Format All + Download. Back up device-specific calibration "
        "and radio data before any manual flashing.\n",
        encoding="utf-8",
        newline="\n",
    )


def write_checksums(package_dir: Path) -> list[dict]:
    entries = []
    for path in sorted(item for item in package_dir.rglob("*") if item.is_file()):
        if path.name == "SHA256SUMS":
            continue
        relative = path.relative_to(package_dir).as_posix()
        entries.append(
            {"path": relative, "size": path.stat().st_size, "sha256": sha256_file(path)}
        )
    content = "".join(f"{item['sha256']}  {item['path']}\n" for item in entries)
    (package_dir / "SHA256SUMS").write_text(content, encoding="utf-8", newline="\n")
    return entries


def create_archive(package_dir: Path, archive: Path) -> None:
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_STORED, allowZip64=True) as handle:
        for path in sorted(item for item in package_dir.rglob("*") if item.is_file()):
            arcname = Path(package_dir.name) / path.relative_to(package_dir)
            handle.write(path, arcname.as_posix())


def package(args: argparse.Namespace) -> dict:
    template = args.scatter_xml.resolve()
    product_out = args.product_out.resolve()
    firmware_dir = args.firmware_dir.resolve()
    firmware_manifest = args.firmware_manifest.resolve()
    download_agent_dir = args.download_agent_dir.resolve()
    output_dir = args.output_dir.resolve()
    if not template.is_file():
        raise ValueError(f"Download-XML template does not exist: {template}")
    if not firmware_manifest.is_file():
        raise ValueError(f"firmware manifest does not exist: {firmware_manifest}")
    firmware = verify_firmware_manifest(firmware_manifest, firmware_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    package_dir = output_dir / args.name
    archive = output_dir / f"{args.name}.zip"
    if package_dir.exists() or archive.exists():
        raise ValueError(f"output already exists: {package_dir} or {archive}")

    with tempfile.TemporaryDirectory(prefix=f".{args.name}-", dir=output_dir) as directory:
        temporary = Path(directory)
        images_dir = temporary / "images"
        images_dir.mkdir()
        copy_required(product_out, BUILD_IMAGES, images_dir)
        copy_required(firmware_dir, FIRMWARE_IMAGES, images_dir)
        download_agent = copy_download_agent(download_agent_dir, images_dir)
        enabled = adapt_download_xml(
            template,
            images_dir / "MT6781_Android_scatter.xml",
            images_dir,
        )
        write_readme(temporary / "README.txt")
        files = write_checksums(temporary)
        temporary.replace(package_dir)

    create_archive(package_dir, archive)
    with zipfile.ZipFile(archive) as handle:
        corrupt = handle.testzip()
        if corrupt:
            raise ValueError(f"corrupt ZIP member: {corrupt}")
    return {
        "archive": str(archive),
        "archiveSha256": sha256_file(archive),
        "directory": str(package_dir),
        "enabledPartitions": enabled,
        "files": files,
        "firmware": firmware,
        "downloadAgent": download_agent,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scatter-xml", required=True, type=Path)
    parser.add_argument("--product-out", required=True, type=Path)
    parser.add_argument("--firmware-dir", required=True, type=Path)
    parser.add_argument("--firmware-manifest", required=True, type=Path)
    parser.add_argument("--download-agent-dir", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--name", required=True)
    args = parser.parse_args()
    try:
        report = package(args)
    except (OSError, ValueError, ET.ParseError, zipfile.BadZipFile) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
