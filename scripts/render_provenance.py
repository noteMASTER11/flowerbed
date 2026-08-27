#!/usr/bin/env python3
import argparse
import json
from pathlib import Path
import re
import tempfile


ALLOWED_STATUSES = {
    "verified-current",
    "candidate-current",
    "historical",
    "modified",
    "unknown",
}
HEX_40 = re.compile(r"^[0-9a-f]{40}$")
HEX_64 = re.compile(r"^[0-9a-f]{64}$")


def _read_json(path: Path) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _require_https(urls, label: str) -> None:
    if not urls or any(not url.startswith("https://") for url in urls):
        raise ValueError(f"{label} must contain HTTPS evidence")


def load_provenance(path: Path) -> dict:
    payload = _read_json(path)
    if payload.get("schemaVersion") != 1:
        raise ValueError("unsupported provenance schema")
    ids = set()
    for item in payload.get("sourceSets", []):
        if item["id"] in ids:
            raise ValueError(f"duplicate source set: {item['id']}")
        ids.add(item["id"])
        if item["status"] not in ALLOWED_STATUSES:
            raise ValueError(f"unsupported source status: {item['status']}")
        paths = [repository["path"] for repository in item["repositories"]]
        if len(paths) != len(set(paths)):
            raise ValueError(f"duplicate repository path in {item['id']}")
        _require_https(item["evidence"], f"source set {item['id']}")
    for finding in payload.get("findings", []):
        _require_https(finding["evidence"], f"finding {finding['channel']}")
    return payload


def load_firmware(path: Path) -> dict:
    payload = _read_json(path)
    if payload.get("schemaVersion") != 1 or payload.get("device") != "fleur":
        raise ValueError("unsupported firmware registry")
    if not HEX_40.fullmatch(payload.get("vendorRevision", "")):
        raise ValueError("vendor revision must be a full Git SHA")
    package = payload["archivePackage"]
    if not package["url"].startswith("https://") or not HEX_64.fullmatch(package["sha256"]):
        raise ValueError("invalid firmware archive provenance")
    names = set()
    for partition in payload.get("partitions", []):
        name = partition["name"]
        if name in names:
            raise ValueError(f"duplicate firmware partition: {name}")
        names.add(name)
        if partition["size"] <= 0 or not HEX_64.fullmatch(partition["sha256"]):
            raise ValueError(f"invalid firmware metadata: {name}")
        if partition["xfuPrefixMatch"] not in (True, False, None):
            raise ValueError(f"invalid XFU match state: {name}")
    return payload


def _cell(value: str) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")


def render(path: Path, firmware_path: Path) -> str:
    payload = load_provenance(path)
    firmware = load_firmware(firmware_path)
    lines = [
        "# fleur source provenance",
        "",
        f"Retrieved: {payload['retrievedAt']}",
        "",
        "## Source sets",
        "",
        "| ID | ROM | Status | Repositories | Evidence | Notes |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for item in sorted(payload["sourceSets"], key=lambda value: value["id"]):
        repositories = "<br>".join(
            f"`{repository['path']}` → `{repository['repository']}@{repository['revision']}`"
            for repository in sorted(item["repositories"], key=lambda value: value["path"])
        )
        evidence = "<br>".join(
            f"[source {index}]({url})" for index, url in enumerate(item["evidence"], 1)
        )
        lines.append(
            f"| `{item['id']}` | {_cell(item['rom'])} | `{item['status']}` | "
            f"{repositories} | {evidence} | {_cell(item['notes'])} |"
        )
    lines.extend([
        "",
        "## Bounded forum and archive findings",
        "",
    ])
    for finding in sorted(payload["findings"], key=lambda value: value["channel"]):
        evidence = ", ".join(
            f"[source {index}]({url})" for index, url in enumerate(finding["evidence"], 1)
        )
        lines.append(f"- **{finding['channel']}:** {finding['result']} ({evidence})")
    package = firmware["archivePackage"]
    lines.extend([
        "",
        "## Firmware payload",
        "",
        f"Pinned vendor: `{firmware['vendorRepository']}@{firmware['vendorRevision']}`",
        "",
        f"Archive match: `{package['version']}` ({package['region']}); "
        f"package SHA-256 `{package['sha256']}` ([download]({package['url']})).",
        "",
        "| Partition | Vendor file | Bytes | SHA-256 | XFU prefix match |",
        "| --- | --- | ---: | --- | --- |",
    ])
    for partition in sorted(firmware["partitions"], key=lambda value: value["name"]):
        match = {True: "yes", False: "no", None: "not present in comparison ZIP"}[
            partition["xfuPrefixMatch"]
        ]
        lines.append(
            f"| `{partition['name']}` | `{partition['file']}` | {partition['size']} | "
            f"`{partition['sha256']}` | {match} |"
        )
    lines.extend([
        "",
        f"Metadata discrepancy: {firmware['metadataDiscrepancy']}",
        "",
    ])
    return "\n".join(lines)


def _write_atomic(path: Path, content: str) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", newline="\n", dir=path.parent, delete=False
    ) as handle:
        handle.write(content)
        temporary = Path(handle.name)
    temporary.replace(path)


def main() -> int:
    parser = argparse.ArgumentParser(description="Render fleur source and firmware provenance")
    parser.add_argument("provenance", type=Path)
    parser.add_argument("--firmware", required=True, type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    content = render(args.provenance, args.firmware)
    if args.output:
        _write_atomic(args.output, content)
    else:
        print(content, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
