#!/usr/bin/env python3
"""Create and validate immutable two-phase fleur kernel build provenance."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import struct
import subprocess
import tempfile
from typing import Mapping, Sequence
import zipfile


class BuildProvenanceError(RuntimeError):
    """Raised when build provenance cannot be established exactly."""


HEX40 = re.compile(r"[0-9a-f]{40}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
TIMESTAMP = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\Z")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _canonical_hash(value: Mapping[str, object]) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(payload).hexdigest()


def _regular(path: Path, label: str) -> Path:
    path = Path(path)
    try:
        metadata = path.lstat()
    except OSError as error:
        raise BuildProvenanceError(f"{label} is unavailable") from error
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise BuildProvenanceError(f"{label} must be a regular non-symlink file")
    return path


def _run(command: Sequence[str | Path], cwd: Path, *, check: bool = True) -> subprocess.CompletedProcess[str]:
    result = subprocess.run([str(item) for item in command], cwd=cwd, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if check and result.returncode:
        raise BuildProvenanceError(f"command failed: {Path(command[0]).name}: {result.stdout.strip()}")
    return result


def _policy_fields(policy: Mapping[str, object]) -> dict[str, str]:
    required = ("project", "file", "base_commit", "patch_sha256", "application_script", "application_script_sha256")
    if set(required) - set(policy):
        raise BuildProvenanceError("kernel policy is incomplete")
    result = {name: policy[name] for name in required}
    if not all(isinstance(value, str) and value for value in result.values()):
        raise BuildProvenanceError("kernel policy fields are invalid")
    if not HEX40.fullmatch(result["base_commit"]):
        raise BuildProvenanceError("kernel policy base commit is invalid")
    for name in ("patch_sha256", "application_script_sha256"):
        if not HEX64.fullmatch(result[name]):
            raise BuildProvenanceError(f"kernel policy {name} is invalid")
    source = Path(result["file"])
    if source.is_absolute() or ".." in source.parts:
        raise BuildProvenanceError("kernel policy source path is invalid")
    return result


def _write_once(path: Path, value: Mapping[str, object]) -> None:
    path = Path(path)
    payload = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()
    descriptor = -1
    temporary: Path | None = None
    try:
        descriptor, raw_temporary = tempfile.mkstemp(
            prefix=f".{path.name}.tmp-", dir=path.parent
        )
        temporary = Path(raw_temporary)
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if not written:
                raise BuildProvenanceError("short provenance write")
            view = view[written:]
        os.fchmod(descriptor, 0o444)
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        try:
            os.link(temporary, path, follow_symlinks=False)
        except FileExistsError as error:
            raise BuildProvenanceError(f"provenance output already exists: {path.name}") from error
        directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def _boot_bytes(target_files: Path) -> bytes:
    _regular(target_files, "unsigned target-files")
    try:
        with zipfile.ZipFile(target_files) as archive:
            matches = [item for item in archive.infolist() if item.filename == "IMAGES/boot.img"]
            if len(matches) != 1:
                raise BuildProvenanceError("unsigned target-files must contain exactly one boot image")
            return archive.read(matches[0])
    except zipfile.BadZipFile as error:
        raise BuildProvenanceError("unsigned target-files is not a ZIP") from error


def normalized_boot_sha256(boot: bytes) -> str:
    content = boot
    if len(boot) >= 64 and boot[-64:-60] == b"AVBf":
        try:
            _magic, major, _minor, original_size, _vbmeta_offset, _vbmeta_size, _reserved = struct.unpack(">4sIIQQQ28s", boot[-64:])
        except struct.error as error:
            raise BuildProvenanceError("boot AVB footer is malformed") from error
        if major != 1 or original_size <= 0 or original_size > len(boot) - 64:
            raise BuildProvenanceError("boot AVB footer original image size is invalid")
        content = boot[:original_size]
    return hashlib.sha256(content).hexdigest()


def create_pre_build_provenance(kernel_root: Path, policy: Mapping[str, object], patch: Path, application_script: Path, output: Path, *, timestamp: str, nonce: str) -> dict[str, object]:
    kernel_root = Path(kernel_root)
    fields = _policy_fields(policy)
    patch = _regular(patch, "kernel patch")
    application_script = _regular(application_script, "patch application script")
    source = _regular(kernel_root / fields["file"], "post-fix kernel source")
    if not TIMESTAMP.fullmatch(timestamp) or not HEX64.fullmatch(nonce):
        raise BuildProvenanceError("pre-build timestamp or session nonce is invalid")
    if sha256_file(patch) != fields["patch_sha256"]:
        raise BuildProvenanceError("kernel patch differs from policy")
    if sha256_file(application_script) != fields["application_script_sha256"]:
        raise BuildProvenanceError("patch application script differs from policy")
    if _run(("git", "rev-parse", "HEAD"), kernel_root).stdout.strip() != fields["base_commit"]:
        raise BuildProvenanceError("kernel checkout base commit differs from policy")
    forward = _run(("git", "apply", "--check", patch), kernel_root, check=False).returncode == 0
    reverse = _run(("git", "apply", "--reverse", "--check", patch), kernel_root, check=False).returncode == 0
    if forward or not reverse:
        raise BuildProvenanceError("kernel patch is registered but unapplied or ambiguously applied")
    evidence = {**fields, "post_fix_source_sha256": sha256_file(source), "forward_applicable": False, "reverse_applicable": True}
    record: dict[str, object] = {
        "schema_version": 1, "state": "pre-build", "device": "fleur", "session_nonce": nonce,
        "pre_build": {**evidence, "timestamp": timestamp, "application_evidence_sha256": _canonical_hash(evidence)},
    }
    _write_once(output, record)
    return record


def _load(path: Path) -> dict[str, object]:
    _regular(path, "build provenance")
    try:
        value = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise BuildProvenanceError("build provenance is invalid JSON") from error
    if not isinstance(value, dict):
        raise BuildProvenanceError("build provenance must be an object")
    return value


def finalize_build_provenance(pre_build_path: Path, unsigned_target_files: Path, output: Path) -> dict[str, object]:
    record = _load(pre_build_path)
    if record.get("state") != "pre-build":
        raise BuildProvenanceError("only a pre-build provenance record can be finalized")
    boot = _boot_bytes(unsigned_target_files)
    target = _regular(unsigned_target_files, "unsigned target-files")
    finalized = dict(record)
    finalized["state"] = "finalized"
    finalized["unsigned_target_files"] = {
        "filename": target.name, "size": target.stat().st_size, "sha256": sha256_file(target),
        "boot_raw_sha256": hashlib.sha256(boot).hexdigest(), "boot_content_sha256": normalized_boot_sha256(boot),
    }
    _write_once(output, finalized)
    return finalized


def validate_final_build_provenance(provenance: Path | Mapping[str, object], unsigned_target_files: Path, policy: Mapping[str, object], patch: Path, application_script: Path, *, target_filename: str | None = None) -> dict[str, object]:
    record = _load(provenance) if isinstance(provenance, (str, Path)) else dict(provenance)
    if set(record) != {"schema_version", "state", "device", "session_nonce", "pre_build", "unsigned_target_files"}:
        raise BuildProvenanceError("final build provenance fields are not exact")
    if record.get("schema_version") != 1 or record.get("state") != "finalized" or record.get("device") != "fleur":
        raise BuildProvenanceError("final build provenance schema/state/device is invalid")
    if not isinstance(record.get("session_nonce"), str) or not HEX64.fullmatch(record["session_nonce"]):
        raise BuildProvenanceError("build provenance session nonce is invalid")
    fields = _policy_fields(policy)
    pre = record.get("pre_build")
    if not isinstance(pre, dict):
        raise BuildProvenanceError("pre-build proof is missing")
    exact_pre = set(fields) | {"post_fix_source_sha256", "forward_applicable", "reverse_applicable", "timestamp", "application_evidence_sha256"}
    if set(pre) != exact_pre or any(pre.get(name) != value for name, value in fields.items()):
        raise BuildProvenanceError("pre-build proof does not match kernel policy")
    if pre.get("forward_applicable") is not False or pre.get("reverse_applicable") is not True:
        raise BuildProvenanceError("kernel patch application proof is invalid")
    if not isinstance(pre.get("post_fix_source_sha256"), str) or not HEX64.fullmatch(pre["post_fix_source_sha256"]):
        raise BuildProvenanceError("post-fix kernel source hash is invalid")
    if not isinstance(pre.get("timestamp"), str) or not TIMESTAMP.fullmatch(pre["timestamp"]):
        raise BuildProvenanceError("pre-build timestamp is invalid")
    evidence = {name: pre[name] for name in fields}
    evidence.update({"post_fix_source_sha256": pre["post_fix_source_sha256"], "forward_applicable": False, "reverse_applicable": True})
    if pre.get("application_evidence_sha256") != _canonical_hash(evidence):
        raise BuildProvenanceError("application evidence hash is invalid")
    if sha256_file(_regular(patch, "kernel patch")) != fields["patch_sha256"]:
        raise BuildProvenanceError("kernel patch differs from final provenance")
    if sha256_file(_regular(application_script, "patch application script")) != fields["application_script_sha256"]:
        raise BuildProvenanceError("application script differs from final provenance")
    target = _regular(unsigned_target_files, "unsigned target-files")
    boot = _boot_bytes(target)
    expected = {
        "filename": target.name if target_filename is None else target_filename,
        "size": target.stat().st_size, "sha256": sha256_file(target),
        "boot_raw_sha256": hashlib.sha256(boot).hexdigest(), "boot_content_sha256": normalized_boot_sha256(boot),
    }
    if record.get("unsigned_target_files") != expected:
        raise BuildProvenanceError("build provenance does not bind exact unsigned target-files and boot")
    return record


def _load_policy(path: Path) -> dict[str, object]:
    _regular(path, "kernel policy")
    try:
        value = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise BuildProvenanceError("kernel policy is invalid JSON") from error
    if not isinstance(value, dict):
        raise BuildProvenanceError("kernel policy must be an object")
    return value


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    pre = commands.add_parser("pre-build")
    pre.add_argument("--kernel-root", required=True, type=Path)
    pre.add_argument("--kernel-policy", required=True, type=Path)
    pre.add_argument("--patch", required=True, type=Path)
    pre.add_argument("--application-script", required=True, type=Path)
    pre.add_argument("--timestamp", required=True)
    pre.add_argument("--session-nonce", required=True)
    pre.add_argument("--output", required=True, type=Path)
    final = commands.add_parser("finalize")
    final.add_argument("--pre-build", required=True, type=Path)
    final.add_argument("--unsigned-target-files", required=True, type=Path)
    final.add_argument("--output", required=True, type=Path)
    verify = commands.add_parser("validate")
    verify.add_argument("--provenance", required=True, type=Path)
    verify.add_argument("--unsigned-target-files", required=True, type=Path)
    verify.add_argument("--kernel-policy", required=True, type=Path)
    verify.add_argument("--patch", required=True, type=Path)
    verify.add_argument("--application-script", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        if args.command == "pre-build":
            result = create_pre_build_provenance(
                args.kernel_root, _load_policy(args.kernel_policy), args.patch,
                args.application_script, args.output, timestamp=args.timestamp,
                nonce=args.session_nonce,
            )
        elif args.command == "finalize":
            result = finalize_build_provenance(
                args.pre_build, args.unsigned_target_files, args.output
            )
        else:
            result = validate_final_build_provenance(
                args.provenance, args.unsigned_target_files,
                _load_policy(args.kernel_policy), args.patch,
                args.application_script,
            )
    except BuildProvenanceError as error:
        print(f"build provenance failed: {error}", file=os.sys.stderr)
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
