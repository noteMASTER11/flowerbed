#!/usr/bin/env python3
"""Generate an encrypted Android/APEX/AVB release keyset atomically."""

from __future__ import annotations

import argparse
import ctypes
from dataclasses import dataclass
import errno
import getpass
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
from typing import Callable, Mapping, Sequence

try:
    from scripts.ubuntu.signing_metadata import SigningInventory, load_signing_inventory
except ModuleNotFoundError:  # Direct execution from scripts/ubuntu.
    from signing_metadata import SigningInventory, load_signing_inventory


class KeyGenerationError(RuntimeError):
    """Raised before an unsafe or incomplete keyset can be published."""


@dataclass(frozen=True)
class KeyPlan:
    android_roles: tuple[str, ...]
    apex_names: tuple[str, ...]
    avb_roles: tuple[str, ...]


CommandRunner = Callable[..., None]
_SAFE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*\Z")
_RENAME_NOREPLACE = 1
_AT_FDCWD = -100


def build_key_plan(source: Path | SigningInventory) -> KeyPlan:
    """Build a deterministic output-key plan from target-files metadata."""
    inventory = load_signing_inventory(source) if isinstance(source, Path) else source
    android_roles = tuple(sorted(inventory.android_roles))
    apex_names = tuple(
        sorted({_apex_key_name(item.name) for item in inventory.apexes if not item.presigned})
    )
    avb_roles = tuple(item.partition for item in inventory.avb_keys)
    for name in (*android_roles, *apex_names, *avb_roles):
        _validate_key_name(name)

    output_bases = [*android_roles, *apex_names, *(f"avb_{role}" for role in avb_roles)]
    if len(output_bases) != len(set(output_bases)):
        raise KeyGenerationError("key metadata produces colliding output names")
    return KeyPlan(android_roles, apex_names, avb_roles)


def validate_private_destination(
    keys_dir: Path, repo_root: Path, android_root: Path
) -> Path:
    """Require a native Linux destination outside source and Android trees."""
    if not keys_dir.is_absolute():
        raise KeyGenerationError("keys directory must be an absolute Linux path")
    lexical = Path(os.path.abspath(os.fspath(keys_dir)))
    if lexical == Path("/mnt") or Path("/mnt") in lexical.parents:
        raise KeyGenerationError("keys directory must not be under /mnt")
    if _has_symlink_component(lexical):
        raise KeyGenerationError("keys directory path must not contain symlinks")

    resolved = lexical.resolve(strict=False)
    if not _is_wsl():
        raise KeyGenerationError("keys directory must be inside WSL")
    if _filesystem_type(resolved) != "ext4":
        raise KeyGenerationError("keys directory must be on the WSL ext4 filesystem")
    for protected, label in ((repo_root, "repository"), (android_root, "Android tree")):
        protected_resolved = protected.resolve(strict=False)
        if resolved == protected_resolved or protected_resolved in resolved.parents:
            raise KeyGenerationError(f"keys directory must be outside the {label}")
    if resolved == Path("/") or resolved.parent == Path("/"):
        raise KeyGenerationError("keys directory is too broad")
    return resolved


def run_command(
    command: Sequence[str],
    *,
    stdin: str | None = None,
    env: Mapping[str, str] | None = None,
) -> None:
    """Run a key-generation command without exposing passphrases in argv."""
    subprocess.run(
        list(command),
        input=stdin,
        text=True,
        env=None if env is None else dict(env),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        check=True,
    )


def generate_keyset(
    target_files: Path,
    android_root: Path,
    keys_dir: Path,
    subject: str,
    *,
    repo_root: Path | None = None,
    runner: CommandRunner = run_command,
    getpass_fn: Callable[[str], str] = getpass.getpass,
    dry_run: bool = False,
) -> Path:
    """Generate the complete protected keyset and publish it with one rename."""
    repository = (
        Path(__file__).resolve().parents[2] if repo_root is None else repo_root
    )
    destination = validate_private_destination(keys_dir, repository, android_root)
    if not subject.strip():
        raise KeyGenerationError("certificate subject must not be blank")
    plan = build_key_plan(target_files)
    _reject_existing_destination(destination, plan)
    if dry_run:
        return destination

    password = getpass_fn("Release-key passphrase: ")
    confirmation = getpass_fn("Confirm release-key passphrase: ")
    if not password:
        raise KeyGenerationError("passphrase must not be blank")
    if password != confirmation:
        raise KeyGenerationError("passphrase confirmation does not match")
    if any(character in password for character in ("\n", "\r", "\x00")):
        raise KeyGenerationError("passphrase cannot be represented safely")

    parent = destination.parent
    parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if _has_symlink_component(parent):
        raise KeyGenerationError("keys directory parent must not contain symlinks")
    staging = Path(tempfile.mkdtemp(prefix=f".{destination.name}.staging-", dir=parent))
    staging.chmod(0o700)
    raw_dir = staging / ".raw"
    public_dir = staging / "public"
    raw_dir.mkdir(mode=0o700)
    public_dir.mkdir(mode=0o700)

    old_umask = os.umask(0o077)
    try:
        _generate_all(plan, staging, raw_dir, public_dir, destination, subject, password, runner)
        shutil.rmtree(raw_dir)
        _write_password_file(
            staging / "passwords",
            _final_password_entries(plan, destination),
            password,
        )
        _write_keyset_manifest(staging / "keyset.json", plan, staging)
        _validate_complete_staging(staging, plan)
        _rename_no_replace(staging, destination)
    except (KeyGenerationError, OSError, subprocess.SubprocessError) as error:
        if staging.exists():
            shutil.rmtree(staging)
        if isinstance(error, KeyGenerationError):
            raise
        raise KeyGenerationError("key generation failed before publication") from error
    finally:
        os.umask(old_umask)
        password = ""
        confirmation = ""
    return destination


def _generate_all(
    plan: KeyPlan,
    staging: Path,
    raw_dir: Path,
    public_dir: Path,
    destination: Path,
    subject: str,
    password: str,
    runner: CommandRunner,
) -> None:
    protected_input = password + "\n"
    for role in plan.android_roles:
        raw_key = raw_dir / f"{role}.raw.pem"
        _run(runner, ["openssl", "genrsa", "-traditional", "-out", raw_key, "2048"])
        _restrict_file(raw_key)
        _derive_container_key(role, raw_key, staging, subject, protected_input, runner)

    encrypted_names = [*plan.apex_names, *(f"avb_{role}" for role in plan.avb_roles)]
    for name in encrypted_names:
        raw_key = raw_dir / f"{name}.raw.pem"
        encrypted_key = staging / f"{name}.pem"
        _run(runner, ["openssl", "genrsa", "-traditional", "-out", raw_key, "4096"])
        _restrict_file(raw_key)
        _run(
            runner,
            [
                "openssl",
                "pkcs8",
                "-in",
                raw_key,
                "-topk8",
                "-out",
                encrypted_key,
                "-passout",
                "stdin",
            ],
            stdin=protected_input,
        )
        _restrict_file(encrypted_key)
        if name in plan.apex_names:
            _derive_container_key(name, raw_key, staging, subject, protected_input, runner)

    temporary_passwords = staging / ".generation-passwords"
    _write_password_file(
        temporary_passwords,
        {str(staging / f"{name}.pem") for name in encrypted_names},
        password,
    )
    helper = Path(__file__).with_name("avb_password_helper.py")
    helper_environment = os.environ.copy()
    helper_environment["ANDROID_PW_FILE"] = str(temporary_passwords)
    helper_environment["ANDROID_SECURE_STORAGE_CMD"] = shlex.join(
        (sys.executable, str(helper), str(temporary_passwords))
    )
    try:
        for name in encrypted_names:
            _run(
                runner,
                [
                    "avbtool",
                    "extract_public_key",
                    "--key",
                    staging / f"{name}.pem",
                    "--output",
                    public_dir / f"{name}.avbpubkey",
                ],
                env=helper_environment,
            )
            _restrict_file(public_dir / f"{name}.avbpubkey")
    finally:
        temporary_passwords.unlink(missing_ok=True)


def _derive_container_key(
    name: str,
    raw_key: Path,
    staging: Path,
    subject: str,
    protected_input: str,
    runner: CommandRunner,
) -> None:
    certificate = staging / f"{name}.x509.pem"
    private_key = staging / f"{name}.pk8"
    _run(
        runner,
        [
            "openssl",
            "req",
            "-new",
            "-x509",
            "-sha256",
            "-key",
            raw_key,
            "-out",
            certificate,
            "-days",
            "10000",
            "-subj",
            subject,
        ],
    )
    _restrict_file(certificate)
    _run(
        runner,
        [
            "openssl",
            "pkcs8",
            "-in",
            raw_key,
            "-topk8",
            "-v1",
            "PBE-SHA1-3DES",
            "-outform",
            "DER",
            "-out",
            private_key,
            "-passout",
            "stdin",
        ],
        stdin=protected_input,
    )
    _restrict_file(private_key)


def _run(
    runner: CommandRunner,
    command: Sequence[str | Path],
    *,
    stdin: str | None = None,
    env: Mapping[str, str] | None = None,
) -> None:
    argv = [str(item) for item in command]
    try:
        runner(argv, stdin=stdin, env=env)
    except (OSError, subprocess.SubprocessError) as error:
        raise KeyGenerationError(f"{Path(argv[0]).name} failed") from error


def _write_password_file(path: Path, names: set[str], password: str) -> None:
    lines = "".join(f"{name}={password}\n" for name in sorted(names))
    _write_exclusive(path, lines.encode("utf-8"))


def _final_password_entries(plan: KeyPlan, destination: Path) -> set[str]:
    entries = {str(destination / role) for role in plan.android_roles}
    for name in plan.apex_names:
        entries.add(str(destination / name))
        entries.add(str(destination / f"{name}.pem"))
    for role in plan.avb_roles:
        entries.add(str(destination / f"avb_{role}.pem"))
    return entries


def _write_keyset_manifest(path: Path, plan: KeyPlan, staging: Path) -> None:
    manifest = {
        "schema_version": 1,
        "android": [
            {"name": role, "certificate_sha256": _sha256(staging / f"{role}.x509.pem")}
            for role in plan.android_roles
        ],
        "apex": [
            {
                "name": name,
                "certificate_sha256": _sha256(staging / f"{name}.x509.pem"),
                "avb_public_key_sha256": _sha256(
                    staging / "public" / f"{name}.avbpubkey"
                ),
            }
            for name in plan.apex_names
        ],
        "avb": [
            {
                "name": f"avb_{role}",
                "partition": role,
                "avb_public_key_sha256": _sha256(
                    staging / "public" / f"avb_{role}.avbpubkey"
                ),
            }
            for role in plan.avb_roles
        ],
    }
    payload = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8")
    _write_exclusive(path, payload)


def _write_exclusive(path: Path, payload: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as output:
            descriptor = -1
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _restrict_file(path: Path) -> None:
    if path.is_symlink() or not path.is_file():
        raise KeyGenerationError("key command did not create a regular output file")
    path.chmod(0o600)


def _validate_complete_staging(staging: Path, plan: KeyPlan) -> None:
    expected_files = _expected_files(plan)
    expected_entries = expected_files | {"public"}
    actual = {
        str(path.relative_to(staging)) for path in staging.rglob("*")
    }
    if actual != expected_entries:
        raise KeyGenerationError("generated keyset is incomplete or inconsistent")
    for directory in (staging, staging / "public"):
        if directory.is_symlink() or not directory.is_dir():
            raise KeyGenerationError("generated keyset contains an invalid directory")
        directory.chmod(0o700)
    for relative in expected_files:
        path = staging / relative
        if path.is_symlink() or not path.is_file():
            raise KeyGenerationError("generated keyset contains an invalid file")
        path.chmod(0o600)


def _expected_files(plan: KeyPlan) -> set[str]:
    files = {"keyset.json", "passwords"}
    for role in plan.android_roles:
        files.update((f"{role}.pk8", f"{role}.x509.pem"))
    for name in plan.apex_names:
        files.update(
            (
                f"{name}.pem",
                f"{name}.pk8",
                f"{name}.x509.pem",
                f"public/{name}.avbpubkey",
            )
        )
    for role in plan.avb_roles:
        name = f"avb_{role}"
        files.update((f"{name}.pem", f"public/{name}.avbpubkey"))
    return files


def _reject_existing_destination(destination: Path, plan: KeyPlan) -> None:
    if destination.parent.exists() and any(
        destination.parent.glob(f".{destination.name}.staging-*")
    ):
        raise KeyGenerationError("abandoned key staging directory requires inspection")
    if not destination.exists() and not destination.is_symlink():
        return
    if destination.is_symlink() or not destination.is_dir():
        raise KeyGenerationError("keys destination already exists and is unsafe")
    manifest_path = destination / "keyset.json"
    if manifest_path.is_symlink() or not manifest_path.is_file():
        raise KeyGenerationError("existing key directory has no valid keyset.json")
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise KeyGenerationError("existing key directory has no valid keyset.json") from error
    if manifest.get("schema_version") != 1:
        raise KeyGenerationError("existing key directory has no valid keyset.json")
    actual = {
        str(path.relative_to(destination))
        for path in destination.rglob("*")
        if path.is_file()
    }
    if actual != _expected_files(plan):
        raise KeyGenerationError("existing key directory is incomplete or inconsistent")
    raise KeyGenerationError("keys destination already contains a complete keyset")


def _rename_no_replace(source: Path, destination: Path) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    renameat2 = getattr(libc, "renameat2", None)
    if renameat2 is None:
        raise KeyGenerationError("atomic no-replace rename is unavailable")
    renameat2.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    ]
    renameat2.restype = ctypes.c_int
    result = renameat2(
        _AT_FDCWD,
        os.fsencode(source),
        _AT_FDCWD,
        os.fsencode(destination),
        _RENAME_NOREPLACE,
    )
    if result != 0:
        code = ctypes.get_errno()
        if code == errno.EEXIST:
            raise KeyGenerationError("keys destination appeared during generation")
        raise OSError(code, os.strerror(code), destination)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _apex_key_name(apex_filename: str) -> str:
    if not apex_filename.endswith(".apex"):
        raise KeyGenerationError("APEX metadata name must end in .apex")
    return apex_filename[: -len(".apex")]


def _validate_key_name(name: str) -> None:
    if not _SAFE_NAME.fullmatch(name) or name in {".", ".."}:
        raise KeyGenerationError("key metadata contains an unsafe output name")


def _has_symlink_component(path: Path) -> bool:
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current /= part
        if current.is_symlink():
            return True
        if not current.exists():
            break
    return False


def _filesystem_type(path: Path) -> str:
    probe = path
    while not probe.exists():
        if probe.parent == probe:
            raise KeyGenerationError("cannot locate keys directory filesystem")
        probe = probe.parent
    probe = probe.resolve()
    matches: list[tuple[int, str]] = []
    try:
        lines = Path("/proc/self/mountinfo").read_text(encoding="utf-8").splitlines()
    except OSError as error:
        raise KeyGenerationError("cannot verify keys directory filesystem") from error
    for line in lines:
        fields = line.split()
        try:
            separator = fields.index("-")
            mountpoint = Path(_unescape_mount_path(fields[4]))
            filesystem = fields[separator + 1]
        except (IndexError, ValueError):
            continue
        if probe == mountpoint or mountpoint in probe.parents:
            matches.append((len(mountpoint.parts), filesystem))
    if not matches:
        raise KeyGenerationError("cannot verify keys directory filesystem")
    return max(matches)[1]


def _is_wsl() -> bool:
    release = platform.release().lower()
    if "microsoft" in release or "wsl" in release:
        return True
    try:
        version = Path("/proc/version").read_text(encoding="utf-8").lower()
    except OSError:
        return False
    return "microsoft" in version or "wsl" in version


def _unescape_mount_path(value: str) -> str:
    return (
        value.replace("\\040", " ")
        .replace("\\011", "\t")
        .replace("\\012", "\n")
        .replace("\\134", "\\")
    )


def _parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target-files", required=True, type=Path)
    parser.add_argument("--android-root", required=True, type=Path)
    parser.add_argument("--keys-dir", required=True, type=Path)
    parser.add_argument("--subject", required=True)
    parser.add_argument("--dry-run", action="store_true")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parse_args(argv)
    try:
        plan = build_key_plan(arguments.target_files)
        if arguments.dry_run:
            destination = validate_private_destination(
                arguments.keys_dir,
                Path(__file__).resolve().parents[2],
                arguments.android_root,
            )
            _reject_existing_destination(destination, plan)
            print(
                json.dumps(
                    {
                        "android_roles": plan.android_roles,
                        "apex_names": plan.apex_names,
                        "avb_roles": plan.avb_roles,
                        "keys_dir": str(destination),
                    },
                    sort_keys=True,
                )
            )
        else:
            generate_keyset(
                arguments.target_files,
                arguments.android_root,
                arguments.keys_dir,
                arguments.subject,
            )
    except KeyGenerationError as error:
        print(f"key generation refused: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
