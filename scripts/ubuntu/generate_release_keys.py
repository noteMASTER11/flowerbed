#!/usr/bin/env python3
"""Generate an encrypted Android/APEX/AVB release keyset atomically."""

from __future__ import annotations

import argparse
from contextlib import contextmanager
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
import secrets
import stat
import subprocess
import sys
from typing import Callable, Mapping, Sequence
import unicodedata

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


@dataclass
class _Workspace:
    destination: Path
    parent_fd: int
    parent_identity: tuple[int, int]
    staging_name: str
    staging_fd: int
    staging_identity: tuple[int, int]
    raw_fd: int
    public_fd: int
    published: bool = False


CommandRunner = Callable[..., None]
_SAFE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*\Z")
_RENAME_NOREPLACE = 1
_DIRECTORY_FLAGS = (
    os.O_RDONLY
    | os.O_DIRECTORY
    | getattr(os, "O_CLOEXEC", 0)
    | getattr(os, "O_NOFOLLOW", 0)
)
_FILE_READ_FLAGS = (
    os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
)
_PATH_FLAGS = (
    getattr(os, "O_PATH", os.O_RDONLY)
    | getattr(os, "O_CLOEXEC", 0)
    | getattr(os, "O_NOFOLLOW", 0)
)
_OPEN_DELIMITER = "[[["
_CLOSE_DELIMITER = "]]]"


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
    """Require a trusted WSL ext4 destination outside all source trees."""
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
    _validate_password_path(str(resolved))
    _validate_trusted_ancestors(resolved.parent)
    return resolved


def run_command(
    command: Sequence[str],
    *,
    stdin: str | None = None,
    env: Mapping[str, str] | None = None,
    pass_fds: Sequence[int] = (),
) -> None:
    """Run a key-generation command without exposing passphrases in argv."""
    subprocess.run(
        list(command),
        input=stdin,
        text=True,
        env=None if env is None else dict(env),
        pass_fds=tuple(pass_fds),
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
    """Generate a complete protected keyset and publish it with one rename."""
    repository = Path(__file__).resolve().parents[2] if repo_root is None else repo_root
    destination = validate_private_destination(keys_dir, repository, android_root)
    if not subject.strip() or "\x00" in subject:
        raise KeyGenerationError("certificate subject is invalid")
    plan = build_key_plan(target_files)
    _reject_existing_destination(destination, plan)
    if dry_run:
        return destination

    password = getpass_fn("Release-key passphrase: ")
    confirmation = getpass_fn("Confirm release-key passphrase: ")
    _validate_passphrase(password)
    if password != confirmation:
        raise KeyGenerationError("passphrase confirmation does not match")

    old_umask = os.umask(0o077)
    try:
        with _workspace_context(destination, plan) as workspace:
            _generate_all(plan, workspace, subject, password, runner)
            _remove_raw_directory(workspace)
            _write_password_file_at(
                workspace.staging_fd,
                "passwords",
                _final_password_entries(plan, destination),
                password,
            )
            _write_keyset_manifest(workspace, plan)
            _validate_complete_staging(workspace, plan)
            _revalidate_workspace(workspace)
            _rename_no_replace_at(
                workspace.parent_fd, workspace.staging_name, destination.name
            )
            workspace.published = True
            os.fsync(workspace.parent_fd)
    finally:
        os.umask(old_umask)
        password = ""
        confirmation = ""
    return destination


@contextmanager
def _workspace_context(destination: Path, plan: KeyPlan):
    workspace = _create_workspace(destination, plan)
    try:
        yield workspace
    except BaseException as error:
        if not workspace.published:
            try:
                if _workspace_is_published(workspace):
                    workspace.published = True
                else:
                    _cleanup_workspace(workspace)
            except BaseException as cleanup_error:
                try:
                    error.add_note(
                        f"staging cleanup also failed: {type(cleanup_error).__name__}"
                    )
                except AttributeError:
                    pass
        raise
    finally:
        _close_workspace(workspace)


def _generate_all(
    plan: KeyPlan,
    workspace: _Workspace,
    subject: str,
    password: str,
    runner: CommandRunner,
) -> None:
    protected_input = password + "\n"
    for role in plan.android_roles:
        raw_name = f"{role}.raw.pem"
        _generate_raw(workspace, raw_name, "2048", runner)
        _derive_container_key(role, raw_name, workspace, subject, protected_input, runner)

    for name in plan.apex_names:
        raw_name = f"{name}.raw.pem"
        _generate_raw(workspace, raw_name, "4096", runner)
        _extract_public(name, raw_name, workspace, runner)
        _derive_container_key(name, raw_name, workspace, subject, protected_input, runner)
        _encrypt_pem(name, raw_name, workspace, protected_input, runner)

    for role in plan.avb_roles:
        name = f"avb_{role}"
        raw_name = f"{name}.raw.pem"
        _generate_raw(workspace, raw_name, "4096", runner)
        _extract_public(name, raw_name, workspace, runner)
        _encrypt_pem(name, raw_name, workspace, protected_input, runner)


def _generate_raw(
    workspace: _Workspace, raw_name: str, bits: str, runner: CommandRunner
) -> None:
    output_fd, identity = _reserve_file(workspace.raw_fd, raw_name)
    try:
        _run(
            workspace,
            runner,
            [
                "openssl",
                "genrsa",
                "-traditional",
                "-out",
                _descriptor_path(output_fd),
                bits,
            ],
            extra_fds=(output_fd,),
        )
        _verify_reserved_file(workspace.raw_fd, raw_name, output_fd, identity)
    finally:
        _close_fd(output_fd)


def _extract_public(
    name: str, raw_name: str, workspace: _Workspace, runner: CommandRunner
) -> None:
    public_name = f"{name}.avbpubkey"
    input_fd = _open_input_file(workspace.raw_fd, raw_name)
    output_fd, identity = _reserve_file(workspace.public_fd, public_name)
    try:
        _run(
            workspace,
            runner,
            [
                "avbtool",
                "extract_public_key",
                "--key",
                _descriptor_path(input_fd),
                "--output",
                _descriptor_path(output_fd),
            ],
            extra_fds=(input_fd, output_fd),
        )
        _verify_reserved_file(
            workspace.public_fd, public_name, output_fd, identity
        )
    finally:
        _close_fd(output_fd)
        _close_fd(input_fd)


def _encrypt_pem(
    name: str,
    raw_name: str,
    workspace: _Workspace,
    protected_input: str,
    runner: CommandRunner,
) -> None:
    encrypted_name = f"{name}.pem"
    input_fd = _open_input_file(workspace.raw_fd, raw_name)
    output_fd, identity = _reserve_file(workspace.staging_fd, encrypted_name)
    try:
        _run(
            workspace,
            runner,
            [
                "openssl",
                "pkcs8",
                "-in",
                _descriptor_path(input_fd),
                "-topk8",
                "-out",
                _descriptor_path(output_fd),
                "-passout",
                "stdin",
            ],
            stdin=protected_input,
            extra_fds=(input_fd, output_fd),
        )
        _verify_reserved_file(
            workspace.staging_fd, encrypted_name, output_fd, identity
        )
    finally:
        _close_fd(output_fd)
        _close_fd(input_fd)


def _derive_container_key(
    name: str,
    raw_name: str,
    workspace: _Workspace,
    subject: str,
    protected_input: str,
    runner: CommandRunner,
) -> None:
    certificate_name = f"{name}.x509.pem"
    input_fd = _open_input_file(workspace.raw_fd, raw_name)
    output_fd, certificate_identity = _reserve_file(
        workspace.staging_fd, certificate_name
    )
    try:
        _run(
            workspace,
            runner,
            [
                "openssl",
                "req",
                "-new",
                "-x509",
                "-sha256",
                "-key",
                _descriptor_path(input_fd),
                "-out",
                _descriptor_path(output_fd),
                "-days",
                "10000",
                "-subj",
                subject,
            ],
            extra_fds=(input_fd, output_fd),
        )
        _verify_reserved_file(
            workspace.staging_fd,
            certificate_name,
            output_fd,
            certificate_identity,
        )
    finally:
        _close_fd(output_fd)
        _close_fd(input_fd)

    private_name = f"{name}.pk8"
    input_fd = _open_input_file(workspace.raw_fd, raw_name)
    output_fd, private_identity = _reserve_file(workspace.staging_fd, private_name)
    try:
        _run(
            workspace,
            runner,
            [
                "openssl",
                "pkcs8",
                "-in",
                _descriptor_path(input_fd),
                "-topk8",
                "-v1",
                "PBE-SHA1-3DES",
                "-outform",
                "DER",
                "-out",
                _descriptor_path(output_fd),
                "-passout",
                "stdin",
            ],
            stdin=protected_input,
            extra_fds=(input_fd, output_fd),
        )
        _verify_reserved_file(
            workspace.staging_fd, private_name, output_fd, private_identity
        )
    finally:
        _close_fd(output_fd)
        _close_fd(input_fd)


def _run(
    workspace: _Workspace,
    runner: CommandRunner,
    command: Sequence[str],
    *,
    stdin: str | None = None,
    extra_fds: Sequence[int] = (),
) -> None:
    _revalidate_workspace(workspace)
    descriptors = tuple(sorted(set(extra_fds)))
    try:
        runner(list(command), stdin=stdin, env=None, pass_fds=descriptors)
    except (OSError, subprocess.SubprocessError) as error:
        raise KeyGenerationError(f"{Path(command[0]).name} failed") from error
    _revalidate_workspace(workspace)


def _create_workspace(destination: Path, plan: KeyPlan) -> _Workspace:
    parent_fd = staging_fd = raw_fd = public_fd = -1
    staging_name = ""
    staging_created = False
    try:
        parent_fd = os.open(destination.parent, _DIRECTORY_FLAGS)
        parent_stat = _validate_directory_fd(parent_fd, owner_required=True)
        parent_path_stat = os.stat(destination.parent, follow_symlinks=False)
        if _identity(parent_stat) != _identity(parent_path_stat):
            raise KeyGenerationError("keys parent changed during validation")
        _reject_existing_destination_at(parent_fd, destination.name, plan)

        for _attempt in range(128):
            candidate = f".{destination.name}.staging-{secrets.token_hex(8)}"
            staging_name = candidate
            staging_created = True
            try:
                os.mkdir(candidate, mode=0o700, dir_fd=parent_fd)
                break
            except FileExistsError:
                staging_created = False
                staging_name = ""
                continue
        if not staging_name:
            raise KeyGenerationError("could not allocate a unique staging directory")
        staging_fd = os.open(staging_name, _DIRECTORY_FLAGS, dir_fd=parent_fd)
        staging_stat = _validate_directory_fd(
            staging_fd, owner_required=True, exact_mode=0o700
        )
        os.mkdir(".raw", mode=0o700, dir_fd=staging_fd)
        os.mkdir("public", mode=0o700, dir_fd=staging_fd)
        raw_fd = os.open(".raw", _DIRECTORY_FLAGS, dir_fd=staging_fd)
        public_fd = os.open("public", _DIRECTORY_FLAGS, dir_fd=staging_fd)
        _validate_directory_fd(raw_fd, owner_required=True, exact_mode=0o700)
        _validate_directory_fd(public_fd, owner_required=True, exact_mode=0o700)
        workspace = _Workspace(
            destination=destination,
            parent_fd=parent_fd,
            parent_identity=_identity(parent_stat),
            staging_name=staging_name,
            staging_fd=staging_fd,
            staging_identity=_identity(staging_stat),
            raw_fd=raw_fd,
            public_fd=public_fd,
        )
        _revalidate_workspace(workspace)
        return workspace
    except BaseException as error:
        if staging_fd >= 0:
            try:
                _remove_tree_contents(staging_fd)
                if staging_name:
                    os.rmdir(staging_name, dir_fd=parent_fd)
            except BaseException as cleanup_error:
                try:
                    error.add_note(
                        f"workspace creation cleanup failed: {type(cleanup_error).__name__}"
                    )
                except AttributeError:
                    pass
        elif staging_created and parent_fd >= 0:
            try:
                os.rmdir(staging_name, dir_fd=parent_fd)
            except FileNotFoundError:
                pass
            except BaseException as cleanup_error:
                try:
                    error.add_note(
                        "workspace creation cleanup failed: "
                        f"{type(cleanup_error).__name__}"
                    )
                except AttributeError:
                    pass
        for descriptor in (public_fd, raw_fd, staging_fd, parent_fd):
            _close_fd(descriptor)
        raise


def _revalidate_workspace(workspace: _Workspace) -> None:
    _validate_trusted_ancestors(workspace.destination.parent)
    parent_stat = _validate_directory_fd(workspace.parent_fd, owner_required=True)
    if _identity(parent_stat) != workspace.parent_identity:
        raise KeyGenerationError("keys parent descriptor changed")
    parent_path_stat = os.stat(workspace.destination.parent, follow_symlinks=False)
    if _identity(parent_path_stat) != workspace.parent_identity:
        raise KeyGenerationError("keys parent path changed")
    staging_stat = _validate_directory_fd(
        workspace.staging_fd, owner_required=True, exact_mode=0o700
    )
    staging_path_stat = os.stat(
        workspace.staging_name,
        dir_fd=workspace.parent_fd,
        follow_symlinks=False,
    )
    if (
        _identity(staging_stat) != workspace.staging_identity
        or _identity(staging_path_stat) != workspace.staging_identity
    ):
        raise KeyGenerationError("staging directory changed")
    _validate_named_directory(workspace.staging_fd, "public", workspace.public_fd)
    if workspace.raw_fd >= 0:
        _validate_named_directory(workspace.staging_fd, ".raw", workspace.raw_fd)


def _validate_named_directory(parent_fd: int, name: str, descriptor: int) -> None:
    descriptor_stat = _validate_directory_fd(
        descriptor, owner_required=True, exact_mode=0o700
    )
    path_stat = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    if _identity(descriptor_stat) != _identity(path_stat):
        raise KeyGenerationError("staging subdirectory changed")


def _reserve_file(directory_fd: int, name: str) -> tuple[int, tuple[int, int]]:
    _validate_leaf_name(name)
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor = os.open(name, flags, 0o600, dir_fd=directory_fd)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.geteuid():
            raise KeyGenerationError("reserved output is not a trusted regular file")
        os.fchmod(descriptor, 0o600)
        return descriptor, _identity(metadata)
    except BaseException:
        os.close(descriptor)
        raise


def _open_input_file(directory_fd: int, name: str) -> int:
    descriptor = os.open(name, _FILE_READ_FLAGS, dir_fd=directory_fd)
    try:
        metadata = os.fstat(descriptor)
        path_metadata = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or _identity(metadata) != _identity(path_metadata)
        ):
            raise KeyGenerationError("private input file changed")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _verify_reserved_file(
    directory_fd: int,
    name: str,
    descriptor: int,
    expected_identity: tuple[int, int],
) -> None:
    try:
        metadata = os.fstat(descriptor)
        path_metadata = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or _identity(metadata) != expected_identity
            or not stat.S_ISREG(path_metadata.st_mode)
            or _identity(path_metadata) != expected_identity
        ):
            raise KeyGenerationError("command output replaced its reserved file")
        os.fchmod(descriptor, 0o600)
        os.fsync(descriptor)
    except OSError as error:
        raise KeyGenerationError("command output path changed") from error


def _write_password_file_at(
    directory_fd: int, name: str, paths: set[str], password: str
) -> None:
    _validate_passphrase(password)
    lines: list[str] = []
    for path in sorted(paths):
        _validate_password_path(path)
        lines.append(f"[[[ {password} ]]] {path}\n")
    _write_exclusive_at(directory_fd, name, "".join(lines).encode("utf-8"))


def _final_password_entries(plan: KeyPlan, destination: Path) -> set[str]:
    entries = {str(destination / role) for role in plan.android_roles}
    for name in plan.apex_names:
        entries.add(str(destination / name))
        entries.add(str(destination / f"{name}.pem"))
    for role in plan.avb_roles:
        entries.add(str(destination / f"avb_{role}.pem"))
    return entries


def _write_keyset_manifest(workspace: _Workspace, plan: KeyPlan) -> None:
    manifest = {
        "schema_version": 1,
        "android": [
            {
                "name": role,
                "certificate_sha256": _sha256_at(
                    workspace.staging_fd, f"{role}.x509.pem"
                ),
            }
            for role in plan.android_roles
        ],
        "apex": [
            {
                "name": name,
                "certificate_sha256": _sha256_at(
                    workspace.staging_fd, f"{name}.x509.pem"
                ),
                "avb_public_key_sha256": _sha256_at(
                    workspace.public_fd, f"{name}.avbpubkey"
                ),
            }
            for name in plan.apex_names
        ],
        "avb": [
            {
                "name": f"avb_{role}",
                "partition": role,
                "avb_public_key_sha256": _sha256_at(
                    workspace.public_fd, f"avb_{role}.avbpubkey"
                ),
            }
            for role in plan.avb_roles
        ],
    }
    payload = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8")
    _write_exclusive_at(workspace.staging_fd, "keyset.json", payload)


def _write_exclusive_at(directory_fd: int, name: str, payload: bytes) -> None:
    _validate_leaf_name(name)
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor = os.open(name, flags, 0o600, dir_fd=directory_fd)
    try:
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written == 0:
                raise OSError("short write while creating private key metadata")
            view = view[written:]
        os.fchmod(descriptor, 0o600)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _sha256_at(directory_fd: int, name: str) -> str:
    descriptor = os.open(name, _FILE_READ_FLAGS, dir_fd=directory_fd)
    digest = hashlib.sha256()
    try:
        with os.fdopen(descriptor, "rb") as source:
            descriptor = -1
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(chunk)
    finally:
        _close_fd(descriptor)
    return digest.hexdigest()


def _remove_raw_directory(workspace: _Workspace) -> None:
    _remove_tree_contents(workspace.raw_fd)
    _close_fd(workspace.raw_fd)
    workspace.raw_fd = -1
    os.rmdir(".raw", dir_fd=workspace.staging_fd)
    os.fsync(workspace.staging_fd)


def _validate_complete_staging(workspace: _Workspace, plan: KeyPlan) -> None:
    expected_files = _expected_files(plan)
    expected_entries = expected_files | {"public"}
    actual, file_modes, directory_modes = _collect_entries(workspace.staging_fd)
    if actual != expected_entries:
        raise KeyGenerationError("generated keyset is incomplete or inconsistent")
    if any(mode != 0o600 for mode in file_modes.values()):
        raise KeyGenerationError("generated keyset contains an unsafe file mode")
    if directory_modes != {"public": 0o700}:
        raise KeyGenerationError("generated keyset contains an unsafe directory mode")
    os.fsync(workspace.public_fd)
    os.fsync(workspace.staging_fd)


def _collect_entries(
    directory_fd: int, prefix: str = ""
) -> tuple[set[str], dict[str, int], dict[str, int]]:
    entries: set[str] = set()
    file_modes: dict[str, int] = {}
    directory_modes: dict[str, int] = {}
    with os.scandir(directory_fd) as iterator:
        children = list(iterator)
    for child in children:
        relative = f"{prefix}/{child.name}" if prefix else child.name
        metadata = child.stat(follow_symlinks=False)
        entries.add(relative)
        if stat.S_ISREG(metadata.st_mode):
            if metadata.st_uid != os.geteuid():
                raise KeyGenerationError("generated keyset has a non-owned file")
            file_modes[relative] = stat.S_IMODE(metadata.st_mode)
        elif stat.S_ISDIR(metadata.st_mode):
            if metadata.st_uid != os.geteuid():
                raise KeyGenerationError("generated keyset has a non-owned directory")
            directory_modes[relative] = stat.S_IMODE(metadata.st_mode)
            child_fd = os.open(child.name, _DIRECTORY_FLAGS, dir_fd=directory_fd)
            try:
                nested_entries, nested_files, nested_directories = _collect_entries(
                    child_fd, relative
                )
            finally:
                os.close(child_fd)
            entries.update(nested_entries)
            file_modes.update(nested_files)
            directory_modes.update(nested_directories)
        else:
            raise KeyGenerationError("generated keyset contains a special or symlink entry")
    return entries, file_modes, directory_modes


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


def _reject_existing_destination_at(parent_fd: int, name: str, plan: KeyPlan) -> None:
    del plan
    names = os.listdir(parent_fd)
    if any(item.startswith(f".{name}.staging-") for item in names):
        raise KeyGenerationError("abandoned key staging directory requires inspection")
    try:
        os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        return
    raise KeyGenerationError("keys destination appeared during validation")


def _cleanup_workspace(workspace: _Workspace) -> None:
    if _workspace_is_published(workspace):
        workspace.published = True
        return
    staging_stat = os.stat(
        workspace.staging_name,
        dir_fd=workspace.parent_fd,
        follow_symlinks=False,
    )
    if _identity(staging_stat) != workspace.staging_identity:
        raise KeyGenerationError("refusing to remove replaced staging directory")
    _close_fd(workspace.raw_fd)
    workspace.raw_fd = -1
    _close_fd(workspace.public_fd)
    workspace.public_fd = -1
    _remove_tree_contents(workspace.staging_fd)
    staging_stat_after = os.stat(
        workspace.staging_name,
        dir_fd=workspace.parent_fd,
        follow_symlinks=False,
    )
    if _identity(staging_stat_after) != workspace.staging_identity:
        raise KeyGenerationError("refusing to remove replaced staging directory")
    os.rmdir(workspace.staging_name, dir_fd=workspace.parent_fd)
    os.fsync(workspace.parent_fd)


def _workspace_is_published(workspace: _Workspace) -> bool:
    try:
        destination_stat = os.stat(
            workspace.destination.name,
            dir_fd=workspace.parent_fd,
            follow_symlinks=False,
        )
    except FileNotFoundError:
        return False
    if _identity(destination_stat) != workspace.staging_identity:
        return False
    if (
        not stat.S_ISDIR(destination_stat.st_mode)
        or destination_stat.st_uid != os.geteuid()
        or stat.S_IMODE(destination_stat.st_mode) != 0o700
    ):
        raise KeyGenerationError("published destination inode is unsafe")
    try:
        os.stat(
            workspace.staging_name,
            dir_fd=workspace.parent_fd,
            follow_symlinks=False,
        )
    except FileNotFoundError:
        return True
    raise KeyGenerationError("workspace inode has two authoritative names")


def _remove_tree_contents(directory_fd: int) -> None:
    parent_stat = os.fstat(directory_fd)
    with os.scandir(directory_fd) as iterator:
        children = list(iterator)
    for child in children:
        expected_identity = (parent_stat.st_dev, child.inode())
        entry_fd = os.open(child.name, _PATH_FLAGS, dir_fd=directory_fd)
        try:
            metadata = os.fstat(entry_fd)
            named_metadata = os.stat(
                child.name, dir_fd=directory_fd, follow_symlinks=False
            )
            if (
                _identity(metadata) != expected_identity
                or _identity(named_metadata) != expected_identity
                or stat.S_IFMT(metadata.st_mode) != stat.S_IFMT(named_metadata.st_mode)
            ):
                raise KeyGenerationError("cleanup entry changed before removal")
            if not stat.S_ISDIR(metadata.st_mode):
                os.unlink(child.name, dir_fd=directory_fd)
                continue

            child_fd = os.open(".", _DIRECTORY_FLAGS, dir_fd=entry_fd)
            try:
                if _identity(os.fstat(child_fd)) != expected_identity:
                    raise KeyGenerationError("cleanup directory descriptor changed")
                _remove_tree_contents(child_fd)
            finally:
                os.close(child_fd)
            named_after = os.stat(
                child.name, dir_fd=directory_fd, follow_symlinks=False
            )
            if _identity(named_after) != expected_identity:
                raise KeyGenerationError("cleanup directory changed during removal")
            os.rmdir(child.name, dir_fd=directory_fd)
        finally:
            os.close(entry_fd)


def _close_workspace(workspace: _Workspace) -> None:
    for descriptor in (
        workspace.public_fd,
        workspace.raw_fd,
        workspace.staging_fd,
        workspace.parent_fd,
    ):
        _close_fd(descriptor)


def _close_fd(descriptor: int) -> None:
    if descriptor < 0:
        return
    try:
        os.close(descriptor)
    except OSError:
        pass


def _rename_no_replace_at(
    parent_fd: int, source_name: str, destination_name: str
) -> None:
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
        parent_fd,
        os.fsencode(source_name),
        parent_fd,
        os.fsencode(destination_name),
        _RENAME_NOREPLACE,
    )
    if result != 0:
        code = ctypes.get_errno()
        if code == errno.EEXIST:
            raise KeyGenerationError("keys destination appeared during generation")
        raise OSError(code, os.strerror(code), destination_name)


def _validate_directory_fd(
    descriptor: int,
    *,
    owner_required: bool,
    exact_mode: int | None = None,
) -> os.stat_result:
    metadata = os.fstat(descriptor)
    mode = stat.S_IMODE(metadata.st_mode)
    if not stat.S_ISDIR(metadata.st_mode):
        raise KeyGenerationError("trusted path component is not a directory")
    if owner_required and metadata.st_uid != os.geteuid():
        raise KeyGenerationError("trusted directory is not owned by the current user")
    if mode & 0o022:
        raise KeyGenerationError("trusted directory is group/world writable")
    if exact_mode is not None and mode != exact_mode:
        raise KeyGenerationError("private key directory permissions must be 0700")
    return metadata


def _validate_trusted_ancestors(path: Path) -> None:
    if not path.exists() or not path.is_dir():
        raise KeyGenerationError("keys parent directory must already exist")
    current = Path(path.anchor)
    current_uid = os.geteuid()
    for part in path.parts[1:]:
        current /= part
        metadata = current.lstat()
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            raise KeyGenerationError("keys ancestor is not a trusted directory")
        if metadata.st_uid not in {0, current_uid}:
            raise KeyGenerationError("keys ancestor has an untrusted owner")
        if stat.S_IMODE(metadata.st_mode) & 0o022:
            raise KeyGenerationError("keys ancestor is group/world writable")
    if path.lstat().st_uid != current_uid:
        raise KeyGenerationError("keys parent must be owned by the current user")


def _identity(metadata: os.stat_result) -> tuple[int, int]:
    return metadata.st_dev, metadata.st_ino


def _descriptor_path(descriptor: int) -> str:
    # avbtool starts its own OpenSSL child, so /proc/self would refer to that
    # child. A fixed path to this still-running generator keeps the held inode
    # accessible without exposing a replaceable directory entry.
    return f"/proc/{os.getpid()}/fd/{descriptor}"


def _validate_leaf_name(name: str) -> None:
    if not _SAFE_NAME.fullmatch(name) or name in {".", ".."}:
        raise KeyGenerationError("unsafe staging file name")


def _validate_passphrase(password: str) -> None:
    if not password or password != password.strip():
        raise KeyGenerationError("passphrase must be nonblank without edge whitespace")
    if _OPEN_DELIMITER in password or _CLOSE_DELIMITER in password:
        raise KeyGenerationError("passphrase contains a password-file delimiter")
    if any(
        unicodedata.category(character).startswith("C")
        or unicodedata.category(character) in {"Zl", "Zp"}
        for character in password
    ):
        raise KeyGenerationError("passphrase contains an unsupported control character")


def _validate_password_path(value: str) -> None:
    if not value or any(character.isspace() for character in value):
        raise KeyGenerationError("key path cannot be represented in the password file")
    if _OPEN_DELIMITER in value or _CLOSE_DELIMITER in value:
        raise KeyGenerationError("key path contains a password-file delimiter")
    if any(unicodedata.category(character).startswith("C") for character in value):
        raise KeyGenerationError("key path contains an unsupported control character")


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
