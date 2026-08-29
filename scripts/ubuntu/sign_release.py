#!/usr/bin/env python3
"""Build deterministic post-build signing commands for a fleur release."""

from __future__ import annotations

import argparse
import ctypes
from dataclasses import dataclass
from datetime import datetime, timezone
import errno
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import stat
import subprocess
import tempfile
from typing import Callable, Mapping, Sequence
from zipfile import BadZipFile, ZipFile

try:
    from scripts.ubuntu.avb_password_helper import PasswordLookupError, parse_password_file
    from scripts.ubuntu.avb_signing_helper import (
        AvbSigningError,
        OpenSslRunner,
        export_public_key,
        run_openssl,
    )
    from scripts.ubuntu.generate_release_keys import KeyGenerationError, build_key_plan
    from scripts.ubuntu.signing_metadata import SigningInventory, load_signing_inventory
except ModuleNotFoundError:  # Direct execution from scripts/ubuntu.
    from avb_password_helper import PasswordLookupError, parse_password_file
    from avb_signing_helper import AvbSigningError, OpenSslRunner, export_public_key, run_openssl
    from generate_release_keys import KeyGenerationError, build_key_plan
    from signing_metadata import SigningInventory, load_signing_inventory


class ReleaseSigningError(RuntimeError):
    """Raised before an incomplete or unsafe signed release can be published."""


_BUILD_ID = re.compile(r"\d{8}T\d{6}Z\Z")
_RENAME_NOREPLACE = 1
_AT_FDCWD = -100
_STANDARD_AVB_PARTITIONS = frozenset(
    {
        "boot",
        "init_boot",
        "recovery",
        "system",
        "system_other",
        "vendor",
        "dtbo",
        "vbmeta",
        "vbmeta_system",
        "vbmeta_vendor",
    }
)


@dataclass(frozen=True)
class SigningPaths:
    target_files: Path
    android_root: Path
    keys_dir: Path
    output_dir: Path
    build_id: str | None = None

    def __post_init__(self) -> None:
        build_id = self.output_dir.name if self.build_id is None else self.build_id
        try:
            parsed_build_id = datetime.strptime(build_id, "%Y%m%dT%H%M%SZ")
        except ValueError as error:
            raise ReleaseSigningError(
                "output directory name must be a UTC YYYYMMDDTHHMMSSZ build identifier"
            ) from error
        if (
            not _BUILD_ID.fullmatch(build_id)
            or parsed_build_id.strftime("%Y%m%dT%H%M%SZ") != build_id
        ):
            raise ReleaseSigningError(
                "output directory name must be a UTC YYYYMMDDTHHMMSSZ build identifier"
            )
        if not all(
            path.is_absolute()
            for path in (
                self.target_files,
                self.android_root,
                self.keys_dir,
                self.output_dir,
            )
        ):
            raise ReleaseSigningError("release signing paths must be absolute")
        object.__setattr__(self, "build_id", build_id)

    @property
    def host_tools(self) -> Path:
        return self.android_root / "out/host/linux-x86/bin"

    @property
    def signed_target_files(self) -> Path:
        return self.output_dir / "lineage_fleur-SIGNED-target_files.zip"

    @property
    def ota_zip(self) -> Path:
        return self.output_dir / f"lineage-23.2-{self.build_id}-SIGNED-fleur.zip"

    @property
    def fastboot_zip(self) -> Path:
        return self.output_dir / "lineage_fleur-SIGNED-img.zip"

    @property
    def public_keys_dir(self) -> Path:
        return self.output_dir / "public-keys"

    @property
    def report(self) -> Path:
        return self.output_dir / "signing-report.json"

    @property
    def checksums(self) -> Path:
        return self.output_dir / "SHA256SUMS"


@dataclass(frozen=True)
class SigningCommands:
    sign_target_files: tuple[str, ...]
    ota_from_target_files: tuple[str, ...]
    img_from_target_files: tuple[str, ...]


CommandRunner = Callable[..., None]
Timestamp = Callable[[], str]


def build_signing_commands(
    inventory: SigningInventory,
    paths: SigningPaths,
    *,
    signing_helper: Path,
    public_key_dir: Path,
) -> SigningCommands:
    """Construct all signing commands from immutable target-files metadata."""
    try:
        build_key_plan(inventory)
    except KeyGenerationError as error:
        raise ReleaseSigningError("signing metadata has colliding generated key roles") from error

    helper_args = f"--signing_helper {shlex.quote(str(signing_helper))}"
    command = [
        str(paths.host_tools / "sign_target_files_apks"),
        "-o",
        "-d",
        str(paths.keys_dir),
        "--tag_changes",
        "-test-keys,+release-keys",
    ]

    apk_mappings = {
        certificate.certificate: paths.keys_dir / Path(certificate.certificate).name
        for certificate in inventory.apk_certificates
        if certificate.certificate != "PRESIGNED"
    }
    for source, destination in sorted(apk_mappings.items()):
        command.extend(("-k", f"{source}={destination}"))

    non_presigned_apexes = tuple(apex for apex in inventory.apexes if not apex.presigned)
    for apex in non_presigned_apexes:
        role = _apex_role(apex.name)
        command.extend(("--extra_apks", f"{apex.name}={paths.keys_dir / role}"))
        command.extend(
            (
                "--extra_apex_payload_key",
                f"{apex.name}={public_key_dir / (role + '.public.pem')}",
            )
        )
    if non_presigned_apexes:
        command.extend(("--avb_apex_extra_args", helper_args))

    for avb_key in inventory.avb_keys:
        public_key = public_key_dir / f"avb_{avb_key.partition}.public.pem"
        if avb_key.partition in _STANDARD_AVB_PARTITIONS:
            prefix = f"--avb_{avb_key.partition}"
            command.extend((f"{prefix}_algorithm", avb_key.algorithm))
            command.extend((f"{prefix}_key", str(public_key)))
            command.extend((f"{prefix}_extra_args", helper_args))
        else:
            command.extend(
                (
                    "--avb_extra_custom_image_algorithm",
                    f"{avb_key.partition}={avb_key.algorithm}",
                    "--avb_extra_custom_image_key",
                    f"{avb_key.partition}={public_key}",
                    "--avb_extra_custom_image_extra_args",
                    f"{avb_key.partition}={helper_args}",
                )
            )

    command.extend((str(paths.target_files), str(paths.signed_target_files)))
    ota = (
        str(paths.host_tools / "ota_from_target_files"),
        "-k",
        str(paths.keys_dir / "releasekey"),
        "--block",
        "--backup=true",
        str(paths.signed_target_files),
        str(paths.ota_zip),
    )
    images = (
        str(paths.host_tools / "img_from_target_files"),
        str(paths.signed_target_files),
        str(paths.fastboot_zip),
    )
    return SigningCommands(tuple(command), ota, images)


def build_child_environment(paths: SigningPaths, config_path: Path) -> dict[str, str]:
    """Build a narrow child environment containing only nonsecret path state."""
    environment: dict[str, str] = {
        "PATH": os.pathsep.join(
            (str(paths.host_tools), os.environ.get("PATH", "/usr/bin:/bin"))
        ),
        "ANDROID_PW_FILE": str(paths.keys_dir / "passwords"),
        "FLEUR_AVB_SIGNING_CONFIG": str(config_path),
        "LC_ALL": "C.UTF-8",
        "LANG": "C.UTF-8",
    }
    if temporary := os.environ.get("TMPDIR"):
        environment["TMPDIR"] = temporary
    return environment


def build_public_environment(paths: SigningPaths) -> dict[str, str]:
    """Build a child environment for tools that never consume private keys."""
    environment = {
        "PATH": os.pathsep.join(
            (str(paths.host_tools), os.environ.get("PATH", "/usr/bin:/bin"))
        ),
        "LC_ALL": "C.UTF-8",
        "LANG": "C.UTF-8",
    }
    if temporary := os.environ.get("TMPDIR"):
        environment["TMPDIR"] = temporary
    return environment


def run_command(command: Sequence[str], *, env: Mapping[str, str]) -> None:
    """Run one release tool without retaining its potentially noisy output."""
    subprocess.run(list(command), env=dict(env), check=True)


def sign_release(
    paths: SigningPaths,
    *,
    runner: CommandRunner = run_command,
    openssl_runner: OpenSslRunner = run_openssl,
    timestamp: Timestamp | None = None,
) -> Path:
    """Sign one target-files archive and atomically publish all public outputs."""
    now = _utc_timestamp if timestamp is None else timestamp
    started_at = now()
    if paths.output_dir.exists() or paths.output_dir.is_symlink():
        raise ReleaseSigningError("output directory already exists")
    if not paths.output_dir.parent.is_dir():
        raise ReleaseSigningError("output parent directory does not exist")
    inventory = _validate_inputs(paths)
    plan = _validate_keyset(inventory, paths.keys_dir)

    staging = Path(
        tempfile.mkdtemp(
            prefix=f".{paths.build_id}.staging-",
            dir=paths.output_dir.parent,
        )
    )
    os.chmod(staging, 0o700)
    staging_paths = SigningPaths(
        paths.target_files,
        paths.android_root,
        paths.keys_dir,
        staging,
        build_id=paths.build_id,
    )
    runtime_dir = staging / ".signing-runtime"
    public_pem_dir = runtime_dir / "public-pem"
    config_path = runtime_dir / "avb-helper.json"
    published = False
    try:
        public_pem_dir.mkdir(parents=True, mode=0o700)
        try:
            mappings = _export_runtime_public_pems(
                plan,
                paths.keys_dir,
                public_pem_dir,
                openssl_runner,
            )
        except AvbSigningError as error:
            raise ReleaseSigningError("public key preparation failed") from error
        _write_private_json(
            config_path,
            {
                "schema_version": 1,
                "password_file": str(paths.keys_dir / "passwords"),
                "keys": mappings,
            },
        )
        helper = Path(__file__).resolve().with_name("avb_signing_helper.py")
        commands = build_signing_commands(
            inventory,
            staging_paths,
            signing_helper=helper,
            public_key_dir=public_pem_dir,
        )
        private_environment = build_child_environment(staging_paths, config_path)
        public_environment = build_public_environment(staging_paths)

        _run_release_tool(commands.sign_target_files, private_environment, runner)
        _validate_zip(staging_paths.signed_target_files)
        _run_release_tool(commands.ota_from_target_files, private_environment, runner)
        _validate_payload_ota(staging_paths.ota_zip)
        _run_release_tool(commands.img_from_target_files, public_environment, runner)
        _validate_zip(staging_paths.fastboot_zip)

        _export_public_bundle(
            plan,
            paths.keys_dir,
            public_pem_dir,
            staging_paths.public_keys_dir,
        )
        shutil.rmtree(runtime_dir)
        completed_at = now()
        _write_report(
            inventory,
            paths,
            staging_paths,
            commands,
            started_at,
            completed_at,
        )
        _write_checksums(staging_paths)
        _fsync_directory(staging)
        _rename_no_replace(staging, paths.output_dir)
        published = True
        _fsync_directory(paths.output_dir.parent)
    except BaseException:
        if not published and staging.exists():
            shutil.rmtree(staging)
        raise
    return paths.output_dir


def _validate_inputs(paths: SigningPaths) -> SigningInventory:
    if paths.output_dir.name != paths.build_id:
        raise ReleaseSigningError("final output directory must use the UTC build identifier")
    if not paths.target_files.is_file() or paths.target_files.is_symlink():
        raise ReleaseSigningError("target-files input is unavailable")
    try:
        inventory = load_signing_inventory(paths.target_files)
    except (OSError, ValueError, BadZipFile) as error:
        raise ReleaseSigningError("target-files signing metadata is invalid") from error
    if inventory.misc_info.get("ab_update") != "true":
        raise ReleaseSigningError("fleur target-files must declare ab_update=true")
    if inventory.misc_info.get("virtual_ab") != "true":
        raise ReleaseSigningError("fleur target-files must declare virtual_ab=true")
    if not inventory.uses_test_build_tags:
        raise ReleaseSigningError("unsigned target-files must carry test-keys before signing")
    for tool in ("sign_target_files_apks", "ota_from_target_files", "img_from_target_files"):
        path = paths.host_tools / tool
        if not path.is_file() or not os.access(path, os.X_OK):
            raise ReleaseSigningError(f"required host tool {tool} is unavailable")
    return inventory


def _validate_keyset(inventory: SigningInventory, keys_dir: Path):
    if keys_dir.is_symlink() or not keys_dir.is_dir():
        raise ReleaseSigningError("release key directory is unavailable")
    directory_metadata = keys_dir.lstat()
    if (
        directory_metadata.st_uid != os.geteuid()
        or stat.S_IMODE(directory_metadata.st_mode) != 0o700
    ):
        raise ReleaseSigningError("release key directory must be owned and mode 0700")
    try:
        plan = build_key_plan(inventory)
    except KeyGenerationError as error:
        raise ReleaseSigningError("signing metadata has colliding generated key roles") from error

    expected_password_entries: set[str] = set()
    for role in plan.android_roles:
        _validate_private_file(keys_dir / f"{role}.pk8")
        _validate_private_file(keys_dir / f"{role}.x509.pem")
        expected_password_entries.add(str(keys_dir / role))
    for role in plan.apex_names:
        for suffix in (".pem", ".pk8", ".x509.pem"):
            _validate_private_file(keys_dir / f"{role}{suffix}")
        _validate_private_file(keys_dir / "public" / f"{role}.avbpubkey")
        expected_password_entries.update((str(keys_dir / role), str(keys_dir / f"{role}.pem")))
    for partition in plan.avb_roles:
        role = f"avb_{partition}"
        _validate_private_file(keys_dir / f"{role}.pem")
        _validate_private_file(keys_dir / "public" / f"{role}.avbpubkey")
        expected_password_entries.add(str(keys_dir / f"{role}.pem"))

    try:
        passwords = parse_password_file(keys_dir / "passwords")
    except PasswordLookupError as error:
        raise ReleaseSigningError("release password file is invalid") from error
    try:
        if set(passwords) != expected_password_entries:
            raise ReleaseSigningError("release password file does not match the key plan")
    finally:
        passwords.clear()

    manifest_path = keys_dir / "keyset.json"
    _validate_private_file(manifest_path)
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ReleaseSigningError("release key manifest is invalid") from error
    if manifest != _expected_key_manifest(plan, keys_dir):
        raise ReleaseSigningError("release key manifest does not match public material")
    return plan


def _expected_key_manifest(plan, keys_dir: Path) -> dict[str, object]:
    return {
        "schema_version": 1,
        "android": [
            {
                "name": role,
                "certificate_sha256": _sha256(keys_dir / f"{role}.x509.pem"),
            }
            for role in plan.android_roles
        ],
        "apex": [
            {
                "name": role,
                "certificate_sha256": _sha256(keys_dir / f"{role}.x509.pem"),
                "avb_public_key_sha256": _sha256(
                    keys_dir / "public" / f"{role}.avbpubkey"
                ),
            }
            for role in plan.apex_names
        ],
        "avb": [
            {
                "name": f"avb_{partition}",
                "partition": partition,
                "avb_public_key_sha256": _sha256(
                    keys_dir / "public" / f"avb_{partition}.avbpubkey"
                ),
            }
            for partition in plan.avb_roles
        ],
    }


def _validate_private_file(path: Path) -> None:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise ReleaseSigningError("release keyset is incomplete") from error
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o600
    ):
        raise ReleaseSigningError("release keyset contains an unsafe file")


def _export_runtime_public_pems(
    plan,
    keys_dir: Path,
    public_pem_dir: Path,
    openssl_runner: OpenSslRunner,
) -> dict[str, str]:
    roles = [*plan.apex_names, *(f"avb_{partition}" for partition in plan.avb_roles)]
    mappings: dict[str, str] = {}
    for role in roles:
        private_key = keys_dir / f"{role}.pem"
        public_key = public_pem_dir / f"{role}.public.pem"
        export_public_key(
            private_key,
            public_key,
            keys_dir / "passwords",
            runner=openssl_runner,
        )
        mappings[str(public_key)] = str(private_key)
    return mappings


def _write_private_json(path: Path, value: object) -> None:
    payload = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")
    descriptor = os.open(
        path,
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written == 0:
                raise ReleaseSigningError("short write while preparing AVB helper config")
            view = view[written:]
        os.fchmod(descriptor, 0o600)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _run_release_tool(
    command: Sequence[str],
    environment: Mapping[str, str],
    runner: CommandRunner,
) -> None:
    try:
        runner(tuple(command), env=dict(environment))
    except (OSError, subprocess.SubprocessError) as error:
        raise ReleaseSigningError(f"{Path(command[0]).name} failed") from error


def _validate_zip(path: Path) -> None:
    if path.is_symlink() or not path.is_file() or path.stat().st_size == 0:
        raise ReleaseSigningError(f"{path.name} was not produced")
    try:
        with ZipFile(path) as archive:
            if archive.testzip() is not None:
                raise ReleaseSigningError(f"{path.name} is corrupt")
    except BadZipFile as error:
        raise ReleaseSigningError(f"{path.name} is not a ZIP archive") from error
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _validate_payload_ota(path: Path) -> None:
    _validate_zip(path)
    with ZipFile(path) as archive:
        if archive.namelist().count("payload.bin") != 1:
            raise ReleaseSigningError("signed A/B OTA must contain exactly one payload.bin")


def _export_public_bundle(plan, keys_dir: Path, public_pem_dir: Path, destination: Path) -> None:
    destination.mkdir(mode=0o755)
    sources: list[tuple[Path, str]] = []
    for role in plan.android_roles:
        sources.append((keys_dir / f"{role}.x509.pem", f"{role}.x509.pem"))
    for role in plan.apex_names:
        sources.extend(
            (
                (keys_dir / f"{role}.x509.pem", f"{role}.x509.pem"),
                (keys_dir / "public" / f"{role}.avbpubkey", f"{role}.avbpubkey"),
                (public_pem_dir / f"{role}.public.pem", f"{role}.public.pem"),
            )
        )
    for partition in plan.avb_roles:
        role = f"avb_{partition}"
        sources.extend(
            (
                (keys_dir / "public" / f"{role}.avbpubkey", f"{role}.avbpubkey"),
                (public_pem_dir / f"{role}.public.pem", f"{role}.public.pem"),
            )
        )
    names = [name for _source, name in sources]
    if len(names) != len(set(names)):
        raise ReleaseSigningError("public key export names collide")
    for source, name in sources:
        _copy_public_file(source, destination / name)
    _fsync_directory(destination)


def _copy_public_file(source: Path, destination: Path) -> None:
    if source.is_symlink() or not source.is_file():
        raise ReleaseSigningError("public key source is unsafe")
    source_fd = os.open(
        source,
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0),
    )
    destination_fd = -1
    try:
        destination_fd = os.open(
            destination,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            0o644,
        )
        while True:
            chunk = os.read(source_fd, 1024 * 1024)
            if not chunk:
                break
            view = memoryview(chunk)
            while view:
                written = os.write(destination_fd, view)
                if written == 0:
                    raise ReleaseSigningError("short write during public key export")
                view = view[written:]
        os.fchmod(destination_fd, 0o644)
        os.fsync(destination_fd)
    finally:
        if destination_fd >= 0:
            os.close(destination_fd)
        os.close(source_fd)


def _write_report(
    inventory: SigningInventory,
    final_paths: SigningPaths,
    staging_paths: SigningPaths,
    commands: SigningCommands,
    started_at: str,
    completed_at: str,
) -> None:
    artifacts = (
        staging_paths.signed_target_files,
        staging_paths.ota_zip,
        staging_paths.fastboot_zip,
    )
    public_files = sorted(
        path for path in staging_paths.public_keys_dir.iterdir() if path.is_file()
    )
    report = {
        "schema_version": 1,
        "build_id": final_paths.build_id,
        "device": "fleur",
        "build_properties": {
            "ab_update": inventory.misc_info.get("ab_update") == "true",
            "virtual_ab": inventory.misc_info.get("virtual_ab") == "true",
        },
        "timestamps": {"started_at": started_at, "completed_at": completed_at},
        "input": {
            "sha256": _sha256(final_paths.target_files),
            "size": final_paths.target_files.stat().st_size,
        },
        "outputs": {
            path.name: {"sha256": _sha256(path), "size": path.stat().st_size}
            for path in artifacts
        },
        "public_fingerprints": {
            path.name: _sha256(path) for path in public_files
        },
        "tool_paths": {
            "sign_target_files_apks": str(final_paths.host_tools / "sign_target_files_apks"),
            "ota_from_target_files": str(final_paths.host_tools / "ota_from_target_files"),
            "img_from_target_files": str(final_paths.host_tools / "img_from_target_files"),
        },
        "sanitized_options": {
            "sign_target_files_apks": _option_names(commands.sign_target_files),
            "ota_from_target_files": _option_names(commands.ota_from_target_files),
            "img_from_target_files": _option_names(commands.img_from_target_files),
        },
    }
    _write_public_json(staging_paths.report, report)


def _write_public_json(path: Path, value: object) -> None:
    payload = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")
    _write_public_file(path, payload)


def _write_public_file(path: Path, payload: bytes) -> None:
    descriptor = os.open(
        path,
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0),
        0o644,
    )
    try:
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written == 0:
                raise ReleaseSigningError("short write while publishing release metadata")
            view = view[written:]
        os.fchmod(descriptor, 0o644)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _write_checksums(paths: SigningPaths) -> None:
    files = sorted(
        path
        for path in paths.output_dir.rglob("*")
        if path.is_file() and path != paths.checksums
    )
    lines = [f"{_sha256(path)}  {path.relative_to(paths.output_dir)}\n" for path in files]
    _write_public_file(paths.checksums, "".join(lines).encode("utf-8"))


def _option_names(command: Sequence[str]) -> list[str]:
    names: set[str] = set()
    for value in command[1:]:
        if value.startswith("--"):
            names.add(value.split("=", 1)[0])
        elif len(value) == 2 and value.startswith("-"):
            names.add(value)
    return sorted(names)


def _sha256(path: Path) -> str:
    result = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            result.update(chunk)
    return result.hexdigest()


def _rename_no_replace(source: Path, destination: Path) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    renameat2 = getattr(libc, "renameat2", None)
    if renameat2 is None:
        raise ReleaseSigningError("atomic no-replace publication is unavailable")
    result = renameat2(
        _AT_FDCWD,
        ctypes.c_char_p(os.fsencode(source)),
        _AT_FDCWD,
        ctypes.c_char_p(os.fsencode(destination)),
        _RENAME_NOREPLACE,
    )
    if result != 0:
        error_number = ctypes.get_errno()
        if error_number == errno.EEXIST:
            raise ReleaseSigningError("output directory already exists")
        raise ReleaseSigningError("atomic release publication failed")


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(
        path,
        os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_CLOEXEC", 0),
    )
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _utc_timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _apex_role(apex_name: str) -> str:
    if not apex_name.endswith(".apex"):
        raise ReleaseSigningError("APEX metadata name must end in .apex")
    return apex_name[: -len(".apex")]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target-files", required=True, type=Path)
    parser.add_argument("--android-root", required=True, type=Path)
    parser.add_argument("--keys-dir", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--dry-run", action="store_true")
    arguments = parser.parse_args(argv)
    try:
        paths = SigningPaths(
            arguments.target_files,
            arguments.android_root,
            arguments.keys_dir,
            arguments.output_dir,
        )
        if arguments.dry_run:
            if paths.output_dir.exists() or paths.output_dir.is_symlink():
                raise ReleaseSigningError("output directory already exists")
            inventory = _validate_inputs(paths)
            _validate_keyset(inventory, paths.keys_dir)
            build_signing_commands(
                inventory,
                paths,
                signing_helper=Path(__file__).resolve().with_name(
                    "avb_signing_helper.py"
                ),
                public_key_dir=paths.output_dir / ".signing-runtime/public-pem",
            )
            print("dry-run: release signing inputs and command structure are valid")
            return 0
        sign_release(paths)
    except ReleaseSigningError as error:
        print(f"release signing failed: {error}", file=os.sys.stderr)
        return 1
    print(paths.output_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
