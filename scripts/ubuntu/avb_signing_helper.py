#!/usr/bin/env python3
"""Sign AVB input with encrypted PEM keys without exposing passphrases."""

from __future__ import annotations

from contextlib import contextmanager
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
from typing import Callable, Sequence

try:
    from scripts.ubuntu.avb_password_helper import PasswordLookupError, lookup_password
except ModuleNotFoundError:  # Direct execution from scripts/ubuntu.
    from avb_password_helper import PasswordLookupError, lookup_password


class AvbSigningError(RuntimeError):
    """Raised when encrypted-key AVB signing cannot proceed safely."""


OpenSslRunner = Callable[..., bytes]
_SUPPORTED_ALGORITHM = "SHA256_RSA4096"
_CONFIG_ENV = "FLEUR_AVB_SIGNING_CONFIG"
_READ_FLAGS = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
_WRITE_FLAGS = (
    os.O_WRONLY
    | os.O_CREAT
    | os.O_EXCL
    | getattr(os, "O_CLOEXEC", 0)
    | getattr(os, "O_NOFOLLOW", 0)
)


def run_openssl(
    command: Sequence[str],
    *,
    input_data: bytes | None,
    pass_fds: Sequence[int],
) -> bytes:
    """Run OpenSSL with inherited descriptors and return public stdout only."""
    try:
        completed = subprocess.run(
            list(command),
            input=input_data,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            pass_fds=tuple(pass_fds),
            check=True,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise AvbSigningError("OpenSSL signing failed") from error
    return completed.stdout


def sign_payload(
    config_path: Path,
    algorithm: str,
    public_key: Path,
    payload: bytes,
    *,
    runner: OpenSslRunner = run_openssl,
) -> bytes:
    """Sign avbtool stdin using the private key mapped from its public key path."""
    if algorithm != _SUPPORTED_ALGORITHM:
        raise AvbSigningError("unsupported AVB signing algorithm")
    password_file, mappings = _load_config(config_path)
    requested_public_key = str(public_key)
    try:
        private_key = Path(mappings[requested_public_key])
    except KeyError as error:
        raise AvbSigningError("unrecognized AVB public key path") from error

    private_fd = _open_private_key(private_key)
    password = ""
    try:
        password = lookup_password(password_file, str(private_key))
        with _password_descriptor(password) as password_fd:
            command = [
                "openssl",
                "rsautl",
                "-sign",
                "-inkey",
                _fd_path(private_fd),
                "-raw",
                "-passin",
                f"fd:{password_fd}",
            ]
            signature = runner(
                command,
                input_data=payload,
                pass_fds=(private_fd, password_fd),
            )
    except PasswordLookupError as error:
        raise AvbSigningError("AVB key password lookup failed") from error
    finally:
        password = ""
        os.close(private_fd)

    if len(signature) != 512:
        raise AvbSigningError("OpenSSL returned an invalid AVB signature length")
    return signature


def export_public_key(
    private_key: Path,
    public_key: Path,
    password_file: Path,
    *,
    runner: OpenSslRunner = run_openssl,
) -> None:
    """Export a public PEM from an encrypted private PEM via password fd."""
    private_fd = _open_private_key(private_key)
    output_fd = -1
    password = ""
    try:
        public_key.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        try:
            output_fd = os.open(public_key, _WRITE_FLAGS, 0o600)
        except FileExistsError as error:
            raise AvbSigningError("public key output already exists") from error
        password = lookup_password(password_file, str(private_key))
        with _password_descriptor(password) as password_fd:
            command = [
                "openssl",
                "pkey",
                "-in",
                _fd_path(private_fd),
                "-pubout",
                "-passin",
                f"fd:{password_fd}",
                "-out",
                _fd_path(output_fd),
            ]
            runner(
                command,
                input_data=None,
                pass_fds=(private_fd, password_fd, output_fd),
            )
        os.fchmod(output_fd, 0o600)
        os.fsync(output_fd)
        if os.fstat(output_fd).st_size == 0:
            raise AvbSigningError("OpenSSL produced an empty public key")
    except (PasswordLookupError, OSError) as error:
        if isinstance(error, PasswordLookupError):
            wrapped = AvbSigningError("AVB key password lookup failed")
        elif isinstance(error, AvbSigningError):
            wrapped = error
        else:
            wrapped = AvbSigningError("public key export failed")
        if output_fd >= 0:
            os.close(output_fd)
            output_fd = -1
            try:
                public_key.unlink()
            except FileNotFoundError:
                pass
        raise wrapped from error
    except BaseException:
        if output_fd >= 0:
            os.close(output_fd)
            output_fd = -1
            try:
                public_key.unlink()
            except FileNotFoundError:
                pass
        raise
    finally:
        password = ""
        if output_fd >= 0:
            os.close(output_fd)
        os.close(private_fd)


def _load_config(config_path: Path) -> tuple[Path, dict[str, str]]:
    descriptor = _open_owned_private_file(config_path, "AVB helper config")
    try:
        with os.fdopen(descriptor, "r", encoding="utf-8") as source:
            descriptor = -1
            config = json.load(source)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise AvbSigningError("AVB helper config is invalid") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if not isinstance(config, dict):
        raise AvbSigningError("AVB helper config must be a JSON object")
    if config.get("schema_version") != 1:
        raise AvbSigningError("AVB helper config has an unsupported schema")
    password_file = config.get("password_file")
    mappings = config.get("keys")
    if not isinstance(password_file, str) or not Path(password_file).is_absolute():
        raise AvbSigningError("AVB helper config has an invalid password file")
    if not isinstance(mappings, dict) or not mappings:
        raise AvbSigningError("AVB helper config has no key mappings")
    if not all(
        isinstance(public, str)
        and Path(public).is_absolute()
        and isinstance(private, str)
        and Path(private).is_absolute()
        for public, private in mappings.items()
    ):
        raise AvbSigningError("AVB helper config has an invalid key mapping")
    return Path(password_file), dict(mappings)


def _open_private_key(private_key: Path) -> int:
    return _open_owned_private_file(private_key, "encrypted private key")


def _open_owned_private_file(path: Path, label: str) -> int:
    descriptor = -1
    try:
        descriptor = os.open(path, _READ_FLAGS)
        metadata = os.fstat(descriptor)
    except OSError as error:
        if descriptor >= 0:
            os.close(descriptor)
        raise AvbSigningError(f"{label} is unavailable") from error
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o600
    ):
        os.close(descriptor)
        raise AvbSigningError(f"{label} must be an owned mode-0600 regular file")
    return descriptor


@contextmanager
def _password_descriptor(password: str):
    if not hasattr(os, "memfd_create"):
        raise AvbSigningError("anonymous password descriptors are unavailable")
    descriptor = os.memfd_create("avb-key-password", getattr(os, "MFD_CLOEXEC", 0))
    try:
        payload = (password + "\n").encode("utf-8")
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written == 0:
                raise AvbSigningError("could not prepare the password descriptor")
            view = view[written:]
        os.lseek(descriptor, 0, os.SEEK_SET)
        yield descriptor
    finally:
        os.close(descriptor)


def _fd_path(descriptor: int) -> str:
    return f"/proc/self/fd/{descriptor}"


def main(argv: list[str] | None = None) -> int:
    arguments = sys.argv[1:] if argv is None else argv
    if len(arguments) != 2:
        print("usage: avb_signing_helper.py ALGORITHM PUBLIC_KEY", file=sys.stderr)
        return 2
    config_value = os.environ.get(_CONFIG_ENV, "")
    try:
        if not config_value:
            raise AvbSigningError("AVB signing config is unavailable")
        signature = sign_payload(
            Path(config_value),
            arguments[0],
            Path(arguments[1]),
            sys.stdin.buffer.read(),
        )
    except AvbSigningError:
        print("AVB signing failed", file=sys.stderr)
        return 1
    sys.stdout.buffer.write(signature)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
