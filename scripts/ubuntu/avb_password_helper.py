#!/usr/bin/env python3
"""Return one encrypted-key password through avbtool's secure-storage pipe."""

from __future__ import annotations

import os
from pathlib import Path
import stat
import sys


class PasswordLookupError(ValueError):
    """Raised when the password file cannot be trusted or queried exactly."""


def lookup_password(password_file: Path, key_file_name: str) -> str:
    """Return the exact key entry from a private, owner-only password file."""
    if not key_file_name or "\n" in key_file_name or "\r" in key_file_name:
        raise PasswordLookupError("invalid requested key name")

    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(password_file, flags)
    except OSError as error:
        raise PasswordLookupError("password file is unavailable") from error

    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise PasswordLookupError("password file is not a regular file")
        if metadata.st_uid != os.geteuid():
            raise PasswordLookupError("password file has the wrong owner")
        if stat.S_IMODE(metadata.st_mode) != 0o600:
            raise PasswordLookupError("password file permissions must be 0600")
        with os.fdopen(descriptor, "r", encoding="utf-8", newline="") as source:
            descriptor = -1
            text = source.read()
    except (OSError, UnicodeError) as error:
        raise PasswordLookupError("password file cannot be read safely") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)

    entries: dict[str, str] = {}
    for line in text.splitlines():
        if not line or "=" not in line:
            raise PasswordLookupError("password file contains a malformed entry")
        name, password = line.split("=", 1)
        if not name or not password or "\x00" in name or "\x00" in password:
            raise PasswordLookupError("password file contains a malformed entry")
        if name in entries:
            raise PasswordLookupError("password file contains a duplicate entry")
        entries[name] = password

    try:
        return entries[key_file_name]
    except KeyError as error:
        raise PasswordLookupError("password file has no exact matching entry") from error


def main(argv: list[str] | None = None) -> int:
    arguments = sys.argv[1:] if argv is None else argv
    if len(arguments) != 1:
        print("usage: avb_password_helper.py PASSWORD_FILE", file=sys.stderr)
        return 2
    requested = os.environ.get("TMP__KEY_FILE_NAME", "")
    try:
        password = lookup_password(Path(arguments[0]), requested)
    except PasswordLookupError:
        print("password lookup failed", file=sys.stderr)
        return 1
    sys.stdout.write(password + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
