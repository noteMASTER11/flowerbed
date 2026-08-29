#!/usr/bin/env python3
"""Return one exact encrypted-key password through a private helper pipe."""

from __future__ import annotations

import os
from pathlib import Path
import re
import stat
import sys
import unicodedata


class PasswordLookupError(ValueError):
    """Raised when the password file cannot be trusted or queried exactly."""


_LINEAGE_ENTRY = re.compile(r"^\[\[\[\s*(.*?)\s*\]\]\]\s*(\S+)$")
_OPEN_DELIMITER = "[[["
_CLOSE_DELIMITER = "]]]"


def parse_password_file(password_file: Path) -> dict[str, str]:
    """Parse a trusted Lineage password-manager file without logging its lines."""
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
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        match = _LINEAGE_ENTRY.fullmatch(stripped)
        if match is None:
            raise PasswordLookupError("password file contains a malformed entry")
        password, name = match.groups()
        _validate_password(password)
        _validate_key_name(name)
        if name in entries:
            raise PasswordLookupError("password file contains a duplicate entry")
        entries[name] = password
    return entries


def lookup_password(password_file: Path, key_file_name: str) -> str:
    """Return the exact key entry from a private, owner-only password file."""
    _validate_key_name(key_file_name)
    entries = parse_password_file(password_file)

    try:
        return entries[key_file_name]
    except KeyError as error:
        raise PasswordLookupError("password file has no exact matching entry") from error


def _validate_password(password: str) -> None:
    if not password or password != password.strip():
        raise PasswordLookupError("password file contains an unsafe password")
    if _OPEN_DELIMITER in password or _CLOSE_DELIMITER in password:
        raise PasswordLookupError("password file contains an unsafe password")
    if any(
        unicodedata.category(character).startswith("C")
        or unicodedata.category(character) in {"Zl", "Zp"}
        for character in password
    ):
        raise PasswordLookupError("password file contains an unsafe password")


def _validate_key_name(key_file_name: str) -> None:
    if not key_file_name or any(character.isspace() for character in key_file_name):
        raise PasswordLookupError("invalid requested key name")
    if _OPEN_DELIMITER in key_file_name or _CLOSE_DELIMITER in key_file_name:
        raise PasswordLookupError("invalid requested key name")
    if any(unicodedata.category(character).startswith("C") for character in key_file_name):
        raise PasswordLookupError("invalid requested key name")


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
    sys.stdout.write(password)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
