#!/usr/bin/env python3
"""Rewrite fleur SELinux signer policy from build certificates to release certificates."""

from __future__ import annotations

import hashlib
import base64
import binascii
import io
from pathlib import Path
import re
import shutil
import stat
from typing import Mapping, Sequence
import xml.etree.ElementTree as ET
import zipfile


class MacPermissionsError(ValueError):
    """Raised when SELinux signer policy cannot be rewritten unambiguously."""


EXPECTED_SEINFO_ROLES = {
    "platform": "platform",
    "sdk_sandbox": "sdk_sandbox",
    "bluetooth": "bluetooth",
    "media": "media",
    "network_stack": "networkstack",
    "nfc": "nfc",
}

_SIGNER_TAG = re.compile(
    rb"<signer(?P<before>[^<>]*?)\bsignature=\"(?P<signature>[^\"]*)\""
    rb"(?P<after>[^<>]*)>"
)
_LOWER_HEX = re.compile(rb"(?:[0-9a-f]{2})+")
_CERTIFICATE_PEM = re.compile(
    rb"\A\s*-----BEGIN CERTIFICATE-----\s*"
    rb"(?P<body>[A-Za-z0-9+/=\r\n]+?)\s*"
    rb"-----END CERTIFICATE-----\s*\Z"
)
_MAC_PERMISSIONS_MEMBER = re.compile(
    r"(?:ODM|PRODUCT|SYSTEM|SYSTEM_EXT|VENDOR)/etc/selinux/"
    r"[a-z0-9_]+_mac_permissions\.xml\Z"
)
EXPECTED_MAC_PERMISSIONS_MEMBERS = frozenset(
    {
        "SYSTEM/etc/selinux/plat_mac_permissions.xml",
        "SYSTEM_EXT/etc/selinux/system_ext_mac_permissions.xml",
        "VENDOR/etc/selinux/vendor_mac_permissions.xml",
        "PRODUCT/etc/selinux/product_mac_permissions.xml",
        "ODM/etc/selinux/odm_mac_permissions.xml",
    }
)
_SYSTEM_POLICY = "SYSTEM/etc/selinux/plat_mac_permissions.xml"
_VENDOR_POLICY = "VENDOR/etc/selinux/vendor_mac_permissions.xml"
EXPECTED_ROLE_TOPOLOGY = {
    "platform": (_SYSTEM_POLICY, _VENDOR_POLICY),
    "sdk_sandbox": (_SYSTEM_POLICY,),
    "bluetooth": (_SYSTEM_POLICY,),
    "media": (_SYSTEM_POLICY,),
    "networkstack": (_SYSTEM_POLICY,),
    "nfc": (_SYSTEM_POLICY,),
}
EXPECTED_OTACERTS_MEMBERS = (
    "BOOT/RAMDISK/system/etc/security/otacerts.zip",
    "SYSTEM/etc/security/otacerts.zip",
)
_REDUNDANT_OTA_KEY_PROPERTIES = frozenset(
    {"extra_recovery_keys", "extra_ota_keys"}
)


def certificate_der_from_pem(payload: bytes) -> bytes:
    """Decode one canonical PEM certificate and validate its outer DER sequence."""
    match = _CERTIFICATE_PEM.fullmatch(payload)
    if match is None:
        raise MacPermissionsError("certificate PEM is invalid")
    try:
        der = base64.b64decode(re.sub(rb"\s+", b"", match.group("body")), validate=True)
    except (ValueError, binascii.Error) as error:
        raise MacPermissionsError("certificate PEM is invalid") from error
    if len(der) < 2 or der[0] != 0x30:
        raise MacPermissionsError("certificate DER is invalid")
    first_length = der[1]
    if first_length < 0x80:
        content_length = first_length
        header_length = 2
    else:
        length_bytes = first_length & 0x7F
        if (
            length_bytes == 0
            or length_bytes > 4
            or len(der) < 2 + length_bytes
            or der[2] == 0
        ):
            raise MacPermissionsError("certificate DER is invalid")
        content_length = int.from_bytes(der[2 : 2 + length_bytes], "big")
        if content_length < 0x80:
            raise MacPermissionsError("certificate DER is invalid")
        header_length = 2 + length_bytes
    if header_length + content_length != len(der):
        raise MacPermissionsError("certificate DER is invalid")
    return der


def validate_otacerts_archive(payload: bytes, release_certificate: bytes) -> str:
    """Require one canonically named regular release certificate in otacerts.zip."""
    try:
        with zipfile.ZipFile(io.BytesIO(payload)) as archive:
            members = archive.infolist()
            if len(members) != 1 or members[0].filename != "releasekey.x509.pem":
                raise MacPermissionsError(
                    "OTA certificate archive must contain one canonical releasekey"
                )
            member = members[0]
            file_type = (member.external_attr >> 16) & 0o170000
            if member.is_dir() or file_type not in (0, stat.S_IFREG):
                raise MacPermissionsError("OTA certificate archive member is unsafe")
            certificate = archive.read(member)
    except (OSError, zipfile.BadZipFile, RuntimeError) as error:
        raise MacPermissionsError("OTA certificate archive is invalid") from error
    if certificate != release_certificate:
        raise MacPermissionsError("OTA certificate does not match releasekey")
    return hashlib.sha256(payload).hexdigest()


def validate_target_files_otacerts(
    archive: zipfile.ZipFile, release_certificate: bytes
) -> dict[str, str]:
    """Validate both Fleur OTA trust archives without extracting them."""
    evidence: dict[str, str] = {}
    for name in EXPECTED_OTACERTS_MEMBERS:
        matches = [member for member in archive.infolist() if member.filename == name]
        if len(matches) != 1:
            raise MacPermissionsError(
                f"target-files must contain exactly one OTA certificate member {name}"
            )
        file_type = (matches[0].external_attr >> 16) & 0o170000
        if matches[0].is_dir() or file_type not in (0, stat.S_IFREG):
            raise MacPermissionsError(
                f"target-files OTA certificate member is not regular: {name}"
            )
        evidence[name] = validate_otacerts_archive(
            archive.read(matches[0]), release_certificate
        )
    return evidence


def _canonicalize_ota_trust_metadata(name: str, payload: bytes) -> bytes:
    if name == "META/otakeys.txt":
        return b"\n"
    if name != "META/misc_info.txt":
        return payload
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as error:
        raise MacPermissionsError("META/misc_info.txt is not UTF-8") from error
    output: list[str] = []
    for source_line in text.splitlines():
        stripped = source_line.strip()
        if stripped and not stripped.startswith("#"):
            if "=" not in source_line:
                raise MacPermissionsError("META/misc_info.txt is malformed")
            key, _value = source_line.split("=", 1)
            if key.strip() in _REDUNDANT_OTA_KEY_PROPERTIES:
                source_line = f"{key}="
        output.append(source_line)
    return ("\n".join(output) + "\n").encode("utf-8")


def mac_permissions_documents_from_archive(
    archive: zipfile.ZipFile,
) -> dict[str, bytes]:
    infos = archive.infolist()
    names: set[str] = set()
    for info in infos:
        name = info.filename
        parts = name.split("/")
        file_type = (info.external_attr >> 16) & 0o170000
        if (
            not name
            or "\x00" in name
            or "\\" in name
            or name.startswith("/")
            or (len(name) > 1 and name[1] == ":" and name[0].isalpha())
            or ".." in parts
            or parts[-1] == "."
            or any(part in {"", "."} for part in parts[:-1])
        ):
            raise MacPermissionsError(f"target-files has unsafe member {name!r}")
        if name in names:
            raise MacPermissionsError("target-files has duplicate members")
        names.add(name)
        if file_type not in (0, stat.S_IFREG, stat.S_IFDIR, stat.S_IFLNK):
            raise MacPermissionsError(
                f"target-files has special-file member {name}"
            )
    selected = {
        info.filename: info
        for info in infos
        if _MAC_PERMISSIONS_MEMBER.fullmatch(info.filename)
    }
    if set(selected) != EXPECTED_MAC_PERMISSIONS_MEMBERS:
        raise MacPermissionsError("fleur mac_permissions member topology is invalid")
    documents: dict[str, bytes] = {}
    for name, info in selected.items():
        file_type = (info.external_attr >> 16) & 0o170000
        if info.is_dir() or file_type not in (0, stat.S_IFREG):
            raise MacPermissionsError(
                f"mac_permissions member is not regular: {name}"
            )
        documents[name] = archive.read(info)
    return documents


def _require_exact_role_topology(occurrences: Mapping[str, Sequence[str]]) -> None:
    for role, expected_members in EXPECTED_ROLE_TOPOLOGY.items():
        if tuple(occurrences.get(role, ())) != expected_members:
            raise MacPermissionsError(
                f"fleur signer topology is invalid for {role}"
            )


def expected_source_certificates(
    documents: Mapping[str, bytes],
) -> dict[str, tuple[bytes, ...]]:
    """Derive the exact old certificate for each required fleur seinfo role."""
    discovered: dict[str, set[bytes]] = {
        role: set() for role in EXPECTED_SEINFO_ROLES.values()
    }
    occurrences: dict[str, list[str]] = {
        role: [] for role in EXPECTED_SEINFO_ROLES.values()
    }
    if set(documents) != EXPECTED_MAC_PERMISSIONS_MEMBERS:
        raise MacPermissionsError("fleur mac_permissions member topology is invalid")
    for name in sorted(documents):
        payload = documents[name]
        try:
            root = ET.fromstring(payload)
        except ET.ParseError as error:
            raise MacPermissionsError(f"malformed XML in {name}") from error
        elements = list(root.iter("signer"))
        matches = list(_SIGNER_TAG.finditer(payload))
        if root.tag != "policy" or len(elements) != len(matches):
            raise MacPermissionsError(f"canonical signature encoding is required in {name}")
        for element, match in zip(elements, matches, strict=True):
            encoded = match.group("signature")
            if (
                element.attrib.get("signature") != encoded.decode("ascii", "ignore")
                or _LOWER_HEX.fullmatch(encoded) is None
            ):
                raise MacPermissionsError(
                    f"canonical signature encoding is required in {name}"
                )
            seinfo = [
                child.attrib.get("value")
                for child in element
                if child.tag == "seinfo"
            ]
            if len(seinfo) != 1 or not seinfo[0]:
                raise MacPermissionsError(f"ambiguous signer policy in {name}")
            role = EXPECTED_SEINFO_ROLES.get(seinfo[0])
            if role is not None:
                discovered[role].add(bytes.fromhex(encoded.decode("ascii")))
                occurrences[role].append(name)
    _require_exact_role_topology(occurrences)
    for role, certificates in discovered.items():
        if len(certificates) != 1:
            raise MacPermissionsError(f"ambiguous expected signer source for {role}")
    return {
        role: tuple(certificates)
        for role, certificates in discovered.items()
    }


def rewrite_target_files_mac_permissions(
    source: Path,
    destination: Path,
    source_certificates: Mapping[str, Sequence[bytes]],
    release_certificates: Mapping[str, bytes],
) -> dict[str, object]:
    """Copy a target-files ZIP while rewriting only selected policy payloads."""
    try:
        with zipfile.ZipFile(source) as input_archive:
            infos = input_archive.infolist()
            documents = mac_permissions_documents_from_archive(input_archive)
            rewritten, evidence = rewrite_mac_permissions(
                documents, source_certificates, release_certificates
            )
            with zipfile.ZipFile(destination, "x", allowZip64=True) as output_archive:
                output_archive.comment = input_archive.comment
                for info in infos:
                    if info.filename in rewritten:
                        output_archive.writestr(info, rewritten[info.filename])
                        continue
                    if info.filename in {"META/misc_info.txt", "META/otakeys.txt"}:
                        output_archive.writestr(
                            info,
                            _canonicalize_ota_trust_metadata(
                                info.filename, input_archive.read(info)
                            ),
                        )
                        continue
                    if info.is_dir():
                        output_archive.writestr(info, b"")
                        continue
                    with input_archive.open(info) as input_member, output_archive.open(
                        info, "w", force_zip64=True
                    ) as output_member:
                        shutil.copyfileobj(input_member, output_member, 1024 * 1024)
    except (OSError, zipfile.BadZipFile, RuntimeError) as error:
        if isinstance(error, MacPermissionsError):
            raise
        raise MacPermissionsError("target-files mac_permissions rewrite failed") from error
    return evidence


def rewrite_mac_permissions(
    documents: Mapping[str, bytes],
    source_certificates: Mapping[str, Sequence[bytes]],
    release_certificates: Mapping[str, bytes],
) -> tuple[dict[str, bytes], dict[str, object]]:
    """Return byte-preserving policy documents with exact signer substitutions."""
    if set(documents) != EXPECTED_MAC_PERMISSIONS_MEMBERS:
        raise MacPermissionsError("fleur mac_permissions member topology is invalid")
    required_roles = set(EXPECTED_SEINFO_ROLES.values())
    if set(release_certificates) & required_roles != required_roles:
        raise MacPermissionsError("missing expected signer release certificate")
    for role in required_roles:
        if len(source_certificates.get(role, ())) != 1:
            raise MacPermissionsError(f"ambiguous expected signer source for {role}")
    release_values = [release_certificates[role] for role in sorted(required_roles)]
    if len(set(release_values)) != len(release_values):
        raise MacPermissionsError("duplicate target certificate mappings")
    for role in required_roles:
        if release_certificates[role] == source_certificates[role][0]:
            raise MacPermissionsError(f"target certificate does not replace source for {role}")

    source_roles: dict[bytes, set[str]] = {}
    for role, certificates in source_certificates.items():
        for certificate in certificates:
            if not certificate:
                raise MacPermissionsError("source certificate is empty")
            source_roles.setdefault(certificate, set()).add(role)

    occurrences: dict[str, list[str]] = {role: [] for role in required_roles}
    rewritten: dict[str, bytes] = {}
    member_evidence: dict[str, dict[str, str]] = {}
    for name in sorted(documents):
        payload = documents[name]
        try:
            root = ET.fromstring(payload)
        except ET.ParseError as error:
            raise MacPermissionsError(f"malformed XML in {name}") from error
        if root.tag != "policy":
            raise MacPermissionsError(f"malformed XML policy root in {name}")
        elements = list(root.iter("signer"))
        matches = list(_SIGNER_TAG.finditer(payload))
        if len(matches) != len(elements):
            raise MacPermissionsError(f"canonical signature encoding is required in {name}")
        replacements: list[bytes] = []
        for element, match in zip(elements, matches, strict=True):
            encoded = match.group("signature")
            if (
                element.attrib.get("signature") != encoded.decode("ascii", "ignore")
                or _LOWER_HEX.fullmatch(encoded) is None
            ):
                raise MacPermissionsError(
                    f"canonical signature encoding is required in {name}"
                )
            signature = bytes.fromhex(encoded.decode("ascii"))
            seinfo = [
                child.attrib.get("value")
                for child in element
                if child.tag == "seinfo"
            ]
            if len(seinfo) != 1 or not seinfo[0]:
                raise MacPermissionsError(f"ambiguous signer policy in {name}")
            expected_role = EXPECTED_SEINFO_ROLES.get(seinfo[0])
            candidates = source_roles.get(signature, set())
            if expected_role is not None:
                if candidates != {expected_role}:
                    problem = "missing" if not candidates else "ambiguous"
                    raise MacPermissionsError(
                        f"{problem} expected signer {expected_role} in {name}"
                    )
                occurrences[expected_role].append(name)
                replacements.append(release_certificates[expected_role].hex().encode())
            else:
                if candidates:
                    raise MacPermissionsError(
                        f"unknown re-signed role in {name}: {sorted(candidates)}"
                    )
                replacements.append(encoded)

        replacement_iterator = iter(replacements)

        def substitute(match: re.Match[bytes]) -> bytes:
            return (
                b"<signer"
                + match.group("before")
                + b'signature="'
                + next(replacement_iterator)
                + b'"'
                + match.group("after")
                + b">"
            )

        output = _SIGNER_TAG.sub(substitute, payload)
        try:
            next(replacement_iterator)
        except StopIteration:
            pass
        else:  # pragma: no cover - guarded by equal element/match counts.
            raise MacPermissionsError("internal signer rewrite mismatch")
        rewritten[name] = output
        member_evidence[name] = {
            "unsigned_sha256": hashlib.sha256(payload).hexdigest(),
            "signed_sha256": hashlib.sha256(output).hexdigest(),
        }

    _require_exact_role_topology(occurrences)
    role_evidence = {
        role: {
            "occurrences": len(occurrences[role]),
            "source_certificate_sha256": hashlib.sha256(
                source_certificates[role][0]
            ).hexdigest(),
            "release_certificate_sha256": hashlib.sha256(
                release_certificates[role]
            ).hexdigest(),
        }
        for role in sorted(required_roles)
    }
    return rewritten, {"members": member_evidence, "roles": role_evidence}
