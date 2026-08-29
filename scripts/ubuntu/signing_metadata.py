"""Parse signing metadata from an Android target-files archive."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import shlex
from types import MappingProxyType
from typing import Mapping
from zipfile import ZipFile


class SigningMetadataError(ValueError):
    """Raised when target-files signing metadata is missing or inconsistent."""


@dataclass(frozen=True)
class ApkCertificate:
    name: str
    certificate: str
    private_key: str


@dataclass(frozen=True)
class ApexKey:
    name: str
    public_key: str
    private_key: str
    container_certificate: str
    container_private_key: str
    partition: str
    presigned: bool


@dataclass(frozen=True)
class AvbPartitionKey:
    partition: str
    algorithm: str
    source_key: str


@dataclass(frozen=True)
class SigningInventory:
    apk_certificates: tuple[ApkCertificate, ...]
    apexes: tuple[ApexKey, ...]
    avb_keys: tuple[AvbPartitionKey, ...]
    misc_info: Mapping[str, str]
    source_key_stems: frozenset[str]
    android_roles: frozenset[str]
    uses_test_build_tags: bool


_PRESIGNED = "PRESIGNED"
_SUPPORTED_AVB_ALGORITHM = "SHA256_RSA4096"
_REQUIRED_MEMBERS = (
    "META/apkcerts.txt",
    "META/apexkeys.txt",
    "META/misc_info.txt",
)


def load_signing_inventory(target_files: Path) -> SigningInventory:
    """Load a deterministic signing inventory from a target-files ZIP archive."""
    with ZipFile(target_files) as archive:
        apk_text = _read_required_member(archive, _REQUIRED_MEMBERS[0])
        apex_text = _read_required_member(archive, _REQUIRED_MEMBERS[1])
        misc_text = _read_required_member(archive, _REQUIRED_MEMBERS[2])

    apk_certificates = _parse_apkcerts(apk_text)
    apexes = _parse_apexkeys(apex_text)
    misc_info = _parse_misc_info(misc_text)
    avb_keys = _parse_avb_keys(misc_info)
    return _assemble_inventory(apk_certificates, apexes, avb_keys, misc_info)


def _read_required_member(archive: ZipFile, member: str) -> str:
    members = [entry for entry in archive.infolist() if entry.filename == member]
    if len(members) != 1:
        raise SigningMetadataError(
            f"target-files must contain exactly one required member {member}; found {len(members)}"
        )
    try:
        with archive.open(members[0]) as source:
            return source.read().decode("utf-8")
    except UnicodeDecodeError as error:
        raise SigningMetadataError(f"target-files member {member} is not UTF-8") from error


def _parse_apkcerts(text: str) -> tuple[ApkCertificate, ...]:
    records: dict[str, ApkCertificate] = {}
    for line_number, fields in _iter_metadata_records(text, "apkcerts.txt"):
        values = _required_fields(
            fields,
            ("name", "certificate", "private_key"),
            "apkcerts.txt",
            line_number,
        )
        certificate = _normalize_key_stem(values["certificate"])
        private_key = _normalize_key_stem(values["private_key"])
        if certificate != private_key:
            raise SigningMetadataError(
                f"apkcerts.txt line {line_number} has mismatched key stems for {values['name']}"
            )
        record = ApkCertificate(values["name"], certificate, private_key)
        _insert_record(records, record.name, record, "APK certificate")
    return tuple(records[name] for name in sorted(records))


def _parse_apexkeys(text: str) -> tuple[ApexKey, ...]:
    records: dict[str, ApexKey] = {}
    for line_number, fields in _iter_metadata_records(text, "apexkeys.txt"):
        values = _required_fields(
            fields,
            (
                "name",
                "public_key",
                "private_key",
                "container_certificate",
                "container_private_key",
                "partition",
            ),
            "apexkeys.txt",
            line_number,
        )
        key_values = (
            values["public_key"],
            values["private_key"],
            values["container_certificate"],
            values["container_private_key"],
        )
        presigned = any(value == _PRESIGNED for value in key_values)
        if presigned and any(value != _PRESIGNED for value in key_values):
            raise SigningMetadataError(
                f"apexkeys.txt line {line_number} mixes PRESIGNED and key paths"
            )
        public_key = _normalize_key_stem(values["public_key"])
        private_key = _normalize_key_stem(values["private_key"])
        container_certificate = _normalize_key_stem(values["container_certificate"])
        container_private_key = _normalize_key_stem(values["container_private_key"])
        if not presigned and public_key != private_key:
            raise SigningMetadataError(
                f"apexkeys.txt line {line_number} has mismatched payload key stems for {values['name']}"
            )
        if not presigned and container_certificate != container_private_key:
            raise SigningMetadataError(
                f"apexkeys.txt line {line_number} has mismatched container key stems for {values['name']}"
            )
        record = ApexKey(
            name=values["name"],
            public_key=public_key,
            private_key=private_key,
            container_certificate=container_certificate,
            container_private_key=container_private_key,
            partition=values["partition"],
            presigned=presigned,
        )
        _insert_record(records, record.name, record, "APEX")
    return tuple(records[name] for name in sorted(records))


def _parse_misc_info(text: str) -> Mapping[str, str]:
    values: dict[str, str] = {}
    for line_number, line in _iter_content_lines(text):
        if "=" not in line:
            raise SigningMetadataError(f"misc_info.txt line {line_number} is not key=value")
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if not key:
            raise SigningMetadataError(f"misc_info.txt line {line_number} has an empty key")
        previous = values.get(key)
        if previous is not None and previous != value:
            raise SigningMetadataError(f"misc_info.txt repeats {key} with conflicting values")
        values[key] = value
    return MappingProxyType(dict(sorted(values.items())))


def _parse_avb_keys(misc_info: Mapping[str, str]) -> tuple[AvbPartitionKey, ...]:
    avb_fields: dict[str, dict[str, str]] = {}
    for key, value in misc_info.items():
        if not key.startswith("avb_"):
            continue
        if key.endswith("_key_path"):
            partition = key[len("avb_") : -len("_key_path")]
            field = "key_path"
        elif key.endswith("_algorithm"):
            partition = key[len("avb_") : -len("_algorithm")]
            field = "algorithm"
        else:
            continue
        if not partition:
            raise SigningMetadataError(f"invalid AVB metadata name {key}")
        avb_fields.setdefault(partition, {})[field] = value

    for partition in sorted(avb_fields):
        fields = avb_fields[partition]
        missing = {"key_path", "algorithm"} - fields.keys()
        if missing:
            raise SigningMetadataError(
                f"AVB metadata for avb_{partition} is missing {', '.join(sorted(missing))}"
            )

    records: list[AvbPartitionKey] = []
    for partition in sorted(avb_fields):
        fields = avb_fields[partition]
        source_key = fields["key_path"]
        algorithm = fields["algorithm"]
        if algorithm != _SUPPORTED_AVB_ALGORITHM:
            raise SigningMetadataError(
                f"unsupported AVB algorithm {algorithm} for partition {partition}"
            )
        if source_key == _PRESIGNED:
            raise SigningMetadataError(f"AVB partition {partition} must reference a key path")
        records.append(
            AvbPartitionKey(
                partition=partition,
                algorithm=algorithm,
                source_key=_normalize_key_stem(source_key),
            )
        )
    return tuple(sorted(records, key=lambda record: record.partition))


def _assemble_inventory(
    apk_certificates: tuple[ApkCertificate, ...],
    apexes: tuple[ApexKey, ...],
    avb_keys: tuple[AvbPartitionKey, ...],
    misc_info: Mapping[str, str],
) -> SigningInventory:
    source_key_stems = {
        value
        for certificate in apk_certificates
        for value in (certificate.certificate, certificate.private_key)
        if value != _PRESIGNED
    }
    for apex in apexes:
        if not apex.presigned:
            source_key_stems.update(
                (
                    apex.public_key,
                    apex.private_key,
                    apex.container_certificate,
                    apex.container_private_key,
                )
            )
    source_key_stems.update(record.source_key for record in avb_keys)
    android_roles = {
        Path(certificate.certificate).name
        for certificate in apk_certificates
        if certificate.certificate != _PRESIGNED
    }
    build_tags = {
        tag.strip() for tag in misc_info.get("build_tags", "").split(",") if tag.strip()
    }
    return SigningInventory(
        apk_certificates=tuple(sorted(apk_certificates, key=lambda record: record.name)),
        apexes=tuple(sorted(apexes, key=lambda record: record.name)),
        avb_keys=tuple(sorted(avb_keys, key=lambda record: record.partition)),
        misc_info=MappingProxyType(dict(sorted(misc_info.items()))),
        source_key_stems=frozenset(source_key_stems),
        android_roles=frozenset(android_roles),
        uses_test_build_tags="test-keys" in build_tags,
    )


def _iter_metadata_records(text: str, filename: str):
    for line_number, line in _iter_content_lines(text):
        try:
            tokens = shlex.split(line, comments=False, posix=True)
        except ValueError as error:
            raise SigningMetadataError(f"{filename} line {line_number} is malformed") from error
        fields: dict[str, str] = {}
        for token in tokens:
            if "=" not in token:
                raise SigningMetadataError(
                    f"{filename} line {line_number} contains a non key=value field"
                )
            key, value = token.split("=", 1)
            if not key or not value:
                raise SigningMetadataError(
                    f"{filename} line {line_number} contains an empty field"
                )
            if key in fields:
                raise SigningMetadataError(f"{filename} line {line_number} repeats {key}")
            fields[key] = value
        yield line_number, fields


def _iter_content_lines(text: str):
    for line_number, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if stripped and not stripped.startswith("#"):
            yield line_number, stripped


def _required_fields(
    fields: Mapping[str, str],
    required: tuple[str, ...],
    filename: str,
    line_number: int,
) -> dict[str, str]:
    missing = [name for name in required if name not in fields]
    if missing:
        raise SigningMetadataError(
            f"{filename} line {line_number} is missing {', '.join(missing)}"
        )
    return {name: fields[name] for name in required}


def _insert_record(
    records: dict[str, object], name: str, record: object, kind: str
) -> None:
    previous = records.get(name)
    if previous is not None and previous != record:
        raise SigningMetadataError(f"{kind} {name} has conflicting duplicate metadata")
    records[name] = record


def _normalize_key_stem(value: str) -> str:
    if value == _PRESIGNED:
        return value
    for suffix in (".x509.pem", ".pk8", ".avbpubkey", ".pem"):
        if value.endswith(suffix):
            return value[: -len(suffix)]
    return value
