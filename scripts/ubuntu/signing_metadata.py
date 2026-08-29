"""Parse signing metadata from an Android target-files archive."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re
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
    device: str
    build_tags: frozenset[str]
    uses_test_build_tags: bool
    extra_ota_key_stems: tuple[str, ...] = ()


_PRESIGNED = "PRESIGNED"
_SUPPORTED_AVB_ALGORITHM = "SHA256_RSA4096"
_KEY_SUFFIXES = (".x509.pem", ".pk8", ".avbpubkey", ".pem")
_SAFE_KEY_PATH_COMPONENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*\Z")
_REQUIRED_MEMBERS = (
    "META/apkcerts.txt",
    "META/apexkeys.txt",
    "META/misc_info.txt",
    "META/otakeys.txt",
    "SYSTEM/build.prop",
)


def load_signing_inventory(target_files: Path) -> SigningInventory:
    """Load a deterministic signing inventory from a target-files ZIP archive."""
    with ZipFile(target_files) as archive:
        required = {
            member: _read_required_member(archive, member)
            for member in _REQUIRED_MEMBERS
        }

    apk_certificates = _parse_apkcerts(required["META/apkcerts.txt"])
    apexes = _parse_apexkeys(required["META/apexkeys.txt"])
    misc_info = _parse_misc_info(required["META/misc_info.txt"])
    otakey_stems = _parse_otakeys(required["META/otakeys.txt"])
    avb_keys = _parse_avb_keys(misc_info)
    device, build_tags = _parse_build_identity(required["SYSTEM/build.prop"])
    return _assemble_inventory(
        apk_certificates,
        apexes,
        avb_keys,
        misc_info,
        device=device,
        build_tags=build_tags,
        otakey_stems=otakey_stems,
    )


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
    for line_number, fields in _iter_metadata_records(
        text,
        "apkcerts.txt",
        allowed_empty_fields=("private_key",),
    ):
        values = _required_fields(
            fields,
            ("name", "certificate", "private_key"),
            "apkcerts.txt",
            line_number,
        )
        if not values["private_key"] and values["certificate"] != _PRESIGNED:
            raise SigningMetadataError(
                f"apkcerts.txt line {line_number} has an empty private_key "
                f"for non-PRESIGNED APK {values['name']}"
            )
        certificate = _normalize_key_stem(values["certificate"])
        if not values["private_key"]:
            private_key = _PRESIGNED
        else:
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


def _parse_build_identity(text: str) -> tuple[str, frozenset[str]]:
    properties = _parse_property_file(text, "SYSTEM/build.prop")
    device = _required_consistent_property(
        properties,
        "ro.product.system.device",
        ("ro.build.product", "ro.product.device"),
        "device",
    )
    tag_value = _required_consistent_property(
        properties,
        "ro.build.tags",
        ("ro.system.build.tags",),
        "build tags",
    )
    build_tags = frozenset(tag.strip() for tag in tag_value.split(",") if tag.strip())
    if not build_tags:
        raise SigningMetadataError("SYSTEM/build.prop has empty build tags")
    return device, build_tags


def _parse_property_file(text: str, filename: str) -> Mapping[str, str]:
    values: dict[str, str] = {}
    for line_number, line in _iter_content_lines(text):
        if "=" not in line:
            raise SigningMetadataError(f"{filename} line {line_number} is not key=value")
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if not key:
            raise SigningMetadataError(
                f"{filename} line {line_number} has an empty property key"
            )
        previous = values.get(key)
        if previous is not None and previous != value:
            raise SigningMetadataError(f"{filename} repeats {key} with conflicting values")
        values[key] = value
    return MappingProxyType(dict(sorted(values.items())))


def _required_consistent_property(
    properties: Mapping[str, str],
    primary: str,
    aliases: tuple[str, ...],
    label: str,
) -> str:
    try:
        value = properties[primary]
    except KeyError as error:
        raise SigningMetadataError(
            f"SYSTEM/build.prop is missing canonical {label} property {primary}"
        ) from error
    if not value:
        raise SigningMetadataError(
            f"SYSTEM/build.prop has empty canonical {label} property {primary}"
        )
    conflicting = [name for name in aliases if name in properties and properties[name] != value]
    if conflicting:
        raise SigningMetadataError(f"SYSTEM/build.prop has ambiguous {label}")
    return value


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


def _parse_extra_ota_key_stems(misc_info: Mapping[str, str]) -> tuple[str, ...]:
    stems: set[str] = set()
    for property_name in ("extra_recovery_keys", "extra_ota_keys"):
        for value in misc_info.get(property_name, "").split():
            if any(suffix in value for suffix in _KEY_SUFFIXES):
                raise SigningMetadataError(
                    f"misc_info.txt {property_name} contains an unsafe key stem"
                )
            stems.add(
                _validate_extra_key_stem(value, f"misc_info.txt {property_name}")
            )
    return tuple(sorted(stems))


def _parse_otakeys(text: str) -> tuple[str, ...]:
    stems: set[str] = set()
    for token in text.split():
        if not token.endswith(".x509.pem"):
            raise SigningMetadataError(
                "otakeys.txt entries must be safe .x509.pem key paths"
            )
        stem = token[: -len(".x509.pem")]
        if any(suffix in stem for suffix in _KEY_SUFFIXES):
            raise SigningMetadataError(
                "otakeys.txt entries must contain one exact .x509.pem suffix"
            )
        stems.add(_validate_extra_key_stem(stem, "otakeys.txt"))
    return tuple(sorted(stems))


def _validate_extra_key_stem(value: str, label: str) -> str:
    if (
        value == _PRESIGNED
        or value.startswith("/")
        or "\\" in value
        or "\x00" in value
        or any(
            component in {"", ".", ".."}
            or not _SAFE_KEY_PATH_COMPONENT.fullmatch(component)
            for component in value.split("/")
        )
    ):
        raise SigningMetadataError(f"{label} contains an unsafe key stem")
    return value


def _assemble_inventory(
    apk_certificates: tuple[ApkCertificate, ...],
    apexes: tuple[ApexKey, ...],
    avb_keys: tuple[AvbPartitionKey, ...],
    misc_info: Mapping[str, str],
    *,
    device: str,
    build_tags: frozenset[str],
    otakey_stems: tuple[str, ...] = (),
) -> SigningInventory:
    extra_ota_key_stems = tuple(
        sorted(set(_parse_extra_ota_key_stems(misc_info)) | set(otakey_stems))
    )
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
    source_key_stems.update(extra_ota_key_stems)
    android_roles = {
        Path(certificate.certificate).name
        for certificate in apk_certificates
        if certificate.certificate != _PRESIGNED
    }
    return SigningInventory(
        apk_certificates=tuple(sorted(apk_certificates, key=lambda record: record.name)),
        apexes=tuple(sorted(apexes, key=lambda record: record.name)),
        avb_keys=tuple(sorted(avb_keys, key=lambda record: record.partition)),
        misc_info=MappingProxyType(dict(sorted(misc_info.items()))),
        source_key_stems=frozenset(source_key_stems),
        android_roles=frozenset(android_roles),
        device=device,
        build_tags=frozenset(build_tags),
        uses_test_build_tags="test-keys" in build_tags,
        extra_ota_key_stems=extra_ota_key_stems,
    )


def _iter_metadata_records(
    text: str,
    filename: str,
    *,
    allowed_empty_fields: tuple[str, ...] = (),
):
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
            if not key or (not value and key not in allowed_empty_fields):
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
    for suffix in _KEY_SUFFIXES:
        if value.endswith(suffix):
            return value[: -len(suffix)]
    return value
