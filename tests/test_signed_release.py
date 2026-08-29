from __future__ import annotations

import base64
import copy
import hashlib
import io
import importlib.util
import json
import os
import stat
import struct
import subprocess
import tarfile
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest import mock
import warnings
import zipfile


ROOT = Path(__file__).resolve().parents[1]
VERIFY = ROOT / "scripts/ubuntu/verify_signed_release.py"
PRE_FIX_BOOT_SHA256 = "9356e7d53016e8a6cf22267abe75b06d50dfeb8d9df90ba99e8e449c3e4544db"
EXPECTED_SKUS = {
    "build_fleur.prop": "Redmi Note 11S",
    "build_miel.prop": "Redmi Note 11S",
    "build_fleurp.prop": "POCO M4 Pro",
    "build_mielp.prop": "POCO M4 Pro",
}
FLEUR_AB_PARTITIONS = (
    "audio_dsp", "boot", "dtbo", "gz", "lk", "logo", "md1img", "odm",
    "pi_img", "preloader_raw", "product", "scp", "spmfw", "sspm", "system",
    "system_ext", "tee", "vbmeta", "vbmeta_system", "vbmeta_vendor", "vendor",
)
FLEUR_IMAGE_PARTITIONS = (
    "boot", "dtbo", "system", "vendor", "product", "system_ext", "odm",
    "vbmeta_system", "vbmeta_vendor", "vbmeta", "super_empty",
    "unsparse_super_empty",
)
FLEUR_RADIO_PARTITIONS = (
    "audio_dsp", "gz", "lk", "logo", "md1img", "pi_img", "preloader_raw",
    "scp", "spmfw", "sspm", "tee",
)
FLEUR_FASTBOOT_INFO = (
    "# fastboot-info for lineage_fleur\n"
    "version 1\n"
    "flash boot\n"
    "flash dtbo\n"
    "flash --apply-vbmeta vbmeta\n"
    "flash vbmeta_system\n"
    "flash vbmeta_vendor\n"
    "reboot fastboot\n"
    "update-super\n"
    "flash system\n"
    "flash system_ext\n"
    "flash product\n"
    "flash vendor\n"
    "flash odm\n"
    "if-wipe erase userdata\n"
    "if-wipe erase metadata\n"
)


def load_verifier():
    if not VERIFY.is_file():
        raise AssertionError("signed release verifier is missing")
    spec = importlib.util.spec_from_file_location("verify_signed_release", VERIFY)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def write_zip_symlink(
    archive: zipfile.ZipFile,
    name: str,
    target: bytes,
    *,
    mode: int = 0o777,
) -> None:
    member = zipfile.ZipInfo(name)
    member.create_system = 3
    member.external_attr = (stat.S_IFLNK | mode) << 16
    archive.writestr(member, target)


def build_newc(
    entries,
    *,
    trailer_data: bytes = b"",
    include_trailer: bool = True,
) -> bytes:
    output = bytearray()
    inode = 300000
    items = list(entries.items()) if isinstance(entries, dict) else list(entries)
    if include_trailer:
        items.append(("TRAILER!!!", (0o755, trailer_data)))
    for name, (mode, data) in items:
        encoded = name.encode("utf-8") + b"\0"
        fields = (
            inode,
            mode,
            0,
            0,
            1,
            0,
            len(data),
            0,
            0,
            0,
            0,
            len(encoded),
            0,
        )
        output.extend(b"070701" + b"".join(f"{value:08x}".encode() for value in fields))
        output.extend(encoded)
        output.extend(b"\0" * (-len(output) % 4))
        output.extend(data)
        output.extend(b"\0" * (-len(output) % 4))
        inode += 1
    if include_trailer:
        output.extend(b"\0" * (-len(output) % 256))
    return bytes(output)


def newc_record_bounds(data: bytes, offset: int = 0) -> dict[str, int]:
    header = data[offset : offset + 110]
    size = int(header[54:62], 16)
    name_size = int(header[94:102], 16)
    name_start = offset + 110
    name_end = name_start + name_size
    data_start = (name_end + 3) & ~3
    data_end = data_start + size
    return {
        "header": offset,
        "name_end": name_end,
        "data_start": data_start,
        "data_end": data_end,
        "record_end": (data_end + 3) & ~3,
    }


def fleur_fastboot_entries() -> tuple[dict[str, bytes], dict[str, bytes]]:
    target = {
        "META/misc_info.txt": (
            "build_super_partition=true\n"
            "dynamic_partition_list=odm product system system_ext vendor\n"
        ).encode(),
        "META/ab_partitions.txt": (
            "\n".join(FLEUR_AB_PARTITIONS) + "\n"
        ).encode(),
        "META/fastboot-info.txt": FLEUR_FASTBOOT_INFO.encode(),
        "OTA/android-info.txt": b"board=fleur\n",
    }
    for partition in FLEUR_IMAGE_PARTITIONS:
        target[f"IMAGES/{partition}.img"] = f"image-{partition}".encode()
    for partition in FLEUR_RADIO_PARTITIONS:
        target[f"RADIO/{partition}.img"] = f"radio-{partition}".encode()
    fastboot = {
        "android-info.txt": target["OTA/android-info.txt"],
        "fastboot-info.txt": target["META/fastboot-info.txt"],
    }
    for source, value in target.items():
        if source.startswith(("IMAGES/", "RADIO/")):
            fastboot[Path(source).name] = value
    return target, fastboot


def write_zip_entries(path: Path, entries: dict[str, bytes]) -> None:
    with zipfile.ZipFile(path, "w") as archive:
        for name, value in entries.items():
            archive.writestr(name, value)


MAC_SEINFO_ROLES = {
    "platform": "platform",
    "sdk_sandbox": "sdk_sandbox",
    "bluetooth": "bluetooth",
    "media": "media",
    "network_stack": "networkstack",
    "nfc": "nfc",
}


def mac_der(role: str, *, release: bool = False) -> bytes:
    payload = f"{'release' if release else 'source'}-{role}".encode()
    return b"\x30" + bytes((len(payload),)) + payload


def mac_pem(role: str) -> bytes:
    value = mac_der(role, release=True)
    return (
        b"-----BEGIN CERTIFICATE-----\n"
        + base64.b64encode(value)
        + b"\n-----END CERTIFICATE-----\n"
    )


def mac_policy(*, signed: bool) -> bytes:
    signers = b"".join(
        b'<signer signature="'
        + mac_der(role, release=signed).hex().encode()
        + b'"><seinfo value="'
        + seinfo.encode()
        + b'"/></signer>'
        for seinfo, role in MAC_SEINFO_ROLES.items()
    )
    return (
        b'<?xml version="1.0" encoding="iso-8859-1"?><policy>'
        + signers
        + b"</policy>"
    )


class SignedReleasePolicyTest(unittest.TestCase):
    def _payload(self, manifest: bytes = b"manifest", signatures: bytes = b"sig"):
        header = struct.pack(">4sQQI", b"CrAU", 2, len(manifest), len(signatures))
        return header + manifest + signatures + b"partition-data"

    def test_rejects_test_build_tags(self):
        module = load_verifier()
        with self.assertRaisesRegex(module.VerificationError, "test-keys"):
            module.verify_build_tags({"ro.product.build.tags": "test-keys"})

    def test_property_parser_allows_optional_empty_values_but_rejects_bad_syntax(self):
        module = load_verifier()
        properties = module._parse_properties(
            "ro.build.version.base_os=\n"
            "ro.product.system.device=fleur\n"
            "ro.build.tags=release-keys\n",
            "SYSTEM/build.prop",
        )
        self.assertEqual("", properties["ro.build.version.base_os"])
        for malformed in (
            "ro.build.version.base_os\n",
            "=value\n",
            "   =value\n",
        ):
            with self.assertRaises(module.VerificationError):
                module._parse_properties(malformed, "SYSTEM/build.prop")

    def test_required_target_build_properties_reject_missing_or_empty_values(self):
        module = load_verifier()
        self.assertEqual(
            "release-keys",
            module.verify_target_build_properties(
                {
                    "ro.build.version.base_os": "",
                    "ro.product.system.device": "fleur",
                    "ro.build.tags": "release-keys",
                }
            ),
        )
        for properties in (
            {"ro.build.tags": "release-keys"},
            {
                "ro.product.system.device": "",
                "ro.build.tags": "release-keys",
            },
            {"ro.product.system.device": "fleur"},
            {
                "ro.product.system.device": "fleur",
                "ro.build.tags": "",
            },
        ):
            with self.assertRaises(module.VerificationError):
                module.verify_target_build_properties(properties)

    def test_rejects_wrong_ota_device(self):
        module = load_verifier()
        with self.assertRaisesRegex(module.VerificationError, "pre-device"):
            module.verify_ota_metadata("pre-device=wrong\nota-type=AB\n")

    def test_rejects_missing_market_name(self):
        module = load_verifier()
        with self.assertRaisesRegex(module.VerificationError, "marketname"):
            module.verify_sku_properties(
                {"build_fleur.prop": "ro.product.odm.model=fleur\n"}
            )

    def test_rejects_mismatched_avb_fingerprints(self):
        module = load_verifier()
        with self.assertRaisesRegex(module.VerificationError, "AVB"):
            module.verify_avb_fingerprints({"boot": "old"}, {"boot": "new"})

    def test_accepts_all_sku_mappings_release_tags_and_matching_avb(self):
        module = load_verifier()
        properties = {
            name: (
                f"ro.product.marketname={market_name}\n"
                f"ro.product.odm.model={market_name}\n"
            )
            for name, market_name in EXPECTED_SKUS.items()
        }
        self.assertEqual("release-keys", module.verify_build_tags({"ro.build.tags": "release-keys"}))
        self.assertEqual("fleur", module.verify_ota_metadata("pre-device=fleur\nota-type=AB\n")["pre-device"])
        self.assertEqual(EXPECTED_SKUS, module.verify_sku_properties(properties))
        fingerprints = {name: hashlib.sha256(name.encode()).hexdigest() for name in ("boot", "vbmeta", "vbmeta_system", "vbmeta_vendor")}
        self.assertEqual(fingerprints, module.verify_avb_fingerprints(fingerprints, dict(fingerprints)))

    def test_allows_preserved_source_paths_but_rejects_test_keys_in_misc(self):
        module = load_verifier()
        avb_metadata = "".join(
            f"avb_{partition}_key_path=/release/.signing-runtime/public-pem/avb_{partition}.public.pem\n"
            f"avb_{partition}_algorithm=SHA256_RSA4096\n"
            for partition in module.REQUIRED_AVB_PARTITIONS
        )
        optional_nonsecurity_misc = (
            "building_oem_image=\n"
            "mkbootimg_init_args=\n"
            "tool_extensions=device/xiaomi/fleur/../common\n"
            "extra_ota_keys=\n"
            "extra_recovery_keys=vendor/lineage/build/target/product/security/lineage\n"
        )
        permitted = module.verify_signing_metadata_paths(
            'name="Settings.apk" certificate="build/make/target/product/security/testkey.x509.pem" private_key="build/make/target/product/security/testkey.pk8"\n'
            'name="AndroidXComposeStartupApp.apk" certificate="PRESIGNED" private_key="" partition="data"\n',
            'name="com.android.art.apex" public_key="build/make/target/product/security/com.android.art.avbpubkey" private_key="build/make/target/product/security/com.android.art.pem" container_certificate="build/make/target/product/security/platform.x509.pem" container_private_key="build/make/target/product/security/platform.pk8" partition="system"\n'
            'name="com.android.tzdata.apex" public_key="PRESIGNED" private_key="PRESIGNED" container_certificate="PRESIGNED" container_private_key="PRESIGNED" partition="system"\n',
            "default_system_dev_certificate=release/releasekey\n"
            + optional_nonsecurity_misc
            + avb_metadata,
        )
        self.assertEqual(["com.android.tzdata.apex"], permitted)
        with self.assertRaisesRegex(module.VerificationError, "test certificate"):
            module.verify_signing_metadata_paths(
                'name="Settings.apk" certificate="build/make/target/product/security/testkey.x509.pem" private_key="build/make/target/product/security/testkey.pk8"\n',
                "",
                "default_system_dev_certificate=build/make/target/product/security/testkey\n"
                + avb_metadata,
            )
        with self.assertRaisesRegex(module.VerificationError, "malformed|private_key"):
            module.verify_signing_metadata_paths(
                'name="Settings.apk" certificate="release/platform.x509.pem" private_key=""\n',
                "",
                "default_system_dev_certificate=release/releasekey\n"
                + avb_metadata,
            )
        with self.assertRaisesRegex(module.VerificationError, "vbmeta_vendor"):
            module.verify_signing_metadata_paths(
                'name="Settings.apk" certificate="release/platform.x509.pem" private_key="release/platform.pk8"\n',
                'name="com.android.tzdata.apex" public_key="PRESIGNED" private_key="PRESIGNED" container_certificate="PRESIGNED" container_private_key="PRESIGNED" partition="system"\n',
                "default_system_dev_certificate=release/releasekey\n"
                + avb_metadata.replace(
                    "avb_vbmeta_vendor_key_path=/release/.signing-runtime/public-pem/avb_vbmeta_vendor.public.pem\n",
                    "",
                ),
            )
        with self.assertRaisesRegex(module.VerificationError, "vbmeta_vendor"):
            module.verify_signing_metadata_paths(
                'name="Settings.apk" certificate="release/platform.x509.pem" private_key="release/platform.pk8"\n',
                "",
                "default_system_dev_certificate=release/releasekey\n"
                + optional_nonsecurity_misc
                + avb_metadata.replace(
                    "avb_vbmeta_vendor_key_path=/release/.signing-runtime/public-pem/avb_vbmeta_vendor.public.pem",
                    "avb_vbmeta_vendor_key_path=",
                ),
            )
        security_failures = (
            (
                "missing default certificate",
                avb_metadata,
                "default_system_dev_certificate",
            ),
            (
                "empty default certificate",
                "default_system_dev_certificate=\n" + avb_metadata,
                "default_system_dev_certificate",
            ),
            (
                "default certificate traversal",
                "default_system_dev_certificate=release/../releasekey\n"
                + avb_metadata,
                "traversal",
            ),
            (
                "AVB test key",
                "default_system_dev_certificate=release/releasekey\n"
                + avb_metadata.replace(
                    "avb_boot_key_path=/release/.signing-runtime/public-pem/avb_boot.public.pem",
                    "avb_boot_key_path=build/make/target/product/security/testkey.pem",
                ),
                "test certificate",
            ),
            (
                "extra recovery traversal",
                "default_system_dev_certificate=release/releasekey\n"
                "extra_recovery_keys=vendor/keys/../test\n"
                + avb_metadata,
                "traversal",
            ),
            (
                "extra OTA test key",
                "default_system_dev_certificate=release/releasekey\n"
                "extra_ota_keys=build/make/target/product/security/testkey\n"
                + avb_metadata,
                "test certificate",
            ),
            (
                "extra key NUL",
                "default_system_dev_certificate=release/releasekey\n"
                "extra_recovery_keys=vendor/keys/good vendor/keys/bad\x00key\n"
                + avb_metadata,
                "invalid",
            ),
        )
        for label, misc_info, message in security_failures:
            with self.subTest(label=label):
                with self.assertRaisesRegex(module.VerificationError, message):
                    module.verify_signing_metadata_paths("", "", misc_info)
        for malformed in ("building_oem_image\n", "=value\n"):
            with self.assertRaises(module.VerificationError):
                module.verify_signing_metadata_paths(
                    "", "", malformed + avb_metadata
                )

    def test_avb_role_normalization_accepts_exact_public_pem_convention(self):
        module = load_verifier()
        self.assertEqual(
            "avb_boot",
            module._key_role(
                "/release/.signing-runtime/public-pem/avb_boot.public.pem"
            ),
        )
        for suffix in (".pem", ".x509.pem", ".pk8", ".avbpubkey"):
            self.assertEqual("avb_boot", module._key_role("keys/avb_boot" + suffix))
        valid_misc = "default_system_dev_certificate=release/releasekey\n" + "".join(
            f"avb_{partition}_key_path=keys/avb_{partition}.public.pem\n"
            f"avb_{partition}_algorithm=SHA256_RSA4096\n"
            for partition in module.REQUIRED_AVB_PARTITIONS
        )
        for deceptive in (
            "keys/avb_boot.public.pem.bak",
            "keys/avb_boot.fake.public.pem",
            "keys/avb_boot.public.public.pem",
            "keys/avb_boot.public.pem/wrong.pem",
            "keys/avb_vbmeta.public.pem",
        ):
            self.assertNotEqual("avb_boot", module._key_role(deceptive))
            with self.assertRaisesRegex(module.VerificationError, "boot"):
                module.verify_signing_metadata_paths(
                    "",
                    "",
                    valid_misc.replace(
                        "avb_boot_key_path=keys/avb_boot.public.pem",
                        f"avb_boot_key_path={deceptive}",
                    ),
                )

    def test_kernel_provenance_allows_only_expected_boot_signing_transform(self):
        module = load_verifier()
        release_certificate = b"release-certificate"
        unsigned_otacerts = io.BytesIO()
        with zipfile.ZipFile(unsigned_otacerts, "w") as archive:
            archive.writestr("lineage.x509.pem", b"lineage-certificate")
            archive.writestr("testkey.x509.pem", b"test-certificate")
        signed_otacerts = io.BytesIO()
        with zipfile.ZipFile(signed_otacerts, "w") as archive:
            archive.writestr("releasekey.x509.pem", release_certificate)

        metadata = (1, stat.S_IFREG | 0o644, 0, 0, 1, 0, 0, 0, 0, 0, 0)

        def entry(data: bytes):
            return {"metadata": metadata, "data": data}

        unsigned = {
            "raw_sha256": "e" * 64,
            "content_sha256": "c" * 64,
            "kernel_sha256": "2" * 64,
            "dtb_sha256": "3" * 64,
            "boot_header": {
                "boot image header version": "2",
                "command line args": "console=tty0",
                "kernel_size": "6",
                "ramdisk size": "100",
                "dtb size": "3",
            },
            "ramdisk_trailer_metadata": (
                300607,
                0o755,
                0,
                0,
                1,
                0,
                0,
                0,
                0,
                0,
                0,
                11,
                0,
            ),
            "ramdisk_padding_size": 236,
            "ramdisk_entries": {
                "init": entry(b"init"),
                "default.prop": {
                    "metadata": (
                        2,
                        stat.S_IFLNK | 0o777,
                        0,
                        0,
                        1,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                    ),
                    "data": b"prop.default",
                },
                "prop.default": entry(
                    b"ro.build.tags=test-keys\n"
                    b"ro.build.display.id=BUILD test-keys\n"
                    b"ro.build.description=fleur userdebug test-keys\n"
                ),
                "first_stage_ramdisk/system/etc/ramdisk/build.prop": entry(
                    b"ro.bootimage.build.tags=test-keys\n"
                ),
                "system/etc/ramdisk/build.prop": entry(
                    b"ro.bootimage.build.tags=test-keys\n"
                ),
                "system/etc/security/otacerts.zip": entry(
                    unsigned_otacerts.getvalue()
                ),
            },
        }
        unsigned["ramdisk_record_order"] = tuple(unsigned["ramdisk_entries"])
        signed = copy.deepcopy(unsigned)
        signed["raw_sha256"] = "d" * 64
        signed["content_sha256"] = "f" * 64
        signed["boot_header"]["ramdisk size"] = "104"
        signed["ramdisk_padding_size"] = 160
        signed["ramdisk_entries"]["prop.default"]["data"] = (
            b"ro.build.tags=release-keys\n"
            b"ro.build.display.id=BUILD\n"
            b"ro.build.description=fleur userdebug release-keys\n\n"
        )
        for name in (
            "first_stage_ramdisk/system/etc/ramdisk/build.prop",
            "system/etc/ramdisk/build.prop",
        ):
            signed["ramdisk_entries"][name]["data"] = (
                b"ro.bootimage.build.tags=release-keys\n\n"
            )
        signed["ramdisk_entries"]["system/etc/security/otacerts.zip"][
            "data"
        ] = signed_otacerts.getvalue()
        record = {
            "project": "kernel/xiaomi/mt6781",
            "file": "drivers/example.h",
            "base_commit": "9" * 40,
            "patch_sha256": "a" * 64,
            "rejected_pre_fix_boot_sha256": PRE_FIX_BOOT_SHA256,
            "rejected_pre_fix_boot_content_sha256": "1" * 64,
            "hardware_tested_fixed_boot_sha256": "b" * 64,
            "cfi_remains_enabled": True,
        }
        with self.assertRaisesRegex(module.VerificationError, "pre-fix"):
            module.verify_kernel_boot_provenance(
                {**unsigned, "raw_sha256": PRE_FIX_BOOT_SHA256},
                signed,
                record,
                release_certificate,
            )
        result = module.verify_kernel_boot_provenance(
            unsigned,
            signed,
            record,
            release_certificate,
        )
        self.assertEqual("kernel/xiaomi/mt6781", result["project"])
        self.assertEqual("2" * 64, result["kernel_sha256"])
        self.assertEqual("f" * 64, result["boot_content_sha256"])
        self.assertEqual("b" * 64, result["hardware_tested_reference_sha256"])

        mutations = {
            "kernel": ("kernel_sha256", "4" * 64),
            "dtb": ("dtb_sha256", "5" * 64),
        }
        for label, (field, value) in mutations.items():
            changed = copy.deepcopy(signed)
            changed[field] = value
            with self.subTest(label=label), self.assertRaisesRegex(
                module.VerificationError, label
            ):
                module.verify_kernel_boot_provenance(
                    unsigned, changed, record, release_certificate
                )
        changed = copy.deepcopy(signed)
        changed["boot_header"]["command line args"] = "console=evil"
        with self.assertRaisesRegex(module.VerificationError, "header"):
            module.verify_kernel_boot_provenance(
                unsigned, changed, record, release_certificate
            )
        changed = copy.deepcopy(signed)
        changed["ramdisk_entries"]["unexpected"] = entry(b"injected")
        with self.assertRaisesRegex(module.VerificationError, "ramdisk"):
            module.verify_kernel_boot_provenance(
                unsigned, changed, record, release_certificate
            )
        changed = copy.deepcopy(signed)
        changed["ramdisk_entries"]["init"]["data"] = b"mutated-init"
        with self.assertRaisesRegex(module.VerificationError, "ramdisk"):
            module.verify_kernel_boot_provenance(
                unsigned, changed, record, release_certificate
            )
        changed = copy.deepcopy(signed)
        changed["ramdisk_entries"]["init"]["metadata"] = (
            1,
            stat.S_IFREG | 0o700,
            0,
            0,
            1,
            0,
            0,
            0,
            0,
            0,
            0,
        )
        with self.assertRaisesRegex(module.VerificationError, "metadata"):
            module.verify_kernel_boot_provenance(
                unsigned, changed, record, release_certificate
            )
        changed = copy.deepcopy(signed)
        changed["ramdisk_trailer_metadata"] = (
            300608,
            0o755,
            0,
            0,
            1,
            0,
            0,
            0,
            0,
            0,
            0,
            11,
            0,
        )
        with self.assertRaisesRegex(module.VerificationError, "trailer"):
            module.verify_kernel_boot_provenance(
                unsigned, changed, record, release_certificate
            )
        changed = copy.deepcopy(signed)
        reordered_names = tuple(reversed(changed["ramdisk_record_order"]))
        changed["ramdisk_entries"] = {
            name: changed["ramdisk_entries"][name] for name in reordered_names
        }
        changed["ramdisk_record_order"] = reordered_names
        with self.assertRaisesRegex(module.VerificationError, "order"):
            module.verify_kernel_boot_provenance(
                unsigned, changed, record, release_certificate
            )
        changed = copy.deepcopy(signed)
        changed["ramdisk_padding_size"] = 300
        with self.assertRaisesRegex(module.VerificationError, "padding"):
            module.verify_kernel_boot_provenance(
                unsigned, changed, record, release_certificate
            )
        changed = copy.deepcopy(signed)
        changed["ramdisk_entries"]["prop.default"]["data"] += b"evil=1\n"
        with self.assertRaisesRegex(module.VerificationError, "property"):
            module.verify_kernel_boot_provenance(
                unsigned, changed, record, release_certificate
            )
        wrong_otacerts = io.BytesIO()
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            with zipfile.ZipFile(wrong_otacerts, "w") as archive:
                archive.writestr("releasekey.x509.pem", b"wrong")
                archive.writestr("releasekey.x509.pem", b"wrong")
        changed = copy.deepcopy(signed)
        changed["ramdisk_entries"]["system/etc/security/otacerts.zip"][
            "data"
        ] = wrong_otacerts.getvalue()
        with self.assertRaisesRegex(module.VerificationError, "OTA certificate"):
            module.verify_kernel_boot_provenance(
                unsigned, changed, record, release_certificate
            )
        invalid_record = dict(record, patch_sha256="invalid")
        with self.assertRaisesRegex(module.VerificationError, "patch"):
            module.verify_kernel_boot_provenance(
                unsigned,
                signed,
                invalid_record,
                release_certificate,
            )

    def test_target_files_otacerts_require_exact_safe_unique_release_certificate(self):
        module = load_verifier()
        release_certificate = b"release-certificate"

        def nested(*entries):
            payload = io.BytesIO()
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", UserWarning)
                with zipfile.ZipFile(payload, "w") as archive:
                    for name, value in entries:
                        archive.writestr(name, value)
            return payload.getvalue()

        members = {
            "BOOT/RAMDISK/system/etc/security/otacerts.zip": nested(
                ("releasekey.x509.pem", release_certificate)
            ),
            "SYSTEM/etc/security/otacerts.zip": nested(
                ("releasekey.x509.pem", release_certificate)
            ),
        }
        with tempfile.TemporaryDirectory() as directory:
            target_files = Path(directory) / "signed.zip"
            write_zip_entries(target_files, members)
            evidence = module.verify_target_files_otacerts(
                target_files, release_certificate
            )
            self.assertEqual(set(members), set(evidence))

            attacks = {
                "duplicate": nested(
                    ("releasekey.x509.pem", release_certificate),
                    ("releasekey.x509.pem", release_certificate),
                ),
                "proc path": nested(
                    ("proc/1/fd/7/releasekey.x509.pem", release_certificate)
                ),
                "traversal": nested(
                    ("../releasekey.x509.pem", release_certificate)
                ),
                "absolute": nested(
                    ("/releasekey.x509.pem", release_certificate)
                ),
                "wrong certificate": nested(("releasekey.x509.pem", b"wrong")),
            }
            for label, payload in attacks.items():
                changed = dict(members)
                changed["SYSTEM/etc/security/otacerts.zip"] = payload
                write_zip_entries(target_files, changed)
                with self.subTest(label=label), self.assertRaises(
                    module.VerificationError
                ):
                    module.verify_target_files_otacerts(
                        target_files, release_certificate
                    )

            with zipfile.ZipFile(target_files, "w") as archive:
                archive.writestr(
                    "BOOT/RAMDISK/system/etc/security/otacerts.zip",
                    members["BOOT/RAMDISK/system/etc/security/otacerts.zip"],
                )
                write_zip_symlink(
                    archive,
                    "SYSTEM/etc/security/otacerts.zip",
                    members["SYSTEM/etc/security/otacerts.zip"],
                )
            with self.assertRaises(module.VerificationError):
                module.verify_target_files_otacerts(
                    target_files, release_certificate
                )

    def test_target_files_relationship_requires_same_partitions_and_firmware(self):
        module = load_verifier()
        unsigned = {
            "IMAGES/boot.img": b"unsigned-boot",
            "IMAGES/system.img": b"unsigned-system",
            "RADIO/md1img.img": b"firmware",
        }
        signed = {
            "IMAGES/boot.img": b"signed-boot",
            "IMAGES/system.img": b"signed-system",
            "RADIO/md1img.img": b"firmware",
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            unsigned_zip = root / "unsigned.zip"
            signed_zip = root / "signed.zip"
            for path, members in ((unsigned_zip, unsigned), (signed_zip, signed)):
                with zipfile.ZipFile(path, "w") as archive:
                    for name, value in members.items():
                        archive.writestr(name, value)
            result = module.compare_target_files(unsigned_zip, signed_zip, {"md1img": hashlib.sha256(b"firmware").hexdigest()})
            self.assertEqual(["boot", "system"], result["android_partitions"])
            self.assertEqual(["md1img"], result["firmware_partitions"])
            with warnings.catch_warnings(), zipfile.ZipFile(signed_zip, "a") as archive:
                warnings.simplefilter("ignore", UserWarning)
                archive.writestr("RADIO/md1img.img", b"changed")
            with self.assertRaisesRegex(module.VerificationError, "duplicate|firmware"):
                module.compare_target_files(unsigned_zip, signed_zip, {"md1img": hashlib.sha256(b"firmware").hexdigest()})

    def test_report_is_sanitized_and_written_atomically(self):
        module = load_verifier()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report = root / "verification-report.json"
            payload = {
                "schema_version": 1,
                "artifacts": {"ota": {"name": "signed.zip", "sha256": "a" * 64, "size": 10}},
                "findings": [{"name": "zip-integrity", "status": "pass"}],
            }
            module.write_sanitized_report(report, payload)
            self.assertEqual(payload, json.loads(report.read_text(encoding="utf-8")))
            self.assertFalse((root / ".verification-report.json.tmp").exists())
            with self.assertRaisesRegex(module.VerificationError, "sanitized"):
                module.write_sanitized_report(report, {"path": "/home/private/key.pem"})

    def test_payload_properties_require_complete_hash_and_size_metadata(self):
        module = load_verifier()
        payload = self._payload()
        metadata_size = 24 + len(b"manifest")
        file_hash = base64.b64encode(hashlib.sha256(payload).digest()).decode("ascii")
        metadata_hash = base64.b64encode(
            hashlib.sha256(payload[:metadata_size]).digest()
        ).decode("ascii")
        complete = (
            "FILE_HASH=" + file_hash + "\n"
            f"FILE_SIZE={len(payload)}\n"
            "METADATA_HASH=" + metadata_hash + "\n"
            f"METADATA_SIZE={metadata_size}\n"
        )
        self.assertEqual(len(payload), module.verify_payload_properties(complete, payload)["FILE_SIZE"])
        with self.assertRaisesRegex(module.VerificationError, "METADATA_SIZE"):
            module.verify_payload_properties(complete.replace(f"METADATA_SIZE={metadata_size}\n", ""))
        with self.assertRaisesRegex(module.VerificationError, "FILE_HASH"):
            module.verify_payload_properties(complete, b"different")
        with self.assertRaisesRegex(module.VerificationError, "METADATA_HASH"):
            module.verify_payload_properties(
                complete.replace(metadata_hash, base64.b64encode(b"x" * 32).decode()),
                payload,
            )
        changed_signature = payload[:metadata_size] + b"NEW" + payload[metadata_size + 3:]
        changed_complete = complete.replace(
            file_hash,
            base64.b64encode(hashlib.sha256(changed_signature).digest()).decode("ascii"),
        )
        self.assertEqual(
            metadata_hash,
            module.verify_payload_properties(changed_complete, changed_signature)["METADATA_HASH"],
        )
        with self.assertRaisesRegex(module.VerificationError, "METADATA_SIZE"):
            module.verify_payload_properties(
                complete.replace(f"METADATA_SIZE={metadata_size}", "METADATA_SIZE=24"),
                payload,
            )

    def test_rejects_normalized_pre_fix_boot_even_after_resigning(self):
        module = load_verifier()
        rejected_content = "6" * 64
        record = {
            "project": "kernel/xiaomi/mt6781",
            "file": "drivers/example.h",
            "base_commit": "9" * 40,
            "patch_sha256": "a" * 64,
            "rejected_pre_fix_boot_sha256": PRE_FIX_BOOT_SHA256,
            "rejected_pre_fix_boot_content_sha256": rejected_content,
            "hardware_tested_fixed_boot_sha256": "b" * 64,
            "cfi_remains_enabled": True,
        }
        with self.assertRaisesRegex(module.VerificationError, "normalized pre-fix"):
            module.verify_kernel_boot_provenance(
                {"raw_sha256": "e" * 64, "content_sha256": rejected_content},
                {"raw_sha256": "d" * 64, "content_sha256": rejected_content},
                record,
                b"release-certificate",
            )

    def test_kernel_source_provenance_binds_patch_and_application_script(self):
        module = load_verifier()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            patch = root / "fix.patch"
            script = root / "apply_patches.sh"
            patch.write_bytes(b"patch")
            script.write_text(
                '"kernel/xiaomi/mt6781|patches/android_kernel_xiaomi_mt6781/0001-mdpm-cfi-function-pointer-signature.patch"\n',
                encoding="utf-8",
            )
            record = {
                "patch_sha256": hashlib.sha256(b"patch").hexdigest(),
                "application_script": "scripts/ubuntu/apply_patches.sh",
                "application_script_sha256": hashlib.sha256(script.read_bytes()).hexdigest(),
            }
            module.verify_kernel_source_provenance(record, patch, script)
            script.write_text("# removed\n", encoding="utf-8")
            with self.assertRaisesRegex(module.VerificationError, "application"):
                module.verify_kernel_source_provenance(record, patch, script)

    def test_rejects_nested_and_windows_test_key_paths_and_mismatched_pairs(self):
        module = load_verifier()
        for value in (
            "/tmp/a/build/make/target/product/security/testkey.x509.pem",
            r"C:\android\build\make\target\product\security\platform.pk8",
            "release/keys/testkey.pk8",
            "release//keys/../testkey.pk8",
            "x/./build//make/target/product/security/testkey.pem",
        ):
            with self.assertRaisesRegex(module.VerificationError, "test certificate"):
                module._reject_test_key_path(value)
        avb_metadata = "".join(
            f"avb_{partition}_key_path=release/avb_{partition}.pem\n"
            f"avb_{partition}_algorithm=SHA256_RSA4096\n"
            for partition in module.REQUIRED_AVB_PARTITIONS
        )
        with self.assertRaisesRegex(module.VerificationError, "mismatched"):
            module.verify_signing_metadata_paths(
                'name="Settings.apk" certificate="release/platform.x509.pem" private_key="release/other.pk8"\n',
                'name="com.android.art.apex" public_key="release/art.avbpubkey" private_key="release/art.pem" container_certificate="release/platform.x509.pem" container_private_key="release/platform.pk8" partition="system"\n',
                "default_system_dev_certificate=release/releasekey\n" + avb_metadata,
            )

    def test_presigned_inventory_must_equal_approved_allowlist(self):
        module = load_verifier()
        module.verify_presigned_allowlist(
            ["WebView.apk"], ["com.android.tzdata.apex"],
            {"apk": ["WebView.apk"], "apex": ["com.android.tzdata.apex"]},
        )
        with self.assertRaisesRegex(module.VerificationError, "PRESIGNED"):
            module.verify_presigned_allowlist(
                ["Injected.apk"], [], {"apk": [], "apex": []}
            )

    def test_update_verifier_checkout_is_pinned_and_success_is_required(self):
        module = load_verifier()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repository = root / "update_verifier"
            repository.mkdir()
            script = repository / "update_verifier.py"
            script.write_text("# fixture\n", encoding="utf-8")
            public_key = root / "ota.public.pem"
            public_key.write_text("public\n", encoding="utf-8")
            ota = root / "ota.zip"
            ota.write_bytes(b"zip")
            commands = []

            def runner(command, **_kwargs):
                commands.append(tuple(str(item) for item in command))
                if command[:2] == ["git", "rev-parse"]:
                    return module.PINNED_UPDATE_VERIFIER_COMMIT + "\n"
                if command[:2] == ["git", "status"]:
                    return ""
                if command[:2] == ["git", "archive"]:
                    output = Path(
                        next(str(item).split("=", 1)[1] for item in command if str(item).startswith("--output="))
                    )
                    with tarfile.open(output, "w") as archive:
                        fixture = root / "fixture-update_verifier.py"
                        fixture.write_text("# fixture\n", encoding="utf-8")
                        archive.add(fixture, arcname="update_verifier.py")
                    return ""
                return "verified successfully\n"

            evidence = module.verify_ota_whole_file_signature(
                repository, ota, public_key, runner=runner
            )
            self.assertEqual(module.PINNED_UPDATE_VERIFIER_COMMIT, evidence["revision"])
            self.assertIn(("git", "rev-parse", "refs/heads/main"), commands)
            execute = next(command for command in commands if "-I" in command)
            self.assertIn("update_verifier.py", {Path(item).name for item in execute})
            self.assertEqual(ota, Path(execute[-1]))

            def wrong_revision(command, **_kwargs):
                if command[:3] == ["git", "rev-parse", "HEAD"]:
                    return "0" * 40 + "\n"
                self.fail("unpinned verifier must not execute")

            with self.assertRaisesRegex(module.VerificationError, "pinned"):
                module.verify_ota_whole_file_signature(
                    repository, ota, public_key, runner=wrong_revision
                )

            def wrong_main(command, **_kwargs):
                if command[:3] == ["git", "rev-parse", "HEAD"]:
                    return module.PINNED_UPDATE_VERIFIER_COMMIT + "\n"
                if command[:3] == ["git", "rev-parse", "refs/heads/main"]:
                    return "0" * 40 + "\n"
                self.fail("verifier must not execute when main is unpinned")

            with self.assertRaisesRegex(module.VerificationError, "main"):
                module.verify_ota_whole_file_signature(
                    repository, ota, public_key, runner=wrong_main
                )

    def test_update_verifier_rejects_untracked_and_executes_clean_export(self):
        module = load_verifier()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repository = root / "verifier"
            repository.mkdir()
            (repository / "helper.py").write_text(
                "MESSAGE = 'verified successfully'\n", encoding="utf-8"
            )
            (repository / "update_verifier.py").write_text(
                "from helper import MESSAGE\nprint(MESSAGE)\n", encoding="utf-8"
            )
            for command in (
                ["git", "init", "-q", "-b", "main"],
                ["git", "config", "user.email", "test@example.invalid"],
                ["git", "config", "user.name", "Test"],
                ["git", "add", "update_verifier.py", "helper.py"],
                ["git", "commit", "-qm", "fixture"],
            ):
                module._default_runner(command, cwd=repository)
            revision = module._default_runner(
                ["git", "rev-parse", "HEAD"], cwd=repository
            ).strip()
            original = module.PINNED_UPDATE_VERIFIER_COMMIT
            module.PINNED_UPDATE_VERIFIER_COMMIT = revision
            try:
                ota = root / "ota.zip"
                public_key = root / "key.pem"
                ota.write_bytes(b"ota")
                public_key.write_bytes(b"key")
                evidence = module.verify_ota_whole_file_signature(
                    repository, ota, public_key
                )
                self.assertEqual("isolated-clean-export", evidence["execution"])
                (repository / "untracked.py").write_text(
                    "raise SystemExit(9)\n", encoding="utf-8"
                )
                with self.assertRaisesRegex(module.VerificationError, "clean"):
                    module.verify_ota_whole_file_signature(
                        repository, ota, public_key
                    )
            finally:
                module.PINNED_UPDATE_VERIFIER_COMMIT = original

    def test_signer_report_binds_exact_input_outputs_metadata_and_key_plan(self):
        module = load_verifier()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            paths = {}
            for label, content in (
                ("unsigned_target_files", b"unsigned"),
                ("signed_target_files", b"signed"),
                ("ota", b"ota"),
                ("fastboot", b"fastboot"),
            ):
                paths[label] = root / f"{label}.zip"
                paths[label].write_bytes(content)
            metadata = {"META/apkcerts.txt": "a" * 64}
            key_plan = {
                "android_mappings": [
                    {"source_stem": "source", "destination_role": "releasekey"}
                ]
            }
            allowlist = {"apk": [], "apex": []}
            public_fingerprints = {"releasekey.x509.pem": "f" * 64}
            build_provenance = {
                "filename": "build-provenance.json", "sha256": "b" * 64,
                "size": 123, "session_nonce": "c" * 64,
                "application_evidence_sha256": "d" * 64,
                "unsigned_target_files": {"sha256": "e" * 64},
            }
            selinux_mac_permissions = {
                "members": {"SYSTEM/etc/selinux/plat_mac_permissions.xml": {}},
                "roles": {"platform": {"occurrences": 1}},
            }
            report = {
                "schema_version": 2,
                "device": "fleur",
                "input": module._path_evidence(paths["unsigned_target_files"]),
                "outputs": {
                    paths[label].name: {
                        "sha256": module._path_evidence(paths[label])["sha256"],
                        "size": module._path_evidence(paths[label])["size"],
                    }
                    for label in ("signed_target_files", "ota", "fastboot")
                },
                "input_metadata_sha256": metadata,
                "key_plan": key_plan,
                "presigned_allowlist": allowlist,
                "public_fingerprints": public_fingerprints,
                "build_provenance": json.loads(json.dumps(build_provenance)),
                "selinux_mac_permissions": json.loads(
                    json.dumps(selinux_mac_permissions)
                ),
            }
            evidence = module.verify_signer_report(
                report, paths, metadata, key_plan, allowlist, public_fingerprints,
                build_provenance,
                selinux_mac_permissions,
            )
            self.assertEqual(
                module._path_evidence(paths["ota"])["sha256"],
                evidence["report_bound_outputs"]["ota"],
            )
            report["outputs"][paths["ota"].name]["sha256"] = "0" * 64
            with self.assertRaisesRegex(module.VerificationError, "signer report"):
                module.verify_signer_report(
                    report, paths, metadata, key_plan, allowlist, public_fingerprints,
                    build_provenance,
                    selinux_mac_permissions,
                )
            report["outputs"][paths["ota"].name]["sha256"] = module._path_evidence(paths["ota"])["sha256"]
            report["build_provenance"]["session_nonce"] = "0" * 64
            with self.assertRaisesRegex(module.VerificationError, "build provenance"):
                module.verify_signer_report(
                    report, paths, metadata, key_plan, allowlist, public_fingerprints,
                    build_provenance,
                    selinux_mac_permissions,
                )
            report["build_provenance"] = json.loads(json.dumps(build_provenance))
            report["selinux_mac_permissions"]["roles"]["platform"][
                "occurrences"
            ] = 2
            with self.assertRaisesRegex(module.VerificationError, "SELinux"):
                module.verify_signer_report(
                    report,
                    paths,
                    metadata,
                    key_plan,
                    allowlist,
                    public_fingerprints,
                    build_provenance,
                    selinux_mac_permissions,
                )

    def test_signed_key_metadata_is_preserved_raw_and_logically(self):
        module = load_verifier()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            unsigned = root / "unsigned.zip"
            signed = root / "signed.zip"
            common = {
                "META/apexkeys.txt": "",
                "META/misc_info.txt": "ab_update=true\nvirtual_ab=true\n",
                "META/otakeys.txt": "\n",
                "SYSTEM/build.prop": (
                    "ro.product.system.device=fleur\n"
                    "ro.build.tags=test-keys\nro.system.build.tags=test-keys\n"
                ),
            }
            apkcerts = (
                'name="ANGLE.apk" certificate="build/make/target/product/security/testkey.x509.pem" private_key="build/make/target/product/security/testkey.pk8"\n'
                'name="Aperture.apk" certificate="build/make/target/product/security/testkey.x509.pem" private_key="build/make/target/product/security/testkey.pk8"\n'
            )
            apexkeys = (
                'name="com.android.art.apex" public_key="build/make/target/product/security/com.android.art.avbpubkey" '
                'private_key="build/make/target/product/security/com.android.art.pem" '
                'container_certificate="build/make/target/product/security/platform.x509.pem" '
                'container_private_key="build/make/target/product/security/platform.pk8" partition="system"\n'
            )
            common["META/apexkeys.txt"] = apexkeys
            for path in (unsigned, signed):
                with zipfile.ZipFile(path, "w") as archive:
                    for name, value in common.items():
                        archive.writestr(name, value)
                    archive.writestr("META/apkcerts.txt", apkcerts)
            inventory = module.load_signing_inventory(unsigned)
            plan = module.build_key_plan(inventory)
            module.verify_signed_key_plan(unsigned, signed, inventory, plan)

            with zipfile.ZipFile(signed, "w") as archive:
                for name, value in common.items():
                    archive.writestr(name, value)
                archive.writestr(
                    "META/apkcerts.txt",
                    apkcerts.replace("Aperture.apk", "Changed.apk"),
                )
            with self.assertRaisesRegex(module.VerificationError, "preserved"):
                module.verify_signed_key_plan(unsigned, signed, inventory, plan)

            with zipfile.ZipFile(signed, "w") as archive:
                for name, value in common.items():
                    archive.writestr(
                        name,
                        value.replace("com.android.art", "com.android.runtime")
                        if name == "META/apexkeys.txt"
                        else value,
                    )
                archive.writestr("META/apkcerts.txt", apkcerts)
            with self.assertRaisesRegex(module.VerificationError, "preserved"):
                module.verify_signed_key_plan(unsigned, signed, inventory, plan)

            for mappings in (
                (
                    SimpleNamespace(source_stem="source/platform", destination_role="platform"),
                    SimpleNamespace(source_stem="source/./platform", destination_role="media"),
                ),
                (
                    SimpleNamespace(source_stem="source/platform", destination_role="roles/platform"),
                    SimpleNamespace(source_stem="source/media", destination_role="roles//platform"),
                ),
            ):
                collision_plan = SimpleNamespace(
                    android_mappings=mappings, apex_names=(), avb_roles=(),
                )
                with self.assertRaisesRegex(module.VerificationError, "canonical.*collision"):
                    module.verify_signed_key_plan(
                        unsigned, unsigned, inventory, collision_plan
                    )

    def test_fastboot_images_and_android_info_must_match_signed_target_files(self):
        module = load_verifier()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            unsigned = root / "unsigned.zip"
            target = root / "signed.zip"
            fastboot = root / "fastboot.zip"
            target_entries, fastboot_entries = fleur_fastboot_entries()
            write_zip_entries(unsigned, target_entries)
            write_zip_entries(target, target_entries)
            write_zip_entries(fastboot, fastboot_entries)
            evidence = module.verify_fastboot_against_target_files(
                unsigned, target, fastboot
            )
            expected_images = sorted(
                f"{partition}.img"
                for partition in FLEUR_IMAGE_PARTITIONS + FLEUR_RADIO_PARTITIONS
            )
            self.assertEqual(expected_images, evidence["images"])
            self.assertEqual(
                "RADIO/audio_dsp.img",
                evidence["source_members"]["audio_dsp.img"],
            )
            self.assertEqual(
                "IMAGES/boot.img", evidence["source_members"]["boot.img"]
            )
            self.assertEqual(
                hashlib.sha256(FLEUR_FASTBOOT_INFO.encode()).hexdigest(),
                evidence["fastboot_info_sha256"],
            )
            self.assertRegex(
                evidence["producer_controls_sha256"], r"^[0-9a-f]{64}$"
            )
            target_entries["OTA/android-info.txt"] = b"require product=fleur\n"
            fastboot_entries["android-info.txt"] = b"require product=fleur\n"
            write_zip_entries(unsigned, target_entries)
            write_zip_entries(target, target_entries)
            write_zip_entries(fastboot, fastboot_entries)
            module.verify_fastboot_against_target_files(unsigned, target, fastboot)
            target_entries["PREBUILT_IMAGES/tee.img"] = target_entries.pop(
                "RADIO/tee.img"
            )
            write_zip_entries(unsigned, target_entries)
            write_zip_entries(target, target_entries)
            prebuilt = module.verify_fastboot_against_target_files(
                unsigned, target, fastboot
            )
            self.assertEqual(
                "PREBUILT_IMAGES/tee.img", prebuilt["source_members"]["tee.img"]
            )

    def test_fastboot_rejects_wrong_product_and_unexpected_or_destructive_members(self):
        module = load_verifier()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            unsigned = root / "unsigned.zip"
            target, fastboot = root / "signed.zip", root / "fastboot.zip"
            base_target, base_fastboot = fleur_fastboot_entries()
            write_zip_entries(unsigned, base_target)
            write_zip_entries(target, base_target)
            write_zip_entries(fastboot, base_fastboot)
            module.verify_fastboot_against_target_files(unsigned, target, fastboot)

            def reject(
                label: str,
                *,
                target_changes: dict[str, bytes | None] | None = None,
                fastboot_changes: dict[str, bytes | None] | None = None,
                fastboot_symlink: str | None = None,
            ) -> None:
                target_entries = dict(base_target)
                output_entries = dict(base_fastboot)
                for entries, changes in (
                    (target_entries, target_changes or {}),
                    (output_entries, fastboot_changes or {}),
                ):
                    for name, value in changes.items():
                        if value is None:
                            entries.pop(name, None)
                        else:
                            entries[name] = value
                write_zip_entries(target, target_entries)
                if fastboot_symlink is None:
                    write_zip_entries(fastboot, output_entries)
                else:
                    with zipfile.ZipFile(fastboot, "w") as archive:
                        for name, value in output_entries.items():
                            if name != fastboot_symlink:
                                archive.writestr(name, value)
                        write_zip_symlink(archive, fastboot_symlink, b"boot.img")
                with self.subTest(label=label), self.assertRaises(
                    module.VerificationError
                ):
                    module.verify_fastboot_against_target_files(
                        unsigned, target, fastboot
                    )

            reject("omitted", fastboot_changes={"logo.img": None})
            reject("extra", fastboot_changes={"surprise.img": b"bad"})
            reject("symlink", fastboot_symlink="boot.img")
            write_zip_entries(target, base_target)
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", UserWarning)
                with zipfile.ZipFile(fastboot, "w") as archive:
                    for name, value in base_fastboot.items():
                        archive.writestr(name, value)
                    archive.writestr("boot.img", b"duplicate")
            with self.assertRaisesRegex(module.VerificationError, "duplicate"):
                module.verify_fastboot_against_target_files(unsigned, target, fastboot)
            target_without_boot = dict(base_target)
            target_without_boot.pop("IMAGES/boot.img")
            with zipfile.ZipFile(target, "w") as archive:
                for name, value in target_without_boot.items():
                    archive.writestr(name, value)
                write_zip_symlink(archive, "IMAGES/boot.img", b"dtbo.img")
            write_zip_entries(fastboot, base_fastboot)
            with self.assertRaisesRegex(module.VerificationError, "not regular"):
                module.verify_fastboot_against_target_files(unsigned, target, fastboot)
            target_without_ab = dict(base_target)
            ab_payload = target_without_ab.pop("META/ab_partitions.txt")
            with zipfile.ZipFile(target, "w") as archive:
                for name, value in target_without_ab.items():
                    archive.writestr(name, value)
                write_zip_symlink(archive, "META/ab_partitions.txt", ab_payload)
            write_zip_entries(fastboot, base_fastboot)
            with self.assertRaisesRegex(module.VerificationError, "not regular"):
                module.verify_fastboot_against_target_files(unsigned, target, fastboot)
            reject(
                "basename collision",
                target_changes={"IMAGES/nested/boot.img": b"collision"},
            )
            reject(
                "update-super missing source",
                target_changes={"IMAGES/super_empty.img": None},
                fastboot_changes={"super_empty.img": None},
            )
            for info in (
                b"board=wrong\n",
                b"board=fleur\nrequire product=fleur\n",
                b"require product=fleur|wrong\n",
                b"product=fleur\n",
                b"board=fleur\nboard=fleur\n",
            ):
                reject(
                    f"android-info {info!r}",
                    target_changes={"OTA/android-info.txt": info},
                    fastboot_changes={"android-info.txt": info},
                )
            reject(
                "android-info byte mismatch",
                fastboot_changes={"android-info.txt": b"require product=fleur\n"},
            )
            hostile_fastboot_info = {
                "wrong version": FLEUR_FASTBOOT_INFO.replace("version 1", "version 2"),
                "unconditional erase": FLEUR_FASTBOOT_INFO.replace(
                    "if-wipe erase userdata", "erase userdata"
                ),
                "other conditional erase": FLEUR_FASTBOOT_INFO.replace(
                    "if-wipe erase userdata", "if-wipe erase cache"
                ),
                "slot flag": FLEUR_FASTBOOT_INFO.replace(
                    "flash boot", "flash --slot-other boot"
                ),
                "wrong apply-vbmeta": FLEUR_FASTBOOT_INFO.replace(
                    "flash boot", "flash --apply-vbmeta boot"
                ),
                "missing image": FLEUR_FASTBOOT_INFO.replace(
                    "flash boot", "flash missing"
                ),
                "alternate filename": FLEUR_FASTBOOT_INFO.replace(
                    "flash boot", "flash boot other.img"
                ),
                "wrong reboot": FLEUR_FASTBOOT_INFO.replace(
                    "reboot fastboot", "reboot bootloader"
                ),
                "update-super argument": FLEUR_FASTBOOT_INFO.replace(
                    "update-super", "update-super super_empty"
                ),
                "duplicate flash": FLEUR_FASTBOOT_INFO.replace(
                    "flash boot\n", "flash boot\nflash boot\n"
                ),
                "missing flash": FLEUR_FASTBOOT_INFO.replace("flash boot\n", ""),
            }
            for label, hostile_text in hostile_fastboot_info.items():
                hostile = hostile_text.encode()
                reject(
                    f"hostile command {label}",
                    target_changes={"META/fastboot-info.txt": hostile},
                    fastboot_changes={"fastboot-info.txt": hostile},
                )
            reject(
                "fastboot-info byte mismatch",
                fastboot_changes={"fastboot-info.txt": b"version 1\nflash boot\n"},
            )
            reject("radio mismatch", fastboot_changes={"audio_dsp.img": b"wrong"})
            reject("IMAGES mismatch", fastboot_changes={"boot.img": b"wrong"})

    def test_fastboot_rejects_signed_producer_control_drift(self):
        module = load_verifier()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            unsigned = root / "unsigned.zip"
            signed = root / "signed.zip"
            fastboot = root / "fastboot.zip"
            baseline_target, baseline_fastboot = fleur_fastboot_entries()
            write_zip_entries(unsigned, baseline_target)

            dynamic_flash = {
                "flash odm\n",
                "flash product\n",
                "flash system\n",
                "flash system_ext\n",
                "flash vendor\n",
            }
            weakened_info = "".join(
                line
                for line in FLEUR_FASTBOOT_INFO.splitlines(keepends=True)
                if line not in dynamic_flash
            ).encode()
            attacks = {
                "empty dynamic partition plan": (
                    {
                        "META/misc_info.txt": b"build_super_partition=true\n"
                        b"dynamic_partition_list=\n",
                        "META/fastboot-info.txt": weakened_info,
                    },
                    {"fastboot-info.txt": weakened_info},
                ),
                "AB partition removal": (
                    {
                        "META/ab_partitions.txt": baseline_target[
                            "META/ab_partitions.txt"
                        ].replace(b"audio_dsp\n", b""),
                    },
                    {"audio_dsp.img": None},
                ),
                "alternate valid product constraint": (
                    {"OTA/android-info.txt": b"require product=fleur\n"},
                    {"android-info.txt": b"require product=fleur\n"},
                ),
                "super build policy": (
                    {
                        "META/misc_info.txt": b"build_super_partition=false\n"
                        b"dynamic_partition_list=odm product system system_ext vendor\n"
                    },
                    {},
                ),
            }
            for property_name, value in (
                ("super_image_in_update_package", "true"),
                ("bootloader_in_update_package", "true"),
                ("super_block_devices", "other_super"),
                ("dynamic_partition_retrofit", "true"),
                ("extfs_sparse_flag", "-s"),
            ):
                attacks[f"misc property {property_name}"] = (
                    {
                        "META/misc_info.txt": baseline_target[
                            "META/misc_info.txt"
                        ]
                        + f"{property_name}={value}\n".encode()
                    },
                    {},
                )
            for label, (signed_changes, fastboot_changes) in attacks.items():
                signed_entries = dict(baseline_target)
                output_entries = dict(baseline_fastboot)
                for entries, changes in (
                    (signed_entries, signed_changes),
                    (output_entries, fastboot_changes),
                ):
                    for name, value in changes.items():
                        if value is None:
                            entries.pop(name)
                        else:
                            entries[name] = value
                write_zip_entries(signed, signed_entries)
                write_zip_entries(fastboot, output_entries)
                with self.subTest(label=label), self.assertRaisesRegex(
                    module.VerificationError, "producer control"
                ):
                    module.verify_fastboot_against_target_files(
                        unsigned, signed, fastboot
                    )

    def test_selinux_mac_permissions_require_exact_release_certificates(self):
        module = load_verifier()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            unsigned = root / "unsigned.zip"
            signed = root / "signed.zip"
            public = root / "public"
            public.mkdir()
            unsigned_entries = {
                "SYSTEM/etc/selinux/plat_mac_permissions.xml": mac_policy(
                    signed=False
                ),
                "VENDOR/etc/selinux/vendor_mac_permissions.xml": (
                    b'<?xml version="1.0" encoding="iso-8859-1"?><policy>'
                    b'<signer signature="'
                    + mac_der("platform").hex().encode()
                    + b'"><seinfo value="platform"/></signer></policy>'
                ),
                "SYSTEM_EXT/etc/selinux/system_ext_mac_permissions.xml": (
                    b'<?xml version="1.0" encoding="iso-8859-1"?>'
                    b"<policy></policy>"
                ),
                "PRODUCT/etc/selinux/product_mac_permissions.xml": (
                    b'<?xml version="1.0" encoding="iso-8859-1"?>'
                    b"<policy></policy>"
                ),
                "ODM/etc/selinux/odm_mac_permissions.xml": (
                    b'<?xml version="1.0" encoding="iso-8859-1"?>'
                    b"<policy></policy>"
                ),
            }
            signed_entries = dict(unsigned_entries)
            for name, value in tuple(signed_entries.items()):
                for role in MAC_SEINFO_ROLES.values():
                    value = value.replace(
                        mac_der(role).hex().encode(),
                        mac_der(role, release=True).hex().encode(),
                    )
                signed_entries[name] = value
            for role in MAC_SEINFO_ROLES.values():
                (public / f"{role}.x509.pem").write_bytes(mac_pem(role))
            write_zip_entries(unsigned, unsigned_entries)
            write_zip_entries(signed, signed_entries)
            evidence = module.verify_selinux_mac_permissions(
                unsigned, signed, public
            )
            self.assertEqual(2, evidence["roles"]["platform"]["occurrences"])

            attacks = {
                "old source remains": dict(unsigned_entries),
                "wrong release": {
                    **signed_entries,
                    "VENDOR/etc/selinux/vendor_mac_permissions.xml": signed_entries[
                        "VENDOR/etc/selinux/vendor_mac_permissions.xml"
                    ].replace(
                        mac_der("platform", release=True).hex().encode(),
                        mac_der("media", release=True).hex().encode(),
                    ),
                },
                "missing member": {
                    name: value
                    for name, value in signed_entries.items()
                    if not name.startswith("VENDOR/")
                },
            }
            for label, entries in attacks.items():
                write_zip_entries(signed, entries)
                with self.subTest(label=label), self.assertRaises(
                    module.VerificationError
                ):
                    module.verify_selinux_mac_permissions(unsigned, signed, public)

    def test_sku_files_require_exact_installed_paths(self):
        module = load_verifier()
        with tempfile.TemporaryDirectory() as directory:
            archive_path = Path(directory) / "target.zip"
            with zipfile.ZipFile(archive_path, "w") as archive:
                for name in EXPECTED_SKUS:
                    archive.writestr(f"WRONG/etc/{name}", b"x")
            with zipfile.ZipFile(archive_path) as archive:
                with self.assertRaisesRegex(module.VerificationError, "SKU"):
                    module._read_sku_files(archive)

    def test_boot_extraction_fails_closed_and_normalizes_avb_footer(self):
        module = load_verifier()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive_path = root / "target.zip"
            with zipfile.ZipFile(archive_path, "w") as archive:
                archive.writestr("IMAGES/boot.img", b"kernel-and-ramdisk")
            calls = []
            ramdisk = build_newc(
                {
                    "init": (stat.S_IFREG | 0o755, b"init"),
                    "default.prop": (stat.S_IFLNK | 0o777, b"prop.default"),
                }
            )

            def runner(command, **_kwargs):
                calls.append(tuple(str(item) for item in command))
                tool = Path(command[0]).name
                if tool == "unpack_bootimg":
                    output = Path(command[command.index("--out") + 1])
                    (output / "kernel").write_bytes(b"kernel")
                    (output / "ramdisk").write_bytes(b"compressed-ramdisk")
                    (output / "dtb").write_bytes(b"dtb")
                    return (
                        "boot magic: ANDROID!\n"
                        "kernel_size: 6\n"
                        "kernel load address: 0x40080000\n"
                        "ramdisk size: 18\n"
                        "ramdisk load address: 0x47c80000\n"
                        "second bootloader size: 0\n"
                        "second bootloader load address: 0x00000000\n"
                        "kernel tags load address: 0x4bc80000\n"
                        "page size: 2048\n"
                        "os version: 16.0.0\n"
                        "os patch level: 2026-08\n"
                        "boot image header version: 2\n"
                        "product name: \n"
                        "command line args: console=tty0\n"
                        "additional command line args: \n"
                        "recovery dtbo size: 0\n"
                        "recovery dtbo offset: 0x0000000000000000\n"
                        "boot header size: 1660\n"
                        "dtb size: 3\n"
                        "dtb address: 0x000000004bc80000\n"
                    )
                if tool == "lz4":
                    Path(command[-1]).write_bytes(ramdisk)
                return ""

            evidence = module.extract_boot_evidence(
                archive_path, root / "avbtool", runner=runner
            )
            digest = hashlib.sha256(b"kernel-and-ramdisk").hexdigest()
            self.assertEqual(digest, evidence["raw_sha256"])
            self.assertEqual(digest, evidence["content_sha256"])
            self.assertEqual(hashlib.sha256(b"kernel").hexdigest(), evidence["kernel_sha256"])
            self.assertEqual(hashlib.sha256(b"dtb").hexdigest(), evidence["dtb_sha256"])
            self.assertEqual(b"init", evidence["ramdisk_entries"]["init"]["data"])
            self.assertEqual(
                b"prop.default",
                evidence["ramdisk_entries"]["default.prop"]["data"],
            )
            self.assertEqual(0o755, evidence["ramdisk_trailer_metadata"][1])
            self.assertEqual(0, evidence["ramdisk_trailer_metadata"][6])
            self.assertEqual(0, len(ramdisk) % 256)
            tools = [Path(command[0]).name for command in calls]
            self.assertEqual(["avbtool", "unpack_bootimg", "lz4"], tools)
            with self.assertRaisesRegex(module.VerificationError, "unsafe"):
                module._parse_newc_ramdisk(
                    build_newc({"../escape": (stat.S_IFREG | 0o644, b"bad")})
                )
            with self.assertRaisesRegex(
                module.VerificationError, "trailer|truncated|padding"
            ):
                module._parse_newc_ramdisk(ramdisk[:-20])

            empty = root / "empty.zip"
            with zipfile.ZipFile(empty, "w"):
                pass
            with self.assertRaisesRegex(module.VerificationError, "boot"):
                module.extract_boot_evidence(empty, root / "avbtool", runner=runner)

    def test_newc_trailer_and_padding_are_canonical_and_fail_closed(self):
        module = load_verifier()
        entries = [("init", (stat.S_IFREG | 0o755, b"init"))]
        ramdisk = build_newc(entries)
        parsed = module._parse_newc_ramdisk(ramdisk)
        self.assertEqual(b"init", parsed["entries"]["init"]["data"])
        self.assertEqual(("init",), parsed["record_order"])
        self.assertEqual(0o755, parsed["trailer_metadata"][1])
        self.assertEqual(0, parsed["trailer_metadata"][6])
        self.assertEqual((-parsed["trailer_end"]) % 256, parsed["padding_size"])
        self.assertEqual(len(ramdisk), parsed["trailer_end"] + parsed["padding_size"])

        noncanonical_trailer = bytearray(ramdisk)
        trailer_offset = noncanonical_trailer.rfind(b"070701")
        noncanonical_trailer[trailer_offset + 6 : trailer_offset + 14] = b"00000001"
        crc_trailer = bytearray(ramdisk)
        crc_trailer[trailer_offset : trailer_offset + 6] = b"070702"
        name_padding = bytearray(ramdisk)
        bounds = newc_record_bounds(name_padding)
        name_padding[bounds["name_end"]] = 1
        data_padding = bytearray(
            build_newc([("x", (stat.S_IFREG | 0o755, b"x"))])
        )
        data_bounds = newc_record_bounds(data_padding)
        data_padding[data_bounds["data_end"]] = 1
        uppercase_numeric = bytearray(ramdisk)
        uppercase_numeric[12] = ord("E")
        short_numeric = bytearray(ramdisk)
        short_numeric[6:14] = b"00493e0 "
        signed_numeric = bytearray(ramdisk)
        signed_numeric[6:14] = b"+00493e0"
        invalid_archives = {
            "nonzero trailer payload": build_newc(entries, trailer_data=b"x"),
            "noncanonical trailer metadata": bytes(noncanonical_trailer),
            "noncanonical trailer magic": bytes(crc_trailer),
            "nonzero name padding": bytes(name_padding),
            "nonzero data padding": bytes(data_padding),
            "uppercase numeric field": bytes(uppercase_numeric),
            "short numeric field": bytes(short_numeric),
            "signed numeric field": bytes(signed_numeric),
            "multiple trailer": ramdisk + build_newc([]),
            "missing trailer": build_newc(entries, include_trailer=False),
            "nonzero padding": ramdisk[:-1] + b"x",
            "extra zero padding": ramdisk + b"\0",
            "duplicate member": build_newc([entries[0], entries[0]]),
        }
        for label, archive in invalid_archives.items():
            with self.subTest(label=label), self.assertRaisesRegex(
                module.VerificationError, "canonical|trailer|padding|duplicate"
            ):
                module._parse_newc_ramdisk(archive)

        aligned_archive = None
        for size in range(256):
            candidate = build_newc(
                [("edge", (stat.S_IFREG | 0o644, b"x" * size))]
            )
            trailer = candidate.rfind(b"070701")
            if newc_record_bounds(candidate, trailer)["record_end"] == len(candidate):
                aligned_archive = candidate
                break
        self.assertIsNotNone(aligned_archive)
        aligned = module._parse_newc_ramdisk(aligned_archive)
        self.assertEqual(0, aligned["padding_size"])

    def test_verifies_representative_apk_and_every_non_presigned_apex(self):
        module = load_verifier()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "signed-target.zip"
            public = root / "public-keys"
            public.mkdir()
            (public / "releasekey.x509.pem").write_text("certificate", encoding="utf-8")
            (public / "com.android.art.x509.pem").write_text(
                "apex certificate", encoding="utf-8"
            )
            (public / "com.android.art.avbpubkey").write_bytes(b"apex-public")
            (public / "com.android.art.public.pem").write_text("public pem", encoding="utf-8")
            nested = io.BytesIO()
            with zipfile.ZipFile(nested, "w") as apex:
                apex.writestr("apex_payload.img", b"payload")
            with zipfile.ZipFile(target, "w") as archive:
                archive.writestr("SYSTEM/app/Settings/Settings.apk", b"apk")
                archive.writestr("SYSTEM/apex/com.android.art.apex", nested.getvalue())
            apkcerts = (
                'name="Settings.apk" certificate="build/make/target/product/security/testkey.x509.pem" '
                'private_key="build/make/target/product/security/testkey.pk8"\n'
                'name="WebView.apk" certificate="PRESIGNED" private_key="PRESIGNED"\n'
            )
            apexkeys = (
                'name="com.android.art.apex" public_key="build/make/target/product/security/com.android.art.avbpubkey" '
                'private_key="build/make/target/product/security/com.android.art.pem" '
                'container_certificate="build/make/target/product/security/platform.x509.pem" '
                'container_private_key="build/make/target/product/security/platform.pk8" partition="system"\n'
                'name="com.android.tzdata.apex" public_key="PRESIGNED" private_key="PRESIGNED" '
                'container_certificate="PRESIGNED" container_private_key="PRESIGNED" partition="system"\n'
            )
            commands = []

            def runner(command, **_kwargs):
                command = tuple(str(item) for item in command)
                commands.append(command)
                if Path(command[0]).name == "openssl":
                    return "sha256 Fingerprint=" + ":".join(["AB"] * 32) + "\n"
                if Path(command[0]).name == "apksigner":
                    return "Signer #1 certificate SHA-256 digest: " + "ab" * 32 + "\n"
                if Path(command[0]).name == "deapexer":
                    Path(command[-1]).mkdir()
                    (Path(command[-1]) / "apex_manifest.pb").write_bytes(b"manifest")
                    return ""
                if Path(command[0]).name == "avbtool" and "info_image" in command:
                    return "Public key (sha1): " + hashlib.sha1(b"apex-public").hexdigest() + "\n"
                return "verified\n"

            evidence = module.verify_package_signatures(
                target,
                apkcerts,
                apexkeys,
                SimpleNamespace(
                    android_mappings=(
                        SimpleNamespace(
                            source_stem="build/make/target/product/security/testkey",
                            destination_role="releasekey",
                        ),
                    ),
                    apex_names=("com.android.art",),
                ),
                public,
                root / "host-tools",
                runner=runner,
            )
            self.assertEqual(["Settings.apk"], evidence["apk_representatives"])
            self.assertEqual(["WebView.apk"], evidence["presigned_apk"])
            self.assertEqual(["com.android.art.apex"], evidence["verified_apex"])
            self.assertEqual(["com.android.tzdata.apex"], evidence["presigned_apex"])
            tool_names = [Path(command[0]).name for command in commands]
            self.assertEqual(2, tool_names.count("apksigner"))
            self.assertEqual(1, tool_names.count("deapexer"))
            self.assertEqual(2, tool_names.count("avbtool"))
            deapexer_command = commands[tool_names.index("deapexer")]
            self.assertIn("--debugfs_path", deapexer_command)
            self.assertIn("--fsckerofs_path", deapexer_command)
            self.assertIn("extract", deapexer_command)
            verify_command = next(command for command in commands if "verify_image" in command)
            self.assertEqual("com.android.art.public.pem", Path(verify_command[verify_command.index("--key") + 1]).name)

            with self.assertRaisesRegex(module.VerificationError, "destination key plan"):
                module.verify_package_signatures(
                    target,
                    apkcerts,
                    apexkeys,
                    SimpleNamespace(
                        android_mappings=(
                            SimpleNamespace(
                                source_stem="build/make/target/product/security/testkey",
                                destination_role="releasekey",
                            ),
                        ),
                        apex_names=(),
                    ),
                    public,
                    root / "host-tools",
                    runner=runner,
                )

    def test_apk_representative_uses_present_aperture_and_destination_role(self):
        module = load_verifier()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "signed-target.zip"
            public = root / "public-keys"
            public.mkdir()
            (public / "releasekey.x509.pem").write_text(
                "certificate", encoding="utf-8"
            )
            with zipfile.ZipFile(target, "w") as archive:
                archive.writestr("SYSTEM/app/Aperture/Aperture.apk", b"signed-apk")
            apkcerts = (
                'name="ANGLE.apk" certificate="build/make/target/product/security/testkey.x509.pem" '
                'private_key="build/make/target/product/security/testkey.pk8"\n'
                'name="Aperture.apk" certificate="build/make/target/product/security/testkey.x509.pem" '
                'private_key="build/make/target/product/security/testkey.pk8"\n'
            )
            plan = SimpleNamespace(
                android_mappings=(
                    SimpleNamespace(
                        source_stem="build/make/target/product/security/testkey",
                        destination_role="releasekey",
                    ),
                ),
                apex_names=(),
            )
            commands = []

            def runner(command, **_kwargs):
                command = tuple(str(item) for item in command)
                commands.append(command)
                if Path(command[0]).name == "openssl":
                    return "sha256 Fingerprint=" + ":".join(["AB"] * 32) + "\n"
                if Path(command[0]).name == "apksigner":
                    return "Signer #1 certificate SHA-256 digest: " + "ab" * 32 + "\n"
                self.fail(command)

            evidence = module.verify_package_signatures(
                target,
                apkcerts,
                "",
                plan,
                public,
                root / "host-tools",
                runner=runner,
            )

            self.assertEqual(["Aperture.apk"], evidence["apk_representatives"])
            self.assertEqual("ab" * 32, evidence["public_fingerprints"]["apk:releasekey"])
            self.assertFalse(any("ANGLE.apk" in " ".join(command) for command in commands))

    def test_installed_apk_mapping_certificate_signature_and_basename_fail_closed(self):
        module = load_verifier()
        apkcerts = (
            'name="Aperture.apk" certificate="build/make/target/product/security/testkey.x509.pem" '
            'private_key="build/make/target/product/security/testkey.pk8"\n'
        )
        mapped = SimpleNamespace(
            android_mappings=(
                SimpleNamespace(
                    source_stem="build/make/target/product/security/testkey",
                    destination_role="releasekey",
                ),
            ),
            apex_names=(),
        )
        unmapped = SimpleNamespace(android_mappings=(), apex_names=())
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            public = root / "public-keys"
            public.mkdir()
            target = root / "signed-target.zip"
            with zipfile.ZipFile(target, "w") as archive:
                archive.writestr("SYSTEM/app/Aperture/Aperture.apk", b"apk")

            with self.assertRaisesRegex(module.VerificationError, "mapping"):
                module.verify_package_signatures(
                    target, apkcerts, "", unmapped, public, root / "host-tools"
                )
            with self.assertRaisesRegex(module.VerificationError, "certificate"):
                module.verify_package_signatures(
                    target, apkcerts, "", mapped, public, root / "host-tools"
                )

            (public / "releasekey.x509.pem").write_text(
                "certificate", encoding="utf-8"
            )

            def mismatch_runner(command, **_kwargs):
                if Path(command[0]).name == "openssl":
                    return "sha256 Fingerprint=" + ":".join(["AB"] * 32) + "\n"
                if Path(command[0]).name == "apksigner":
                    return "Signer #1 certificate SHA-256 digest: " + "cd" * 32 + "\n"
                self.fail(command)

            with self.assertRaisesRegex(module.VerificationError, "fingerprint"):
                module.verify_package_signatures(
                    target,
                    apkcerts,
                    "",
                    mapped,
                    public,
                    root / "host-tools",
                    runner=mismatch_runner,
                )

            with zipfile.ZipFile(target, "w") as archive:
                archive.writestr("SYSTEM/app/Aperture/Aperture.apk", b"one")
                archive.writestr("PRODUCT/app/Aperture/Aperture.apk", b"two")
            with self.assertRaisesRegex(module.VerificationError, "exactly one"):
                module.verify_package_signatures(
                    target, apkcerts, "", mapped, public, root / "host-tools"
                )

    def test_absent_only_apk_role_is_not_selected_or_required(self):
        module = load_verifier()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "signed-target.zip"
            public = root / "public-keys"
            public.mkdir()
            with zipfile.ZipFile(target, "w") as archive:
                archive.writestr("META/member", b"fixture")
            apkcerts = (
                'name="ANGLE.apk" certificate="build/make/target/product/security/testkey.x509.pem" '
                'private_key="build/make/target/product/security/testkey.pk8"\n'
            )

            evidence = module.verify_package_signatures(
                target,
                apkcerts,
                "",
                SimpleNamespace(android_mappings=(), apex_names=()),
                public,
                root / "host-tools",
                runner=lambda *_args, **_kwargs: self.fail("tool must not run"),
            )

            self.assertEqual([], evidence["apk_representatives"])

    def test_verifies_all_required_avb_images_against_public_bundle(self):
        module = load_verifier()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "signed-target.zip"
            public = root / "public-keys"
            public.mkdir()
            with zipfile.ZipFile(target, "w") as archive:
                for partition in module.REQUIRED_AVB_PARTITIONS:
                    archive.writestr(f"IMAGES/{partition}.img", partition.encode())
                    (public / f"avb_{partition}.avbpubkey").write_bytes(
                        f"public-{partition}".encode()
                    )
                    (public / f"avb_{partition}.public.pem").write_text(
                        f"pem-{partition}", encoding="utf-8"
                    )
            commands = []

            chain_locations = {
                "boot": 1,
                "vbmeta_system": 2,
                "vbmeta_vendor": 3,
            }

            def vbmeta_info(chains=chain_locations):
                lines = [
                    "Public key (sha1): "
                    + hashlib.sha1(
                        (public / "avb_vbmeta.avbpubkey").read_bytes()
                    ).hexdigest(),
                    "Descriptors:",
                ]
                for partition, location in chains.items():
                    lines.extend(
                        (
                            "    Chain Partition descriptor:",
                            f"      Partition Name:          {partition}",
                            f"      Rollback Index Location: {location}",
                            "      Public key (sha1):       "
                            + hashlib.sha1(
                                (public / f"avb_{partition}.avbpubkey").read_bytes()
                            ).hexdigest(),
                            "      Flags:                   0",
                        )
                    )
                return "\n".join(lines) + "\n"

            def runner(command, **_kwargs):
                commands.append(tuple(str(item) for item in command))
                if "verify_image" in command:
                    image = Path(command[command.index("--image") + 1])
                    if image.stem == "vbmeta":
                        if (
                            "--key" in command
                            and "--follow_chain_partitions" in command
                        ):
                            self.fail(
                                "root key must not be reused for followed child images"
                            )
                        self.assertTrue(
                            all(
                                (image.parent / f"{partition}.img").is_file()
                                for partition in module.REQUIRED_AVB_PARTITIONS
                            )
                        )
                if "info_image" in command:
                    image = Path(command[command.index("--image") + 1])
                    partition = image.stem
                    if partition == "vbmeta":
                        return vbmeta_info()
                    return "Public key (sha1): " + hashlib.sha1(
                        (public / f"avb_{partition}.avbpubkey").read_bytes()
                    ).hexdigest() + "\n"
                return "Footer version: 1.0\n"

            expected = {
                partition: hashlib.sha256((public / f"avb_{partition}.avbpubkey").read_bytes()).hexdigest()
                for partition in module.REQUIRED_AVB_PARTITIONS
            }
            evidence = module.verify_avb_images(
                target, public, root / "avbtool", runner=runner
            )
            self.assertEqual(expected, evidence)
            self.assertEqual(9, len(commands))
            self.assertTrue(all(Path(command[0]).name == "avbtool" for command in commands))
            root_verifies = [
                command
                for command in commands
                if "verify_image" in command
                and Path(command[command.index("--image") + 1]).stem == "vbmeta"
            ]
            self.assertEqual(2, len(root_verifies))
            self.assertIn("--key", root_verifies[0])
            self.assertIn("--follow_chain_partitions", root_verifies[1])
            keyed_root = next(
                command for command in root_verifies if "--key" in command
            )
            followed_root = next(
                command for command in root_verifies if "--follow_chain_partitions" in command
            )
            self.assertNotIn("--follow_chain_partitions", keyed_root)
            self.assertNotIn("--key", followed_root)
            expected_chains = {
                f"{partition}:{location}:{public / f'avb_{partition}.avbpubkey'}"
                for partition, location in chain_locations.items()
            }
            for root_verify in root_verifies:
                actual_chains = {
                    root_verify[index + 1]
                    for index, value in enumerate(root_verify)
                    if value == "--expected_chain_partition"
                }
                self.assertEqual(
                    len(chain_locations),
                    root_verify.count("--expected_chain_partition"),
                )
                self.assertEqual(expected_chains, actual_chains)
            keyed_children = [
                command
                for command in commands
                if "verify_image" in command
                and Path(command[command.index("--image") + 1]).stem != "vbmeta"
            ]
            self.assertEqual(3, len(keyed_children))
            self.assertTrue(
                all(
                    Path(command[command.index("--key") + 1]).name.endswith(
                        ".public.pem"
                    )
                    for command in keyed_children
                )
            )

    def test_root_vbmeta_chain_manifest_must_match_release_keys_exactly(self):
        module = load_verifier()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "signed-target.zip"
            public = root / "public-keys"
            public.mkdir()
            with zipfile.ZipFile(target, "w") as archive:
                for partition in module.REQUIRED_AVB_PARTITIONS:
                    archive.writestr(f"IMAGES/{partition}.img", partition.encode())
                    (public / f"avb_{partition}.avbpubkey").write_bytes(
                        f"public-{partition}".encode()
                    )
                    (public / f"avb_{partition}.public.pem").write_text(
                        f"pem-{partition}", encoding="utf-8"
                    )

            expected = {
                "boot": (
                    1,
                    hashlib.sha1(
                        (public / "avb_boot.avbpubkey").read_bytes()
                    ).hexdigest(),
                ),
                "vbmeta_system": (
                    2,
                    hashlib.sha1(
                        (public / "avb_vbmeta_system.avbpubkey").read_bytes()
                    ).hexdigest(),
                ),
                "vbmeta_vendor": (
                    3,
                    hashlib.sha1(
                        (public / "avb_vbmeta_vendor.avbpubkey").read_bytes()
                    ).hexdigest(),
                ),
            }

            def info(chains):
                lines = [
                    "Public key (sha1): "
                    + hashlib.sha1(
                        (public / "avb_vbmeta.avbpubkey").read_bytes()
                    ).hexdigest(),
                    "Descriptors:",
                ]
                for partition, (location, digest) in chains.items():
                    lines.extend(
                        (
                            "    Chain Partition descriptor:",
                            f"      Partition Name:          {partition}",
                            f"      Rollback Index Location: {location}",
                            f"      Public key (sha1):       {digest}",
                            "      Flags:                   0",
                        )
                    )
                return "\n".join(lines) + "\n"

            cases = {
                "missing": {
                    name: value
                    for name, value in expected.items()
                    if name != "vbmeta_vendor"
                },
                "extra": {**expected, "recovery": (4, "a" * 40)},
                "wrong rollback location": {
                    **expected,
                    "boot": (9, expected["boot"][1]),
                },
                "wrong public key": {**expected, "boot": (1, "b" * 40)},
            }
            for label, chains in cases.items():
                with self.subTest(label=label):
                    def runner(command, **_kwargs):
                        if "info_image" not in command:
                            return "Footer version: 1.0\n"
                        image = Path(command[command.index("--image") + 1])
                        if image.stem == "vbmeta":
                            return info(chains)
                        return "Public key (sha1): " + hashlib.sha1(
                            (public / f"avb_{image.stem}.avbpubkey").read_bytes()
                        ).hexdigest() + "\n"

                    with self.assertRaisesRegex(module.VerificationError, "chain"):
                        module.verify_avb_images(
                            target, public, root / "avbtool", runner=runner
                        )

            malformed = (
                "    Chain Partition descriptor:\n"
                "      Partition Name:          boot\n"
                "      Public key (sha1):       "
                + expected["boot"][1]
                + "\n"
            )
            with self.assertRaisesRegex(module.VerificationError, "malformed"):
                module._parse_avb_chain_descriptors(malformed)

            duplicate = info(expected) + info({"boot": expected["boot"]})
            with self.assertRaisesRegex(module.VerificationError, "duplicate"):
                module._parse_avb_chain_descriptors(duplicate)

    def test_root_vbmeta_public_key_must_come_from_top_level_header(self):
        module = load_verifier()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            public = root / "public-keys"
            public.mkdir()
            image = root / "vbmeta.img"
            image.write_bytes(b"vbmeta")
            for partition in module.REQUIRED_AVB_PARTITIONS:
                (public / f"avb_{partition}.avbpubkey").write_bytes(
                    f"public-{partition}".encode()
                )
                (public / f"avb_{partition}.public.pem").write_text(
                    f"pem-{partition}", encoding="utf-8"
                )
            loose_root = hashlib.sha1(
                (public / "avb_vbmeta.avbpubkey").read_bytes()
            ).hexdigest()
            lines = [f"Nested Public key (sha1): {loose_root}", "Descriptors:"]
            for partition, location in (
                ("boot", 1),
                ("vbmeta_system", 2),
                ("vbmeta_vendor", 3),
            ):
                lines.extend(
                    (
                        "    Chain Partition descriptor:",
                        f"      Partition Name:          {partition}",
                        f"      Rollback Index Location: {location}",
                        "      Public key (sha1):       "
                        + hashlib.sha1(
                            (public / f"avb_{partition}.avbpubkey").read_bytes()
                        ).hexdigest(),
                        "      Flags:                   0",
                    )
                )

            def runner(command, **_kwargs):
                if "info_image" in command:
                    return "\n".join(lines) + "\n"
                if "--key" in command and "--follow_chain_partitions" in command:
                    self.fail(
                        "root key must not be reused for followed child images"
                    )
                return "verified\n"

            with self.assertRaisesRegex(
                module.VerificationError, "embedded public key"
            ):
                module._verify_root_vbmeta(
                    image, public, root / "avbtool", runner=runner
                )

    def test_payload_partition_policy_requires_android_and_manifest_firmware(self):
        module = load_verifier()
        firmware = {"audio_dsp", "md1img"}
        actual = set(module.REQUIRED_ANDROID_PAYLOAD_PARTITIONS) | firmware
        evidence = module.verify_payload_partition_set(actual, actual)
        self.assertEqual(sorted(actual), evidence)
        with self.assertRaisesRegex(module.VerificationError, "system"):
            module.verify_payload_partition_set(actual - {"system"}, actual)
        with self.assertRaisesRegex(module.VerificationError, "unexpected"):
            module.verify_payload_partition_set(actual | {"userdata"}, actual)
        incomplete = actual - {"system"}
        with self.assertRaisesRegex(module.VerificationError, "mandatory.*system"):
            module.verify_payload_partition_set(incomplete, incomplete)

    def test_ota_partition_inventory_and_content_are_derived_from_target_files(self):
        module = load_verifier()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target.zip"
            extracted = root / "extracted"
            extracted.mkdir()
            expected = {
                name: f"image-{name}".encode()
                for name in module.REQUIRED_ANDROID_PAYLOAD_PARTITIONS
            }
            expected["md1img"] = b"radio"
            with zipfile.ZipFile(target, "w") as archive:
                archive.writestr("META/ab_partitions.txt", "".join(f"{name}\n" for name in sorted(expected)))
                for name, value in expected.items():
                    archive.writestr(
                        f"RADIO/{name}.img" if name == "md1img" else f"IMAGES/{name}.img",
                        value,
                    )
            for name, value in expected.items():
                (extracted / f"{name}.img").write_bytes(value)
            evidence = module.verify_ota_partition_binding(
                target, extracted, set(expected), sparse_converter=None
            )
            self.assertEqual(sorted(expected), evidence["partitions"])
            (extracted / "system.img").write_bytes(b"tampered")
            with self.assertRaisesRegex(module.VerificationError, "system"):
                module.verify_ota_partition_binding(
                    target, extracted, set(expected), sparse_converter=None
                )

    def test_full_verification_writes_sanitized_report_and_binds_ota_boot(self):
        module = load_verifier()
        fixed_boot = b"refreshed-fixed-kernel-boot"
        firmware = b"pinned-firmware"
        fingerprint = "ab" * 32
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            android_root = root / "android"
            host_tools = android_root / "out/host/linux-x86/bin"
            host_framework = android_root / "out/host/linux-x86/framework"
            host_lib64 = android_root / "out/host/linux-x86/lib64"
            jdk_bin = android_root / "prebuilts/jdk/jdk21/linux-x86/bin"
            host_tools.mkdir(parents=True)
            host_framework.mkdir(parents=True)
            host_lib64.mkdir(parents=True)
            jdk_bin.mkdir(parents=True)
            for tool in (
                "apksigner",
                "deapexer",
                "avbtool",
                "lz4",
                "ota_extractor",
                "debugfs_static",
                "fsck.erofs",
                "unpack_bootimg",
            ):
                (host_tools / tool).write_text("fixture\n", encoding="utf-8")
                (host_tools / tool).chmod(0o755)
            (host_framework / "apksigner.jar").write_bytes(b"jar-fixture")
            (host_lib64 / "libc++.so").write_bytes(b"libcxx-fixture")
            (jdk_bin / "java").write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            (jdk_bin / "java").chmod(0o755)
            payload_info = android_root / "system/update_engine/scripts/payload_info.py"
            payload_info.parent.mkdir(parents=True)
            payload_info.write_text("# fixture\n", encoding="utf-8")
            verifier_repo = android_root / "external/update_verifier"
            verifier_repo.mkdir(parents=True)
            (verifier_repo / "update_verifier.py").write_text("# fixture\n", encoding="utf-8")
            public = root / "public-keys"
            public.mkdir()
            (public / "releasekey.x509.pem").write_text(
                "certificate", encoding="utf-8"
            )
            for role in MAC_SEINFO_ROLES.values():
                (public / f"{role}.x509.pem").write_bytes(mac_pem(role))
            (public / "com.android.art.avbpubkey").write_bytes(b"apex-key")
            (public / "com.android.art.public.pem").write_text("apex pem", encoding="utf-8")
            (public / "com.android.art.x509.pem").write_text("apex certificate", encoding="utf-8")
            for partition in module.REQUIRED_AVB_PARTITIONS:
                (public / f"avb_{partition}.avbpubkey").write_bytes(partition.encode())
                (public / f"avb_{partition}.public.pem").write_text(
                    f"pem-{partition}", encoding="utf-8"
                )
            release_certificate_bytes = (public / "releasekey.x509.pem").read_bytes()
            unsigned_otacerts = io.BytesIO()
            with zipfile.ZipFile(unsigned_otacerts, "w") as archive:
                archive.writestr("lineage.x509.pem", b"lineage")
                archive.writestr("testkey.x509.pem", b"testkey")
            signed_otacerts = io.BytesIO()
            with zipfile.ZipFile(signed_otacerts, "w") as archive:
                archive.writestr(
                    "releasekey.x509.pem", release_certificate_bytes
                )

            apex_buffer = io.BytesIO()
            with zipfile.ZipFile(apex_buffer, "w") as apex:
                apex.writestr("apex_payload.img", b"apex-payload")

            unsigned = root / "lineage_fleur-target_files-test.zip"
            signed = root / "lineage_fleur-SIGNED-target_files.zip"
            common = {
                "META/apkcerts.txt": (
                    'name="ANGLE.apk" certificate="build/make/target/product/security/testkey.x509.pem" '
                    'private_key="build/make/target/product/security/testkey.pk8"\n'
                    'name="Settings.apk" certificate="build/make/target/product/security/testkey.x509.pem" '
                    'private_key="build/make/target/product/security/testkey.pk8"\n'
                ),
                "META/apexkeys.txt": (
                    'name="com.android.art.apex" public_key="build/make/target/product/security/com.android.art.avbpubkey" '
                    'private_key="build/make/target/product/security/com.android.art.pem" '
                    'container_certificate="build/make/target/product/security/platform.x509.pem" '
                    'container_private_key="build/make/target/product/security/platform.pk8" partition="system"\n'
                ),
                "META/misc_info.txt": (
                    "ab_update=true\nvirtual_ab=true\n"
                    "build_super_partition=true\n"
                    "dynamic_partition_list=odm product system system_ext vendor\n"
                    "building_oem_image=\nmkbootimg_init_args=\n"
                    "tool_extensions=device/xiaomi/fleur/../common\n"
                    "default_system_dev_certificate=release/releasekey\n"
                    + "".join(
                        f"avb_{partition}_key_path=/release/.signing-runtime/public-pem/avb_{partition}.public.pem\n"
                        f"avb_{partition}_algorithm=SHA256_RSA4096\n"
                        for partition in module.REQUIRED_AVB_PARTITIONS
                    )
                ),
                "META/otakeys.txt": "\n",
                "META/ab_partitions.txt": "\n".join(
                    sorted(set(module.REQUIRED_ANDROID_PAYLOAD_PARTITIONS) | {"md1img"})
                ) + "\n",
                "META/fastboot-info.txt": FLEUR_FASTBOOT_INFO,
                "OTA/android-info.txt": "board=fleur\n",
                "SYSTEM/app/Settings/Settings.apk": b"apk",
                "SYSTEM/apex/com.android.art.apex": apex_buffer.getvalue(),
                "RADIO/md1img.img": firmware,
            }
            for filename, market_name in EXPECTED_SKUS.items():
                common[f"ODM/etc/{filename}"] = (
                    f"ro.product.marketname={market_name}\n"
                    f"ro.product.odm.model={market_name}\n"
                )
            for partition in set(module.REQUIRED_ANDROID_PAYLOAD_PARTITIONS) | {
                "super_empty",
                "unsparse_super_empty",
            }:
                common[f"IMAGES/{partition}.img"] = (
                    fixed_boot if partition == "boot" else f"image-{partition}".encode()
                )
            for path, tags in ((unsigned, "test-keys"), (signed, "release-keys")):
                with zipfile.ZipFile(path, "w") as archive:
                    for name, value in common.items():
                        archive.writestr(name, value)
                    archive.writestr(
                        "SYSTEM/build.prop",
                        "ro.build.version.base_os=\n"
                        f"ro.product.system.device=fleur\nro.build.tags={tags}\nro.system.build.tags={tags}\n",
                    )
                    archive.writestr(
                        "SYSTEM/etc/selinux/plat_mac_permissions.xml",
                        mac_policy(signed=path == signed),
                    )
                    platform_certificate = mac_der(
                        "platform", release=path == signed
                    )
                    archive.writestr(
                        "VENDOR/etc/selinux/vendor_mac_permissions.xml",
                        b'<?xml version="1.0" encoding="iso-8859-1"?><policy>'
                        b'<signer signature="'
                        + platform_certificate.hex().encode()
                        + b'"><seinfo value="platform"/></signer></policy>',
                    )
                    for partition in ("ODM", "PRODUCT", "SYSTEM_EXT"):
                        archive.writestr(
                            f"{partition}/etc/selinux/"
                            f"{partition.lower()}_mac_permissions.xml",
                            b'<?xml version="1.0" encoding="iso-8859-1"?>'
                            b"<policy></policy>",
                        )
                    write_zip_symlink(
                        archive,
                        "BOOT/RAMDISK/adb_keys",
                        b"/product/etc/security/adb_keys",
                    )
                    trust_payload = (
                        unsigned_otacerts.getvalue()
                        if path == unsigned
                        else signed_otacerts.getvalue()
                    )
                    for trust_name in (
                        "BOOT/RAMDISK/system/etc/security/otacerts.zip",
                        "SYSTEM/etc/security/otacerts.zip",
                    ):
                        archive.writestr(trust_name, trust_payload)

            ota = root / "lineage-SIGNED-fleur.zip"
            with zipfile.ZipFile(ota, "w") as archive:
                archive.writestr("META-INF/com/android/metadata", "pre-device=fleur\nota-type=AB\n")
                payload = self._payload()
                metadata_size = 24 + len(b"manifest")
                archive.writestr("payload.bin", payload)
                archive.writestr(
                    "payload_properties.txt",
                    "FILE_HASH="
                    + base64.b64encode(hashlib.sha256(payload).digest()).decode("ascii")
                    + f"\nFILE_SIZE={len(payload)}\n"
                    "METADATA_HASH="
                    + base64.b64encode(hashlib.sha256(payload[:metadata_size]).digest()).decode("ascii")
                    + f"\nMETADATA_SIZE={metadata_size}\n",
                )
            fastboot = root / "lineage_fleur-SIGNED-img.zip"
            with zipfile.ZipFile(fastboot, "w") as archive:
                archive.writestr("android-info.txt", "board=fleur\n")
                archive.writestr("fastboot-info.txt", FLEUR_FASTBOOT_INFO)
                for partition in set(module.REQUIRED_ANDROID_PAYLOAD_PARTITIONS) | {
                    "super_empty",
                    "unsparse_super_empty",
                }:
                    archive.writestr(
                        f"{partition}.img",
                        fixed_boot if partition == "boot" else f"image-{partition}".encode(),
                    )
                archive.writestr("md1img.img", firmware)
            manifest = root / "firmware.json"
            manifest.write_text(
                json.dumps(
                    {
                        "schemaVersion": 1,
                        "device": "fleur",
                        "vendorRevision": "1" * 40,
                        "archivePackage": {"version": "fixture"},
                        "partitions": [
                            {
                                "name": "md1img",
                                "file": "radio/md1img.img",
                                "size": len(firmware),
                                "sha256": hashlib.sha256(firmware).hexdigest(),
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            report = root / "verification-report.json"
            source_inventory = module.load_signing_inventory(unsigned)
            kernel_policy = json.loads((ROOT / "sources/kernel-fix.json").read_text(encoding="utf-8"))
            policy_fields = {
                name: kernel_policy[name]
                for name in (
                    "project", "file", "base_commit", "patch_sha256",
                    "application_script", "application_script_sha256",
                    "rejected_pre_fix_boot_sha256",
                    "rejected_pre_fix_boot_content_sha256",
                )
            }
            application = {
                **policy_fields, "post_fix_source_sha256": "1" * 64,
                "forward_applicable": False, "reverse_applicable": True,
            }
            build_provenance = root / "build-provenance.json"
            build_record = {
                "schema_version": 1, "state": "finalized", "device": "fleur",
                "session_nonce": "2" * 64,
                "pre_build": {
                    **application, "timestamp": "2026-08-29T00:00:00Z",
                    "application_evidence_sha256": hashlib.sha256(
                        json.dumps(application, sort_keys=True, separators=(",", ":")).encode()
                    ).hexdigest(),
                },
                "unsigned_target_files": {
                    **module._path_evidence(unsigned),
                    "boot_raw_sha256": hashlib.sha256(fixed_boot).hexdigest(),
                    "boot_content_sha256": hashlib.sha256(fixed_boot).hexdigest(),
                },
            }
            build_provenance.write_text(json.dumps(build_record), encoding="utf-8")
            signer_report = root / "signing-report.json"
            selinux_evidence = module.verify_selinux_mac_permissions(
                unsigned, signed, public
            )
            signer_report.write_text(
                json.dumps(
                    {
                        "schema_version": 2,
                        "device": "fleur",
                        "input": module._path_evidence(unsigned),
                        "outputs": {
                            path.name: {
                                "sha256": module._path_evidence(path)["sha256"],
                                "size": module._path_evidence(path)["size"],
                            }
                            for path in (signed, ota, fastboot)
                        },
                        "input_metadata_sha256": module.target_metadata_hashes(unsigned),
                        "key_plan": module.key_plan_evidence(module.build_key_plan(source_inventory)),
                        "presigned_allowlist": module.presigned_inventory(source_inventory),
                        "public_fingerprints": module.fingerprint_public_bundle(public),
                        "build_provenance": module.build_provenance_evidence(
                            build_provenance, build_record
                        ),
                        "selinux_mac_permissions": selinux_evidence,
                    }
                ),
                encoding="utf-8",
            )
            commands = []
            apksigner_environments = []
            unsigned_ramdisk = build_newc(
                {
                    "init": (stat.S_IFREG | 0o755, b"init"),
                    "default.prop": (stat.S_IFLNK | 0o777, b"prop.default"),
                    "prop.default": (
                        stat.S_IFREG | 0o644,
                        b"ro.build.tags=test-keys\n",
                    ),
                    "first_stage_ramdisk/system/etc/ramdisk/build.prop": (
                        stat.S_IFREG | 0o644,
                        b"ro.bootimage.build.tags=test-keys\n",
                    ),
                    "system/etc/ramdisk/build.prop": (
                        stat.S_IFREG | 0o644,
                        b"ro.bootimage.build.tags=test-keys\n",
                    ),
                    "system/etc/security/otacerts.zip": (
                        stat.S_IFREG | 0o644,
                        unsigned_otacerts.getvalue(),
                    ),
                }
            )
            signed_ramdisk = build_newc(
                {
                    "init": (stat.S_IFREG | 0o755, b"init"),
                    "default.prop": (stat.S_IFLNK | 0o777, b"prop.default"),
                    "prop.default": (
                        stat.S_IFREG | 0o644,
                        b"ro.build.tags=release-keys\n\n",
                    ),
                    "first_stage_ramdisk/system/etc/ramdisk/build.prop": (
                        stat.S_IFREG | 0o644,
                        b"ro.bootimage.build.tags=release-keys\n\n",
                    ),
                    "system/etc/ramdisk/build.prop": (
                        stat.S_IFREG | 0o644,
                        b"ro.bootimage.build.tags=release-keys\n\n",
                    ),
                    "system/etc/security/otacerts.zip": (
                        stat.S_IFREG | 0o644,
                        signed_otacerts.getvalue(),
                    ),
                }
            )
            boot_unpack_count = 0
            decompressed_ramdisks = {}

            def runner(command, **kwargs):
                nonlocal boot_unpack_count
                command = tuple(str(item) for item in command)
                commands.append(command)
                tool = Path(command[0]).name
                if tool == "git" and command[1] == "archive":
                    output = Path(next(value.split("=", 1)[1] for value in command if value.startswith("--output=")))
                    with tarfile.open(output, "w") as archive:
                        archive.add(verifier_repo / "update_verifier.py", arcname="update_verifier.py")
                    return ""
                if tool == "git" and command[1] == "status":
                    return ""
                if tool == "git":
                    return module.PINNED_UPDATE_VERIFIER_COMMIT + "\n"
                if "-I" in command and "update_verifier.py" in {
                    Path(item).name for item in command
                }:
                    return "verified successfully\n"
                if tool == "openssl" and "-pubkey" in command:
                    return "-----BEGIN PUBLIC KEY-----\nfixture\n-----END PUBLIC KEY-----\n"
                if tool == "openssl":
                    return "sha256 Fingerprint=" + ":".join(["AB"] * 32) + "\n"
                if tool == "apksigner":
                    apksigner_environments.append(kwargs.get("env"))
                    return f"Signer #1 certificate SHA-256 digest: {fingerprint}\n"
                if "-I" in command and "payload_info.py" in {Path(item).name for item in command}:
                    names = set(module.REQUIRED_ANDROID_PAYLOAD_PARTITIONS) | {"md1img"}
                    return "\n".join(f'Number of "{name}" ops: 1' for name in sorted(names))
                if tool == "ota_extractor":
                    output = Path(next(value.split("=", 1)[1] for value in command if value.startswith("--output_dir=")))
                    output.mkdir(exist_ok=True)
                    for partition in set(module.REQUIRED_ANDROID_PAYLOAD_PARTITIONS) | {"md1img"}:
                        if partition == "boot":
                            value = fixed_boot
                        elif partition == "md1img":
                            value = firmware
                        else:
                            value = f"image-{partition}".encode()
                        (output / f"{partition}.img").write_bytes(value)
                    return ""
                if tool == "unpack_bootimg":
                    output = Path(command[command.index("--out") + 1])
                    ramdisk = (
                        unsigned_ramdisk if boot_unpack_count == 0 else signed_ramdisk
                    )
                    boot_unpack_count += 1
                    (output / "kernel").write_bytes(b"kernel")
                    (output / "dtb").write_bytes(b"dtb")
                    compressed = b"compressed-ramdisk"
                    (output / "ramdisk").write_bytes(compressed)
                    decompressed_ramdisks[str(output / "ramdisk")] = ramdisk
                    return (
                        "boot magic: ANDROID!\n"
                        "kernel_size: 6\n"
                        "kernel load address: 0x40080000\n"
                        f"ramdisk size: {len(compressed)}\n"
                        "ramdisk load address: 0x47c80000\n"
                        "second bootloader size: 0\n"
                        "second bootloader load address: 0x00000000\n"
                        "kernel tags load address: 0x4bc80000\n"
                        "page size: 2048\n"
                        "os version: 16.0.0\n"
                        "os patch level: 2026-08\n"
                        "boot image header version: 2\n"
                        "product name: \n"
                        "command line args: console=tty0\n"
                        "additional command line args: \n"
                        "recovery dtbo size: 0\n"
                        "recovery dtbo offset: 0x0000000000000000\n"
                        "boot header size: 1660\n"
                        "dtb size: 3\n"
                        "dtb address: 0x000000004bc80000\n"
                    )
                if tool == "lz4":
                    Path(command[-1]).write_bytes(
                        decompressed_ramdisks[command[-2]]
                    )
                    return ""
                if tool == "deapexer":
                    Path(command[-1]).mkdir()
                    (Path(command[-1]) / "apex_manifest.pb").write_bytes(b"manifest")
                    return ""
                if tool == "avbtool" and "info_image" in command:
                    image = Path(command[command.index("--image") + 1])
                    if image.name.startswith("payload-"):
                        public_blob = b"apex-key"
                    else:
                        public_blob = image.stem.encode()
                    output = "Public key (sha1): " + hashlib.sha1(public_blob).hexdigest() + "\n"
                    if image.stem == "vbmeta":
                        for partition, location in (
                            ("boot", 1),
                            ("vbmeta_system", 2),
                            ("vbmeta_vendor", 3),
                        ):
                            output += (
                                "    Chain Partition descriptor:\n"
                                f"      Partition Name:          {partition}\n"
                                f"      Rollback Index Location: {location}\n"
                                "      Public key (sha1):       "
                                + hashlib.sha1(partition.encode()).hexdigest()
                                + "\n      Flags:                   0\n"
                            )
                    return output
                return "verified\n"

            args = SimpleNamespace(
                unsigned_target_files=unsigned,
                signed_target_files=signed,
                ota=ota,
                fastboot=fastboot,
                public_keys=public,
                android_root=android_root,
                firmware_manifest=manifest,
                signing_report=signer_report,
                build_provenance=build_provenance,
                report=report,
            )
            result = module.verify_release(
                args,
                runner=runner,
                firmware_verifier=lambda *_args: {
                    "status": "verified",
                    "partitions": [{"name": "md1img"}],
                },
            )
            self.assertEqual("pass", result["status"])
            self.assertEqual(
                set(MAC_SEINFO_ROLES.values()),
                set(result["selinux_mac_permissions"]["roles"]),
            )
            self.assertEqual(
                hashlib.sha256(fixed_boot).hexdigest(),
                result["kernel_provenance"]["boot_content_sha256"],
            )
            self.assertEqual(result, json.loads(report.read_text(encoding="utf-8")))
            self.assertNotIn(str(root), report.read_text(encoding="utf-8"))
            self.assertTrue(apksigner_environments)
            for environment in apksigner_environments:
                self.assertEqual(
                    str(jdk_bin.parent), environment["JAVA_HOME"]
                )
                self.assertEqual(
                    str(jdk_bin), environment["PATH"].split(os.pathsep)[0]
                )

            (report).unlink()
            with zipfile.ZipFile(ota, "w") as archive:
                archive.writestr("META-INF/com/android/metadata", "pre-device=fleur\nota-type=AB\n")
                archive.writestr("payload.bin", b"payload")
                archive.writestr("payload_properties.txt", "FILE_HASH=bad\n")
            with self.assertRaises(module.VerificationError):
                module.verify_release(
                    args,
                    runner=runner,
                    firmware_verifier=lambda *_args: self.fail("invalid OTA must fail first"),
                )
            self.assertFalse(report.exists())

    def test_public_bundle_rejects_symlinks_and_fingerprints_every_file(self):
        module = load_verifier()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bundle = root / "public"
            bundle.mkdir()
            (bundle / "releasekey.x509.pem").write_bytes(b"cert")
            fingerprints = module.fingerprint_public_bundle(bundle)
            self.assertEqual({"releasekey.x509.pem"}, set(fingerprints))
            os.symlink(bundle / "releasekey.x509.pem", bundle / "alias.x509.pem")
            with self.assertRaisesRegex(module.VerificationError, "symlink"):
                module.fingerprint_public_bundle(bundle)

    def test_snapshotted_input_detects_post_use_replacement(self):
        module = load_verifier()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "artifact.zip"
            source.write_bytes(b"original")
            with module.snapshot_regular_files({"artifact": source}) as snapshot:
                self.assertEqual(b"original", snapshot.paths["artifact"].read_bytes())
                replacement = root / "replacement"
                replacement.write_bytes(b"changed")
                os.replace(replacement, source)
                with self.assertRaisesRegex(module.VerificationError, "changed"):
                    snapshot.verify()

    def test_android_toolchain_snapshot_rejects_symlink_and_source_replacement(self):
        module = load_verifier()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            android = root / "android"
            tools = android / "out/host/linux-x86/bin"
            framework = android / "out/host/linux-x86/framework"
            libraries = android / "out/host/linux-x86/lib64"
            jdk_bin = android / "prebuilts/jdk/jdk21/linux-x86/bin"
            scripts = android / "system/update_engine/scripts"
            tools.mkdir(parents=True)
            framework.mkdir(parents=True)
            libraries.mkdir(parents=True)
            jdk_bin.mkdir(parents=True)
            scripts.mkdir(parents=True)
            for name in module.ANDROID_TOOL_NAMES:
                path = tools / name
                path.write_bytes((name + "-original").encode())
                path.chmod(0o755)
            (framework / "apksigner.jar").write_bytes(b"apksigner-jar-original")
            (libraries / "libc++.so").write_bytes(b"libcxx-original")
            (libraries / "libprotobuf-cpp-lite.so").write_bytes(b"protobuf-original")
            (jdk_bin / "java").write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            (jdk_bin / "java").chmod(0o755)
            (scripts / "payload_info.py").write_text("print('fixture')\n", encoding="utf-8")
            (scripts / "helper.py").write_text("VALUE = 'clean'\n", encoding="utf-8")

            with self.assertRaisesRegex(module.VerificationError, "changed"):
                with module.snapshot_android_toolchain(android) as snapshot:
                    self.assertEqual(
                        b"avbtool-original",
                        (snapshot.host_tools / "avbtool").read_bytes(),
                    )
                    replacement = root / "replacement"
                    replacement.write_bytes(b"changed")
                    replacement.chmod(0o755)
                    os.replace(replacement, tools / "avbtool")

            (tools / "avbtool").write_bytes(b"avbtool-original")
            (tools / "avbtool").chmod(0o755)
            with self.assertRaisesRegex(module.VerificationError, "changed"):
                with module.snapshot_android_toolchain(android) as snapshot:
                    self.assertEqual(
                        b"apksigner-jar-original",
                        (snapshot.root / "framework/apksigner.jar").read_bytes(),
                    )
                    (framework / "apksigner.jar").write_bytes(b"mutated")
            (framework / "apksigner.jar").write_bytes(b"apksigner-jar-original")
            with self.assertRaisesRegex(module.VerificationError, "changed"):
                with module.snapshot_android_toolchain(android) as snapshot:
                    self.assertEqual(
                        b"libcxx-original",
                        (snapshot.root / "lib64/libc++.so").read_bytes(),
                    )
                    (libraries / "libc++.so").write_bytes(b"mutated")
            (libraries / "libc++.so").write_bytes(b"libcxx-original")
            with self.assertRaisesRegex(module.VerificationError, "inventory changed"):
                with module.snapshot_android_toolchain(android):
                    (libraries / "late-library.so").write_bytes(b"late")
            (libraries / "late-library.so").unlink()
            with self.assertRaisesRegex(module.VerificationError, "changed"):
                with module.snapshot_android_toolchain(android):
                    (jdk_bin / "java").write_bytes(b"mutated-java")
            (jdk_bin / "java").write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            (jdk_bin / "java").chmod(0o755)
            with self.assertRaisesRegex(module.VerificationError, "inventory changed"):
                with module.snapshot_android_toolchain(android):
                    (scripts / "shadow.py").write_text(
                        "raise RuntimeError('late import shadow')\n", encoding="utf-8"
                    )
            (scripts / "shadow.py").unlink()

            with self.assertRaisesRegex(module.VerificationError, "execution copy changed"):
                with module.snapshot_android_toolchain(android) as snapshot:
                    executed = snapshot.host_tools / "avbtool"
                    executed.chmod(0o755)
                    executed.write_bytes(b"mutated-execution-copy")

            with self.assertRaisesRegex(module.VerificationError, "execution copy changed"):
                with module.snapshot_android_toolchain(android) as snapshot:
                    executed_import = snapshot.payload_scripts / "helper.py"
                    executed_import.chmod(0o644)
                    executed_import.write_text(
                        "VALUE = 'mutated execution import'\n", encoding="utf-8"
                    )

            (tools / "avbtool").unlink()
            os.symlink(tools / "apksigner", tools / "avbtool")
            with self.assertRaisesRegex(module.VerificationError, "symlink"):
                with module.snapshot_android_toolchain(android):
                    self.fail("symlinked Android tool must not be consumed")

    def test_apksigner_snapshot_requires_safe_jar_and_preserves_launcher_layout(self):
        module = load_verifier()

        def make_fixture(
            root: Path,
            *,
            jar_kind: str,
            java_kind: str = "regular",
            lib_kind: str = "regular",
        ):
            android = root / "android"
            tools = android / "out/host/linux-x86/bin"
            framework = android / "out/host/linux-x86/framework"
            libraries = android / "out/host/linux-x86/lib64"
            jdk_bin = android / "prebuilts/jdk/jdk21/linux-x86/bin"
            scripts = android / "system/update_engine/scripts"
            tools.mkdir(parents=True)
            if jar_kind == "parent-symlink":
                outside_framework = root / "outside-framework"
                outside_framework.mkdir()
                (outside_framework / "apksigner.jar").write_bytes(b"outside")
                os.symlink(outside_framework, framework)
            else:
                framework.mkdir(parents=True)
            if lib_kind == "symlink":
                outside_libraries = root / "outside-lib64"
                outside_libraries.mkdir()
                (outside_libraries / "libc++.so").write_bytes(b"outside")
                os.symlink(outside_libraries, libraries)
            elif lib_kind != "missing":
                libraries.mkdir(parents=True)
            jdk_bin.mkdir(parents=True)
            scripts.mkdir(parents=True)
            for name in module.ANDROID_TOOL_NAMES:
                path = tools / name
                path.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
                path.chmod(0o755)
            (tools / "apksigner").write_text(
                "#!/bin/sh\n"
                'jar="$(dirname "$0")/../framework/apksigner.jar"\n'
                'test -r "$jar" || { echo "missing jar"; exit 9; }\n'
                'exec java -jar "$jar" "$@"\n',
                encoding="utf-8",
            )
            (tools / "debugfs_static").write_text(
                "#!/bin/sh\n"
                'library="$(dirname "$0")/../lib64/libc++.so"\n'
                'test -r "$library" || { echo "missing libc++"; exit 127; }\n'
                'sha256sum "$library" | cut -d" " -f1\n',
                encoding="utf-8",
            )
            java = jdk_bin / "java"
            if java_kind == "regular":
                java.write_text(
                    "#!/bin/sh\n"
                    'printf "%s\\n" "$JAVA_HOME"\n'
                    'printf "%s\\n" "$*"\n',
                    encoding="utf-8",
                )
                java.chmod(0o755)
            elif java_kind == "nonexec":
                java.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
                java.chmod(0o644)
            elif java_kind == "symlink":
                target = root / "outside-java"
                target.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
                target.chmod(0o755)
                os.symlink(target, java)
            (scripts / "payload_info.py").write_text(
                "print('fixture')\n", encoding="utf-8"
            )
            jar = framework / "apksigner.jar"
            if jar_kind == "regular":
                jar.write_bytes(b"jar-fixture")
            elif jar_kind == "symlink":
                target = root / "outside.jar"
                target.write_bytes(b"outside")
                os.symlink(target, jar)
            if lib_kind == "regular":
                (libraries / "libc++.so").write_bytes(b"libcxx-fixture")
                (libraries / "libprotobuf-cpp-lite.so").write_bytes(
                    b"protobuf-fixture"
                )
            elif lib_kind == "file-symlink":
                target = root / "outside-libc++.so"
                target.write_bytes(b"outside")
                os.symlink(target, libraries / "libc++.so")
            elif lib_kind == "subdir":
                (libraries / "nested").mkdir()
                (libraries / "libc++.so").write_bytes(b"libcxx-fixture")
            elif lib_kind == "special":
                os.mkfifo(libraries / "libc++.so")
            return android

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            android = make_fixture(root, jar_kind="regular")
            with module.snapshot_android_toolchain(android) as snapshot:
                result = subprocess.run(
                    [snapshot.host_tools / "apksigner", "verify"],
                    check=True,
                    text=True,
                    stdout=subprocess.PIPE,
                    env=snapshot.apksigner_environment,
                )
                lines = result.stdout.splitlines()
                self.assertEqual(
                    android / "prebuilts/jdk/jdk21/linux-x86",
                    Path(lines[0]),
                )
                self.assertIn("framework/apksigner.jar verify", lines[1])
                debugfs = subprocess.run(
                    [snapshot.host_tools / "debugfs_static"],
                    check=True,
                    text=True,
                    stdout=subprocess.PIPE,
                )
                self.assertEqual(
                    hashlib.sha256(b"libcxx-fixture").hexdigest(),
                    debugfs.stdout.strip(),
                )
                self.assertEqual(
                    b"protobuf-fixture",
                    (snapshot.root / "lib64/libprotobuf-cpp-lite.so").read_bytes(),
                )

        for jar_kind, message in (
            ("missing", "unavailable"),
            ("symlink", "symlink"),
            ("parent-symlink", "symlink"),
        ):
            with self.subTest(jar_kind=jar_kind), tempfile.TemporaryDirectory() as directory:
                android = make_fixture(Path(directory), jar_kind=jar_kind)
                with self.assertRaisesRegex(module.VerificationError, message):
                    with module.snapshot_android_toolchain(android):
                        self.fail("unsafe or missing apksigner.jar must not be consumed")

        for java_kind, message in (
            ("missing", "Java.*unavailable"),
            ("symlink", "Java.*symlink"),
            ("nonexec", "Java.*executable"),
        ):
            with self.subTest(java_kind=java_kind), tempfile.TemporaryDirectory() as directory:
                android = make_fixture(
                    Path(directory), jar_kind="regular", java_kind=java_kind
                )
                with self.assertRaisesRegex(module.VerificationError, message):
                    with module.snapshot_android_toolchain(android):
                        self.fail("unsafe or missing Android JDK21 java must not run")

        for lib_kind, message in (
            ("missing", "lib64.*unavailable"),
            ("missing-libcxx", r"libc\+\+.*unavailable"),
            ("symlink", "lib64.*symlink"),
            ("file-symlink", "lib64.*symlink"),
            ("subdir", "lib64.*subdirector"),
            ("special", "lib64.*special"),
        ):
            with self.subTest(lib_kind=lib_kind), tempfile.TemporaryDirectory() as directory:
                android = make_fixture(
                    Path(directory), jar_kind="regular", lib_kind=lib_kind
                )
                with self.assertRaisesRegex(module.VerificationError, message):
                    with module.snapshot_android_toolchain(android):
                        self.fail("unsafe Android host lib64 must not run")

    def test_android_toolchain_execution_labels_reject_traversal_and_collisions(self):
        module = load_verifier()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            claimed: set[Path] = set()
            self.assertEqual(
                root / "framework/apksigner.jar",
                module._android_execution_destination(
                    root, "framework:apksigner.jar", claimed
                ),
            )
            with self.assertRaisesRegex(module.VerificationError, "collision"):
                module._android_execution_destination(
                    root, "framework:apksigner.jar", claimed
                )
            for label in (
                "unknown:file",
                "tool:../framework/apksigner.jar",
                "tool:/absolute",
                r"tool:dir\file",
                "script:dir//file",
                "script:dir/./file",
            ):
                with self.subTest(label=label):
                    with self.assertRaises(module.VerificationError):
                        module._android_execution_destination(root, label, set())

    def test_isolated_python_tool_imports_only_from_snapshotted_root(self):
        module = load_verifier()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            clean = root / "clean"
            shadow = root / "shadow"
            clean.mkdir()
            shadow.mkdir()
            (clean / "helper.py").write_text("VALUE='clean'\n", encoding="utf-8")
            script = clean / "tool.py"
            script.write_text("from helper import VALUE\nprint(VALUE)\n", encoding="utf-8")
            (shadow / "helper.py").write_text(
                "raise RuntimeError('shadowed import executed')\n", encoding="utf-8"
            )
            output = module.run_isolated_python_tool(
                script, clean, [], cwd=shadow
            )
            self.assertEqual("clean", output.strip())

    def test_update_verifier_detects_mutated_clean_export_execution_copy(self):
        module = load_verifier()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repository = root / "verifier"
            repository.mkdir()
            (repository / "update_verifier.py").write_text(
                "print('verified successfully')\n", encoding="utf-8"
            )
            ota = root / "ota.zip"
            key = root / "key.pem"
            ota.write_bytes(b"ota")
            key.write_bytes(b"key")

            def runner(command, **_kwargs):
                command = [str(item) for item in command]
                if command[:3] == ["git", "rev-parse", "HEAD"] or command[:3] == ["git", "rev-parse", "refs/heads/main"]:
                    return module.PINNED_UPDATE_VERIFIER_COMMIT + "\n"
                if command[:2] == ["git", "status"]:
                    return ""
                if command[:2] == ["git", "archive"]:
                    output = Path(next(item.split("=", 1)[1] for item in command if item.startswith("--output=")))
                    with tarfile.open(output, "w") as archive:
                        archive.add(repository / "update_verifier.py", arcname="update_verifier.py")
                    return ""
                if "-I" in command:
                    script = next(Path(item) for item in command if Path(item).name == "update_verifier.py")
                    script.chmod(0o644)
                    script.write_text("print('tampered')\n", encoding="utf-8")
                    return "verified successfully\n"
                self.fail(command)

            with self.assertRaisesRegex(module.VerificationError, "execution copy changed"):
                module.verify_ota_whole_file_signature(
                    repository, ota, key, runner=runner
                )

    def test_report_temporary_is_removed_on_fsync_failure(self):
        module = load_verifier()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report = root / "verification.json"
            with mock.patch.object(module.os, "fsync", side_effect=OSError("disk")):
                with self.assertRaises(OSError):
                    module.write_sanitized_report(report, {"status": "pass"})
            self.assertFalse((root / ".verification.json.tmp").exists())

    def test_zip_member_policy_rejects_traversal_symlink_and_duplicates(self):
        module = load_verifier()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for suffix, writer in (
                ("traversal", lambda z: z.writestr("../evil", b"x")),
                (
                    "duplicate",
                    lambda z: (z.writestr("same", b"x"), z.writestr("same", b"y")),
                ),
            ):
                path = root / f"{suffix}.zip"
                with warnings.catch_warnings(), zipfile.ZipFile(path, "w") as archive:
                    warnings.simplefilter("ignore", UserWarning)
                    writer(archive)
                with self.assertRaises(module.VerificationError):
                    module.validate_zip_members(path)
            symlink_zip = root / "symlink.zip"
            info = zipfile.ZipInfo("link")
            info.create_system = 3
            info.external_attr = 0o120777 << 16
            with zipfile.ZipFile(symlink_zip, "w") as archive:
                archive.writestr(info, "target")
            with self.assertRaisesRegex(module.VerificationError, "symlink"):
                module.validate_zip_members(symlink_zip)
            with self.assertRaisesRegex(module.VerificationError, "symlink"):
                module._zip_evidence(symlink_zip)

    def test_target_files_symlink_manifest_must_match_exactly(self):
        module = load_verifier()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            unsigned = root / "unsigned.zip"
            expected = {
                "BOOT/RAMDISK/adb_keys": b"/product/etc/security/adb_keys",
                "SYSTEM/bin/tool": b"../lib64/tool",
            }
            with zipfile.ZipFile(unsigned, "w") as archive:
                archive.writestr("META/member", b"unsigned")
                for name, target in expected.items():
                    write_zip_symlink(archive, name, target)

            matching = root / "matching.zip"
            with zipfile.ZipFile(matching, "w") as archive:
                archive.writestr("META/member", b"signed")
                for name, target in expected.items():
                    write_zip_symlink(archive, name, target)
            module.validate_target_files_symlink_manifest(unsigned, matching)

            variants = {
                "added": {
                    **expected,
                    "SYSTEM/bin/added": b"/system/lib64/added",
                },
                "removed": {
                    "BOOT/RAMDISK/adb_keys": expected["BOOT/RAMDISK/adb_keys"],
                },
                "retargeted": {
                    **expected,
                    "SYSTEM/bin/tool": b"../lib64/other",
                },
            }
            for label, links in variants.items():
                with self.subTest(change=label):
                    candidate = root / f"{label}.zip"
                    with zipfile.ZipFile(candidate, "w") as archive:
                        archive.writestr("META/member", b"signed")
                        for name, target in links.items():
                            write_zip_symlink(archive, name, target)
                    with self.assertRaisesRegex(
                        module.VerificationError, "symlink manifest"
                    ):
                        module.validate_target_files_symlink_manifest(
                            unsigned, candidate
                        )

            mode_changed = root / "mode-changed.zip"
            with zipfile.ZipFile(mode_changed, "w") as archive:
                archive.writestr("META/member", b"signed")
                for name, target in expected.items():
                    write_zip_symlink(
                        archive,
                        name,
                        target,
                        mode=0o755 if name == "SYSTEM/bin/tool" else 0o777,
                    )
            with self.assertRaisesRegex(module.VerificationError, "symlink manifest"):
                module.validate_target_files_symlink_manifest(unsigned, mode_changed)

    def test_target_files_and_generic_zip_policies_reject_terminal_dot(self):
        module = load_verifier()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            unsigned = root / "unsigned.zip"
            with zipfile.ZipFile(unsigned, "w") as archive:
                archive.writestr("dir/", b"")

            valid = root / "valid.zip"
            with zipfile.ZipFile(valid, "w") as archive:
                archive.writestr("dir/", b"")
            module.validate_zip_members(valid)
            module.validate_target_files_symlink_manifest(unsigned, valid)

            for unsafe_name in (".", "dir/."):
                candidate = root / f"unsafe-{unsafe_name.replace('/', '-')}.zip"
                with zipfile.ZipFile(candidate, "w") as archive:
                    archive.writestr(unsafe_name, b"unsafe")
                with self.subTest(policy="generic", member=unsafe_name):
                    with self.assertRaisesRegex(module.VerificationError, "unsafe"):
                        module.validate_zip_members(candidate)
                with self.subTest(policy="target-files", member=unsafe_name):
                    with self.assertRaisesRegex(module.VerificationError, "unsafe"):
                        module.validate_target_files_symlink_manifest(
                            unsigned, candidate
                        )

    def test_target_files_symlink_policy_rejects_other_special_files(self):
        module = load_verifier()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            unsigned = root / "unsigned.zip"
            signed = root / "signed.zip"
            for path in (unsigned, signed):
                with zipfile.ZipFile(path, "w") as archive:
                    special = zipfile.ZipInfo("SYSTEM/bin/fifo")
                    special.create_system = 3
                    special.external_attr = (stat.S_IFIFO | 0o600) << 16
                    archive.writestr(special, b"")
            with self.assertRaisesRegex(module.VerificationError, "special"):
                module.validate_target_files_symlink_manifest(unsigned, signed)

    def test_cli_passes_all_required_release_paths_to_verifier(self):
        module = load_verifier()
        captured = []

        def verifier(args):
            captured.append(args)
            return {"status": "pass", "device": "fleur"}

        output = io.StringIO()
        argv = [
            "--unsigned-target-files", "unsigned.zip",
            "--signed-target-files", "signed.zip",
            "--ota", "ota.zip",
            "--fastboot", "fastboot.zip",
            "--public-keys", "public",
            "--android-root", "android",
            "--firmware-manifest", "firmware.json",
            "--signing-report", "signing-report.json",
            "--build-provenance", "build-provenance.json",
            "--report", "verification-report.json",
        ]
        with redirect_stdout(output):
            self.assertEqual(0, module.main(argv, verifier=verifier))
        self.assertEqual("unsigned.zip", str(captured[0].unsigned_target_files))
        self.assertEqual("verification-report.json", str(captured[0].report))
        self.assertEqual("build-provenance.json", str(captured[0].build_provenance))
        self.assertEqual("pass", json.loads(output.getvalue())["status"])


if __name__ == "__main__":
    unittest.main()
