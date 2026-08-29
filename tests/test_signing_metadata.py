from pathlib import Path
import tempfile
import unittest
import warnings
import zipfile

from scripts.ubuntu.signing_metadata import (
    ApexKey,
    ApkCertificate,
    AvbPartitionKey,
    SigningMetadataError,
    _assemble_inventory,
    _parse_apexkeys,
    _parse_apkcerts,
    _parse_avb_keys,
    _parse_misc_info,
    _read_required_member,
    load_signing_inventory,
)


APK_CERTS = '''\
name="framework-res.apk" certificate="build/make/target/product/security/platform.x509.pem" private_key="build/make/target/product/security/platform.pk8"
name="Settings.apk" certificate="build/make/target/product/security/releasekey.x509.pem" private_key="build/make/target/product/security/releasekey.pk8"
'''

APEX_KEYS = '''\
name="com.android.art.apex" public_key="build/make/target/product/security/com.android.art.avbpubkey" private_key="build/make/target/product/security/com.android.art.pem" container_certificate="build/make/target/product/security/platform.x509.pem" container_private_key="build/make/target/product/security/platform.pk8" partition="system"
name="com.android.tzdata.apex" public_key="PRESIGNED" private_key="PRESIGNED" container_certificate="PRESIGNED" container_private_key="PRESIGNED" partition="system"
'''

MISC_INFO = '''\
build_tags=test-keys
avb_boot_key_path=build/make/target/product/security/testkey.pem
avb_boot_algorithm=SHA256_RSA4096
avb_vbmeta_key_path=build/make/target/product/security/testkey.pem
avb_vbmeta_algorithm=SHA256_RSA4096
avb_vbmeta_system_key_path=build/make/target/product/security/testkey.pem
avb_vbmeta_system_algorithm=SHA256_RSA4096
'''

# Sanitized from the authorized local fleur target-files archive.
REAL_MISC_INFO = '''\
ab_update=true
virtual_ab=true
default_system_dev_certificate=build/make/target/product/security/testkey
avb_boot_key_path=external/avb/test/data/testkey_rsa4096.pem
avb_boot_algorithm=SHA256_RSA4096
avb_vbmeta_key_path=external/avb/test/data/testkey_rsa4096.pem
avb_vbmeta_algorithm=SHA256_RSA4096
avb_vbmeta_system_key_path=external/avb/test/data/testkey_rsa4096.pem
avb_vbmeta_system_algorithm=SHA256_RSA4096
avb_vbmeta_vendor_key_path=external/avb/test/data/testkey_rsa4096.pem
avb_vbmeta_vendor_algorithm=SHA256_RSA4096
'''

REAL_SYSTEM_BUILD_PROP = '''\
ro.product.system.device=fleur
ro.system.build.tags=test-keys
ro.build.tags=test-keys
'''


def write_target_files(
    path: Path,
    *,
    apkcerts: str = APK_CERTS,
    apexkeys: str = APEX_KEYS,
    misc_info: str = MISC_INFO,
    system_build_prop: str = REAL_SYSTEM_BUILD_PROP,
    omit: str | None = None,
) -> None:
    members = {
        "META/apkcerts.txt": apkcerts,
        "META/apexkeys.txt": apexkeys,
        "META/misc_info.txt": misc_info,
        "SYSTEM/build.prop": system_build_prop,
    }
    with zipfile.ZipFile(path, "w") as archive:
        for name, text in members.items():
            if name != omit:
                archive.writestr(name, text)


class SigningMetadataTest(unittest.TestCase):
    def test_loads_real_shaped_tags_and_device_from_canonical_system_build_prop(self):
        with tempfile.TemporaryDirectory() as directory:
            target_files = Path(directory) / "lineage_fleur-target_files.zip"
            write_target_files(target_files, misc_info=REAL_MISC_INFO)

            inventory = load_signing_inventory(target_files)

        self.assertEqual(inventory.device, "fleur")
        self.assertEqual(inventory.build_tags, frozenset({"test-keys"}))
        self.assertTrue(inventory.uses_test_build_tags)

    def test_rejects_missing_canonical_system_build_prop(self):
        with tempfile.TemporaryDirectory() as directory:
            target_files = Path(directory) / "lineage_fleur-target_files.zip"
            write_target_files(
                target_files,
                misc_info=REAL_MISC_INFO,
                omit="SYSTEM/build.prop",
            )

            with self.assertRaisesRegex(SigningMetadataError, "SYSTEM/build.prop"):
                load_signing_inventory(target_files)

    def test_rejects_conflicting_canonical_build_tag_properties(self):
        conflicting = REAL_SYSTEM_BUILD_PROP.replace(
            "ro.system.build.tags=test-keys",
            "ro.system.build.tags=release-keys",
        )
        with tempfile.TemporaryDirectory() as directory:
            target_files = Path(directory) / "lineage_fleur-target_files.zip"
            write_target_files(
                target_files,
                misc_info=REAL_MISC_INFO,
                system_build_prop=conflicting,
            )

            with self.assertRaisesRegex(SigningMetadataError, "build tags"):
                load_signing_inventory(target_files)

    def test_rejects_missing_or_ambiguous_canonical_build_identity_properties(self):
        cases = {
            "missing device": REAL_SYSTEM_BUILD_PROP.replace(
                "ro.product.system.device=fleur\n", ""
            ),
            "missing tags": REAL_SYSTEM_BUILD_PROP.replace(
                "ro.build.tags=test-keys\n", ""
            ),
            "ambiguous device": REAL_SYSTEM_BUILD_PROP
            + "ro.product.device=other\n",
        }
        for label, properties in cases.items():
            with self.subTest(case=label), tempfile.TemporaryDirectory() as directory:
                target_files = Path(directory) / "lineage_fleur-target_files.zip"
                write_target_files(
                    target_files,
                    misc_info=REAL_MISC_INFO,
                    system_build_prop=properties,
                )

                with self.assertRaisesRegex(SigningMetadataError, "device|build tags"):
                    load_signing_inventory(target_files)

    def test_reads_required_member_directly(self):
        with tempfile.TemporaryDirectory() as directory:
            target_files = Path(directory) / "target-files.zip"
            write_target_files(target_files)

            with zipfile.ZipFile(target_files) as archive:
                self.assertEqual(
                    _read_required_member(archive, "META/apkcerts.txt"), APK_CERTS
                )

    def test_loads_deterministic_inventory_from_target_files(self):
        with tempfile.TemporaryDirectory() as directory:
            target_files = Path(directory) / "target-files.zip"
            write_target_files(target_files)

            inventory = load_signing_inventory(target_files)

        self.assertEqual(inventory.android_roles, {"platform", "releasekey"})
        self.assertEqual(inventory.apexes[0].name, "com.android.art.apex")
        self.assertEqual(
            {item.partition for item in inventory.avb_keys},
            {"boot", "vbmeta", "vbmeta_system"},
        )
        self.assertTrue(inventory.uses_test_build_tags)
        self.assertIn(
            "build/make/target/product/security/testkey", inventory.source_key_stems
        )
        self.assertTrue(inventory.apexes[1].presigned)
        self.assertNotIn("PRESIGNED", inventory.source_key_stems)

    def test_rejects_missing_required_metadata_member(self):
        with tempfile.TemporaryDirectory() as directory:
            target_files = Path(directory) / "target-files.zip"
            write_target_files(target_files, omit="META/apexkeys.txt")

            with self.assertRaisesRegex(SigningMetadataError, "META/apexkeys.txt"):
                load_signing_inventory(target_files)

    def test_rejects_duplicate_required_metadata_member(self):
        with tempfile.TemporaryDirectory() as directory:
            target_files = Path(directory) / "target-files.zip"
            write_target_files(target_files)
            with zipfile.ZipFile(target_files, "a") as archive:
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore", UserWarning)
                    archive.writestr(
                        "META/apkcerts.txt",
                        'name="other.apk" certificate="other.x509.pem" '
                        'private_key="other.pk8"\n',
                    )

            with self.assertRaisesRegex(SigningMetadataError, "META/apkcerts.txt"):
                load_signing_inventory(target_files)

    def test_rejects_conflicting_duplicate_apex_name(self):
        duplicate = APEX_KEYS + (
            'name="com.android.art.apex" public_key="other.avbpubkey" '
            'private_key="other.pem" container_certificate="other.x509.pem" '
            'container_private_key="other.pk8" partition="product"\n'
        )
        with tempfile.TemporaryDirectory() as directory:
            target_files = Path(directory) / "target-files.zip"
            write_target_files(target_files, apexkeys=duplicate)

            with self.assertRaisesRegex(SigningMetadataError, "com.android.art.apex"):
                load_signing_inventory(target_files)

    def test_rejects_unsupported_avb_algorithm(self):
        unsupported = MISC_INFO.replace("SHA256_RSA4096", "SHA256_RSA2048", 1)
        with tempfile.TemporaryDirectory() as directory:
            target_files = Path(directory) / "target-files.zip"
            write_target_files(target_files, misc_info=unsupported)

            with self.assertRaisesRegex(SigningMetadataError, "SHA256_RSA2048"):
                load_signing_inventory(target_files)

    def test_rejects_orphan_avb_algorithm_before_accepting_algorithms(self):
        orphaned = MISC_INFO + "avb_vendor_algorithm=SHA256_RSA2048\n"

        with self.assertRaisesRegex(SigningMetadataError, "avb_vendor"):
            _parse_avb_keys(_parse_misc_info(orphaned))

    def test_rejects_orphan_avb_key_path(self):
        orphaned = (
            MISC_INFO
            + "avb_vendor_key_path=build/make/target/product/security/testkey.pem\n"
        )

        with self.assertRaisesRegex(SigningMetadataError, "avb_vendor"):
            _parse_avb_keys(_parse_misc_info(orphaned))

    def test_rejects_apk_certificate_and_private_key_stem_mismatch(self):
        mismatched = APK_CERTS.replace("platform.pk8", "releasekey.pk8", 1)

        with self.assertRaisesRegex(SigningMetadataError, "framework-res.apk"):
            _parse_apkcerts(mismatched)

    def test_rejects_apex_payload_key_stem_mismatch(self):
        mismatched = APEX_KEYS.replace("com.android.art.pem", "other.pem", 1)

        with self.assertRaisesRegex(SigningMetadataError, "com.android.art.apex"):
            _parse_apexkeys(mismatched)

    def test_rejects_apex_container_key_stem_mismatch(self):
        mismatched = APEX_KEYS.replace("platform.pk8", "other.pk8", 1)

        with self.assertRaisesRegex(SigningMetadataError, "com.android.art.apex"):
            _parse_apexkeys(mismatched)

    def test_parses_quoted_apk_and_apex_records(self):
        certificates = _parse_apkcerts(APK_CERTS)
        apexes = _parse_apexkeys(APEX_KEYS)

        self.assertEqual(
            certificates,
            (
                ApkCertificate(
                    "Settings.apk",
                    "build/make/target/product/security/releasekey",
                    "build/make/target/product/security/releasekey",
                ),
                ApkCertificate(
                    "framework-res.apk",
                    "build/make/target/product/security/platform",
                    "build/make/target/product/security/platform",
                ),
            ),
        )
        self.assertEqual(apexes[0].name, "com.android.art.apex")
        self.assertEqual(apexes[0].private_key, "build/make/target/product/security/com.android.art")
        self.assertTrue(apexes[1].presigned)

    def test_parses_avb_keys_in_partition_order(self):
        misc_info = _parse_misc_info(MISC_INFO)

        self.assertEqual(misc_info["build_tags"], "test-keys")

        self.assertEqual(
            _parse_avb_keys(misc_info),
            (
                AvbPartitionKey(
                    "boot", "SHA256_RSA4096", "build/make/target/product/security/testkey"
                ),
                AvbPartitionKey(
                    "vbmeta", "SHA256_RSA4096", "build/make/target/product/security/testkey"
                ),
                AvbPartitionKey(
                    "vbmeta_system", "SHA256_RSA4096", "build/make/target/product/security/testkey"
                ),
            ),
        )

    def test_assembles_roles_and_test_build_tag_from_parsed_metadata(self):
        inventory = _assemble_inventory(
            _parse_apkcerts(APK_CERTS),
            _parse_apexkeys(APEX_KEYS),
            _parse_avb_keys(_parse_misc_info(MISC_INFO)),
            _parse_misc_info(MISC_INFO),
            device="fleur",
            build_tags=frozenset({"test-keys"}),
        )

        self.assertEqual(inventory.android_roles, frozenset({"platform", "releasekey"}))
        self.assertTrue(inventory.uses_test_build_tags)


if __name__ == "__main__":
    unittest.main()
