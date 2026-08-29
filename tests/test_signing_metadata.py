from pathlib import Path
import tempfile
import unittest
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


def write_target_files(
    path: Path,
    *,
    apkcerts: str = APK_CERTS,
    apexkeys: str = APEX_KEYS,
    misc_info: str = MISC_INFO,
    omit: str | None = None,
) -> None:
    members = {
        "META/apkcerts.txt": apkcerts,
        "META/apexkeys.txt": apexkeys,
        "META/misc_info.txt": misc_info,
    }
    with zipfile.ZipFile(path, "w") as archive:
        for name, text in members.items():
            if name != omit:
                archive.writestr(name, text)


class SigningMetadataTest(unittest.TestCase):
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
        )

        self.assertEqual(inventory.android_roles, frozenset({"platform", "releasekey"}))
        self.assertTrue(inventory.uses_test_build_tags)


if __name__ == "__main__":
    unittest.main()
