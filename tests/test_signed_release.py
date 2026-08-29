from __future__ import annotations

import base64
import hashlib
import io
import importlib.util
import json
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
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


def load_verifier():
    if not VERIFY.is_file():
        raise AssertionError("signed release verifier is missing")
    spec = importlib.util.spec_from_file_location("verify_signed_release", VERIFY)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class SignedReleasePolicyTest(unittest.TestCase):
    def test_rejects_test_build_tags(self):
        module = load_verifier()
        with self.assertRaisesRegex(module.VerificationError, "test-keys"):
            module.verify_build_tags({"ro.product.build.tags": "test-keys"})

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

    def test_rejects_standard_test_key_paths_and_reports_presigned_apex(self):
        module = load_verifier()
        avb_metadata = "".join(
            f"avb_{partition}_key_path=release/avb_{partition}.pem\n"
            f"avb_{partition}_algorithm=SHA256_RSA4096\n"
            for partition in module.REQUIRED_AVB_PARTITIONS
        )
        with self.assertRaisesRegex(module.VerificationError, "test certificate"):
            module.verify_signing_metadata_paths(
                'name="Settings.apk" certificate="build/make/target/product/security/testkey.x509.pem" private_key="build/make/target/product/security/testkey.pk8"\n',
                'name="com.android.tzdata.apex" public_key="PRESIGNED" private_key="PRESIGNED" container_certificate="PRESIGNED" container_private_key="PRESIGNED" partition="system"\n',
                "default_system_dev_certificate=releasekey\n" + avb_metadata,
            )
        permitted = module.verify_signing_metadata_paths(
            'name="Settings.apk" certificate="release/platform.x509.pem" private_key="release/platform.pk8"\n',
            'name="com.android.tzdata.apex" public_key="PRESIGNED" private_key="PRESIGNED" container_certificate="PRESIGNED" container_private_key="PRESIGNED" partition="system"\n',
            "default_system_dev_certificate=release/releasekey\n" + avb_metadata,
        )
        self.assertEqual(["com.android.tzdata.apex"], permitted)
        with self.assertRaisesRegex(module.VerificationError, "vbmeta_vendor"):
            module.verify_signing_metadata_paths(
                'name="Settings.apk" certificate="release/platform.x509.pem" private_key="release/platform.pk8"\n',
                'name="com.android.tzdata.apex" public_key="PRESIGNED" private_key="PRESIGNED" container_certificate="PRESIGNED" container_private_key="PRESIGNED" partition="system"\n',
                "default_system_dev_certificate=release/releasekey\n"
                + avb_metadata.replace(
                    "avb_vbmeta_vendor_key_path=release/avb_vbmeta_vendor.pem\n",
                    "",
                ),
            )

    def test_kernel_provenance_rejects_pre_fix_and_requires_content_match(self):
        module = load_verifier()
        record = {
            "project": "kernel/xiaomi/mt6781",
            "file": "drivers/example.h",
            "base_commit": "9" * 40,
            "patch_sha256": "a" * 64,
            "rejected_pre_fix_boot_sha256": PRE_FIX_BOOT_SHA256,
            "hardware_tested_fixed_boot_sha256": "b" * 64,
            "cfi_remains_enabled": True,
        }
        with self.assertRaisesRegex(module.VerificationError, "pre-fix"):
            module.verify_kernel_boot_provenance(
                {"raw_sha256": PRE_FIX_BOOT_SHA256, "content_sha256": "c" * 64},
                {"raw_sha256": "d" * 64, "content_sha256": "c" * 64},
                record,
            )
        with self.assertRaisesRegex(module.VerificationError, "content"):
            module.verify_kernel_boot_provenance(
                {"raw_sha256": "e" * 64, "content_sha256": "f" * 64},
                {"raw_sha256": "d" * 64, "content_sha256": "c" * 64},
                record,
            )
        result = module.verify_kernel_boot_provenance(
            {"raw_sha256": "e" * 64, "content_sha256": "c" * 64},
            {"raw_sha256": "d" * 64, "content_sha256": "c" * 64},
            record,
        )
        self.assertEqual("kernel/xiaomi/mt6781", result["project"])
        self.assertEqual("c" * 64, result["boot_content_sha256"])
        self.assertEqual("b" * 64, result["hardware_tested_reference_sha256"])
        invalid_record = dict(record, patch_sha256="invalid")
        with self.assertRaisesRegex(module.VerificationError, "patch"):
            module.verify_kernel_boot_provenance(
                {"raw_sha256": "e" * 64, "content_sha256": "c" * 64},
                {"raw_sha256": "d" * 64, "content_sha256": "c" * 64},
                invalid_record,
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
        payload = b"payload"
        file_hash = base64.b64encode(hashlib.sha256(payload).digest()).decode("ascii")
        complete = (
            "FILE_HASH=" + file_hash + "\n"
            f"FILE_SIZE={len(payload)}\n"
            "METADATA_HASH=" + "B" * 43 + "=\n"
            "METADATA_SIZE=45\n"
        )
        self.assertEqual(len(payload), module.verify_payload_properties(complete, payload)["FILE_SIZE"])
        with self.assertRaisesRegex(module.VerificationError, "METADATA_SIZE"):
            module.verify_payload_properties(complete.replace("METADATA_SIZE=45\n", ""))
        with self.assertRaisesRegex(module.VerificationError, "FILE_HASH"):
            module.verify_payload_properties(complete, b"different")

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
                return "verified successfully\n"

            evidence = module.verify_ota_whole_file_signature(
                repository, ota, public_key, runner=runner
            )
            self.assertEqual(module.PINNED_UPDATE_VERIFIER_COMMIT, evidence["revision"])
            self.assertIn(("git", "rev-parse", "refs/heads/main"), commands)
            self.assertEqual("update_verifier.py", Path(commands[-1][1]).name)
            self.assertEqual(ota, Path(commands[-1][-1]))

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

    def test_fastboot_images_and_android_info_must_match_signed_target_files(self):
        module = load_verifier()
        images = {
            "boot": b"boot",
            "dtbo": b"dtbo",
            "vbmeta": b"vbmeta",
            "vbmeta_system": b"vbmeta-system",
            "vbmeta_vendor": b"vbmeta-vendor",
            "super": b"super",
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target.zip"
            fastboot = root / "fastboot.zip"
            with zipfile.ZipFile(target, "w") as archive:
                archive.writestr("OTA/android-info.txt", "require product=fleur\n")
                for partition, value in images.items():
                    archive.writestr(f"IMAGES/{partition}.img", value)
            with zipfile.ZipFile(fastboot, "w") as archive:
                archive.writestr("android-info.txt", "require product=fleur\n")
                for partition, value in images.items():
                    archive.writestr(f"{partition}.img", value)
            evidence = module.verify_fastboot_against_target_files(target, fastboot)
            self.assertEqual(sorted(images), evidence["images"])

            with zipfile.ZipFile(fastboot, "w") as archive:
                archive.writestr("android-info.txt", "require product=fleur\n")
                for partition, value in images.items():
                    archive.writestr(f"{partition}.img", b"wrong" if partition == "boot" else value)
            with self.assertRaisesRegex(module.VerificationError, "boot"):
                module.verify_fastboot_against_target_files(target, fastboot)

    def test_boot_extraction_fails_closed_and_normalizes_avb_footer(self):
        module = load_verifier()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive_path = root / "target.zip"
            with zipfile.ZipFile(archive_path, "w") as archive:
                archive.writestr("IMAGES/boot.img", b"kernel-and-ramdisk")
            calls = []

            def runner(command, **_kwargs):
                calls.append(tuple(str(item) for item in command))
                return ""

            evidence = module.extract_boot_evidence(
                archive_path, root / "avbtool", runner=runner
            )
            digest = hashlib.sha256(b"kernel-and-ramdisk").hexdigest()
            self.assertEqual(digest, evidence["raw_sha256"])
            self.assertEqual(digest, evidence["content_sha256"])
            self.assertIn("erase_footer", calls[0])

            empty = root / "empty.zip"
            with zipfile.ZipFile(empty, "w"):
                pass
            with self.assertRaisesRegex(module.VerificationError, "boot"):
                module.extract_boot_evidence(empty, root / "avbtool", runner=runner)

    def test_verifies_representative_apk_and_every_non_presigned_apex(self):
        module = load_verifier()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "signed-target.zip"
            public = root / "public-keys"
            public.mkdir()
            (public / "platform.x509.pem").write_text("certificate", encoding="utf-8")
            (public / "com.android.art.avbpubkey").write_bytes(b"apex-public")
            (public / "com.android.art.public.pem").write_text("public pem", encoding="utf-8")
            nested = io.BytesIO()
            with zipfile.ZipFile(nested, "w") as apex:
                apex.writestr("apex_payload.img", b"payload")
            with zipfile.ZipFile(target, "w") as archive:
                archive.writestr("SYSTEM/app/Settings/Settings.apk", b"apk")
                archive.writestr("SYSTEM/apex/com.android.art.apex", nested.getvalue())
            apkcerts = (
                'name="Settings.apk" certificate="release/platform.x509.pem" '
                'private_key="release/platform.pk8"\n'
                'name="WebView.apk" certificate="PRESIGNED" private_key="PRESIGNED"\n'
            )
            apexkeys = (
                'name="com.android.art.apex" public_key="release/com.android.art.avbpubkey" '
                'private_key="release/com.android.art.pem" '
                'container_certificate="release/platform.x509.pem" '
                'container_private_key="release/platform.pk8" partition="system"\n'
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

            def runner(command, **_kwargs):
                commands.append(tuple(str(item) for item in command))
                if "verify_image" in command:
                    image = Path(command[command.index("--image") + 1])
                    if image.stem == "vbmeta":
                        self.assertTrue(
                            all(
                                (image.parent / f"{partition}.img").is_file()
                                for partition in module.REQUIRED_AVB_PARTITIONS
                            )
                        )
                if "info_image" in command:
                    image = Path(command[command.index("--image") + 1])
                    partition = image.stem
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
            self.assertEqual(8, len(commands))
            self.assertTrue(all(Path(command[0]).name == "avbtool" for command in commands))
            self.assertTrue(
                all(
                    Path(command[command.index("--key") + 1]).name.endswith(".public.pem")
                    for command in commands
                    if "verify_image" in command
                )
            )

    def test_payload_partition_policy_requires_android_and_manifest_firmware(self):
        module = load_verifier()
        firmware = {"audio_dsp", "md1img"}
        actual = set(module.REQUIRED_ANDROID_PAYLOAD_PARTITIONS) | firmware
        evidence = module.verify_payload_partition_set(actual, firmware)
        self.assertEqual(sorted(actual), evidence)
        with self.assertRaisesRegex(module.VerificationError, "system"):
            module.verify_payload_partition_set(actual - {"system"}, firmware)

    def test_full_verification_writes_sanitized_report_and_binds_ota_boot(self):
        module = load_verifier()
        fixed_boot = b"refreshed-fixed-kernel-boot"
        firmware = b"pinned-firmware"
        fingerprint = "ab" * 32
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            android_root = root / "android"
            host_tools = android_root / "out/host/linux-x86/bin"
            host_tools.mkdir(parents=True)
            for tool in (
                "apksigner",
                "deapexer",
                "avbtool",
                "ota_extractor",
                "debugfs_static",
                "fsck.erofs",
            ):
                (host_tools / tool).write_text("fixture\n", encoding="utf-8")
            payload_info = android_root / "system/update_engine/scripts/payload_info.py"
            payload_info.parent.mkdir(parents=True)
            payload_info.write_text("# fixture\n", encoding="utf-8")
            verifier_repo = android_root / "external/update_verifier"
            verifier_repo.mkdir(parents=True)
            (verifier_repo / "update_verifier.py").write_text("# fixture\n", encoding="utf-8")
            public = root / "public-keys"
            public.mkdir()
            for role in ("releasekey", "platform"):
                (public / f"{role}.x509.pem").write_text("certificate", encoding="utf-8")
            (public / "com.android.art.avbpubkey").write_bytes(b"apex-key")
            (public / "com.android.art.public.pem").write_text("apex pem", encoding="utf-8")
            for partition in module.REQUIRED_AVB_PARTITIONS:
                (public / f"avb_{partition}.avbpubkey").write_bytes(partition.encode())
                (public / f"avb_{partition}.public.pem").write_text(
                    f"pem-{partition}", encoding="utf-8"
                )

            apex_buffer = io.BytesIO()
            with zipfile.ZipFile(apex_buffer, "w") as apex:
                apex.writestr("apex_payload.img", b"apex-payload")

            unsigned = root / "lineage_fleur-target_files-test.zip"
            signed = root / "lineage_fleur-SIGNED-target_files.zip"
            common = {
                "META/apkcerts.txt": (
                    'name="Settings.apk" certificate="release/platform.x509.pem" '
                    'private_key="release/platform.pk8"\n'
                ),
                "META/apexkeys.txt": (
                    'name="com.android.art.apex" public_key="release/com.android.art.avbpubkey" '
                    'private_key="release/com.android.art.pem" '
                    'container_certificate="release/platform.x509.pem" '
                    'container_private_key="release/platform.pk8" partition="system"\n'
                ),
                "META/misc_info.txt": (
                    "ab_update=true\nvirtual_ab=true\n"
                    "default_system_dev_certificate=release/releasekey\n"
                    + "".join(
                        f"avb_{partition}_key_path=release/avb_{partition}.pem\n"
                        f"avb_{partition}_algorithm=SHA256_RSA4096\n"
                        for partition in module.REQUIRED_AVB_PARTITIONS
                    )
                ),
                "OTA/android-info.txt": "require product=fleur\n",
                "SYSTEM/app/Settings/Settings.apk": b"apk",
                "SYSTEM/apex/com.android.art.apex": apex_buffer.getvalue(),
                "RADIO/md1img.img": firmware,
            }
            for filename, market_name in EXPECTED_SKUS.items():
                common[f"ODM/etc/{filename}"] = (
                    f"ro.product.marketname={market_name}\n"
                    f"ro.product.odm.model={market_name}\n"
                )
            for partition in set(module.REQUIRED_ANDROID_PAYLOAD_PARTITIONS) | {"super"}:
                common[f"IMAGES/{partition}.img"] = (
                    fixed_boot if partition == "boot" else f"image-{partition}".encode()
                )
            for path, tags in ((unsigned, "test-keys"), (signed, "release-keys")):
                with zipfile.ZipFile(path, "w") as archive:
                    for name, value in common.items():
                        archive.writestr(name, value)
                    archive.writestr(
                        "SYSTEM/build.prop",
                        f"ro.product.system.device=fleur\nro.build.tags={tags}\nro.system.build.tags={tags}\n",
                    )

            ota = root / "lineage-SIGNED-fleur.zip"
            with zipfile.ZipFile(ota, "w") as archive:
                archive.writestr("META-INF/com/android/metadata", "pre-device=fleur\nota-type=AB\n")
                payload = b"payload"
                archive.writestr("payload.bin", payload)
                archive.writestr(
                    "payload_properties.txt",
                    "FILE_HASH="
                    + base64.b64encode(hashlib.sha256(payload).digest()).decode("ascii")
                    + "\nFILE_SIZE=7\n"
                    "METADATA_HASH=" + "B" * 43 + "=\nMETADATA_SIZE=2\n",
                )
            fastboot = root / "lineage_fleur-SIGNED-img.zip"
            with zipfile.ZipFile(fastboot, "w") as archive:
                archive.writestr("android-info.txt", "require product=fleur\n")
                for partition in module.REQUIRED_FASTBOOT_IMAGES:
                    archive.writestr(
                        f"{partition}.img",
                        fixed_boot if partition == "boot" else f"image-{partition}".encode(),
                    )
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
            commands = []

            def runner(command, **_kwargs):
                command = tuple(str(item) for item in command)
                commands.append(command)
                tool = Path(command[0]).name
                if tool == "git":
                    return module.PINNED_UPDATE_VERIFIER_COMMIT + "\n"
                if len(command) > 1 and Path(command[1]).name == "update_verifier.py":
                    return "verified successfully\n"
                if tool == "openssl" and "-pubkey" in command:
                    return "-----BEGIN PUBLIC KEY-----\nfixture\n-----END PUBLIC KEY-----\n"
                if tool == "openssl":
                    return "sha256 Fingerprint=" + ":".join(["AB"] * 32) + "\n"
                if tool == "apksigner":
                    return f"Signer #1 certificate SHA-256 digest: {fingerprint}\n"
                if len(command) > 1 and Path(command[1]).name == "payload_info.py":
                    names = set(module.REQUIRED_ANDROID_PAYLOAD_PARTITIONS) | {"md1img"}
                    return "\n".join(f'Number of "{name}" ops: 1' for name in sorted(names))
                if tool == "ota_extractor":
                    output = Path(next(value.split("=", 1)[1] for value in command if value.startswith("--output_dir=")))
                    output.mkdir(exist_ok=True)
                    (output / "boot.img").write_bytes(fixed_boot)
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
                    return "Public key (sha1): " + hashlib.sha1(public_blob).hexdigest() + "\n"
                return "verified\n"

            args = SimpleNamespace(
                unsigned_target_files=unsigned,
                signed_target_files=signed,
                ota=ota,
                fastboot=fastboot,
                public_keys=public,
                android_root=android_root,
                firmware_manifest=manifest,
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
                hashlib.sha256(fixed_boot).hexdigest(),
                result["kernel_provenance"]["boot_content_sha256"],
            )
            self.assertEqual(result, json.loads(report.read_text(encoding="utf-8")))
            self.assertNotIn(str(root), report.read_text(encoding="utf-8"))

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
            "--report", "verification-report.json",
        ]
        with redirect_stdout(output):
            self.assertEqual(0, module.main(argv, verifier=verifier))
        self.assertEqual("unsigned.zip", str(captured[0].unsigned_target_files))
        self.assertEqual("verification-report.json", str(captured[0].report))
        self.assertEqual("pass", json.loads(output.getvalue())["status"])


if __name__ == "__main__":
    unittest.main()
