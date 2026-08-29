from pathlib import Path
import hashlib
import importlib.util
import json
import subprocess
import tempfile
import unittest
import zipfile


ROOT = Path(__file__).resolve().parents[1]
VERIFY = ROOT / "scripts" / "ubuntu" / "verify_artifacts.py"
EXPECTED_FIRMWARE = {
    "audio_dsp",
    "gz",
    "lk",
    "logo",
    "md1img",
    "pi_img",
    "preloader_raw",
    "scp",
    "spmfw",
    "sspm",
    "tee",
}


def load_verifier():
    if not VERIFY.is_file():
        raise AssertionError("artifact verifier is missing")
    spec = importlib.util.spec_from_file_location("verify_artifacts", VERIFY)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def make_ota(path: Path, metadata: str, include_payload: bool = True):
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("META-INF/com/android/metadata", metadata)
        if include_payload:
            archive.writestr("payload.bin", b"payload")
            archive.writestr("payload_properties.txt", "FILE_HASH=fake\n")


class ArtifactTest(unittest.TestCase):
    def run_verify(self, ota: Path, *args: str):
        return subprocess.run(
            ["python", str(VERIFY), str(ota), *args],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )

    def test_accepts_fleur_ab_ota_and_writes_checksum_atomically(self):
        with tempfile.TemporaryDirectory() as directory:
            ota = Path(directory) / "lineage-23.2-test-UNOFFICIAL-fleur.zip"
            make_ota(
                ota,
                "pre-device=fleur\npost-build=Lineage/fleur/fleur:16/test\nota-type=AB\n",
            )
            result = self.run_verify(ota)
            self.assertEqual(0, result.returncode, result.stdout)
            report = json.loads(result.stdout)
            self.assertEqual("fleur", report["device"])
            self.assertEqual("not-run", report["firmware"]["status"])
            self.assertEqual(hashlib.sha256(ota.read_bytes()).hexdigest(), report["sha256"])
            sums = ota.parent / "SHA256SUMS"
            self.assertEqual(f"{report['sha256']}  {ota.name}\n", sums.read_text(encoding="utf-8"))
            self.assertFalse((ota.parent / "SHA256SUMS.tmp").exists())

    def test_rejects_wrong_device(self):
        with tempfile.TemporaryDirectory() as directory:
            ota = Path(directory) / "wrong.zip"
            make_ota(ota, "pre-device=rosemary\nota-type=AB\n")
            result = self.run_verify(ota)
            self.assertNotEqual(0, result.returncode)
            self.assertIn("expected fleur", result.stdout.lower())

    def test_rejects_missing_payload(self):
        with tempfile.TemporaryDirectory() as directory:
            ota = Path(directory) / "missing-payload.zip"
            make_ota(ota, "pre-device=fleur\nota-type=AB\n", include_payload=False)
            result = self.run_verify(ota)
            self.assertNotEqual(0, result.returncode)
            self.assertIn("payload.bin", result.stdout)

    def test_parses_official_payload_info_partition_lines(self):
        module = load_verifier()
        text = "\n".join(
            f'  Number of "{name}" ops: 1' for name in sorted(EXPECTED_FIRMWARE)
        )
        self.assertEqual(EXPECTED_FIRMWARE, module.parse_payload_partitions(text))

    def test_rejects_payload_missing_one_firmware_partition(self):
        module = load_verifier()
        actual = EXPECTED_FIRMWARE - {"preloader_raw"}
        with self.assertRaisesRegex(ValueError, "preloader_raw"):
            module.require_payload_partitions(actual, EXPECTED_FIRMWARE)

    def test_extracted_image_accepts_only_zero_padding_after_vendor_prefix(self):
        module = load_verifier()
        vendor = b"pinned-vendor-image"
        expected_hash = hashlib.sha256(vendor).hexdigest()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            vendor_path = root / "vendor.img"
            extracted_path = root / "extracted.img"
            vendor_path.write_bytes(vendor)
            extracted_path.write_bytes(vendor + b"\0" * 4096)
            report = module.verify_normalized_image(
                extracted_path,
                vendor_path,
                expected_size=len(vendor),
                expected_sha256=expected_hash,
            )
            self.assertEqual(len(vendor) + 4096, report["extractedSize"])
            extracted_path.write_bytes(vendor + b"\0" * 4095 + b"\1")
            with self.assertRaisesRegex(ValueError, "non-zero padding"):
                module.verify_normalized_image(
                    extracted_path,
                    vendor_path,
                    expected_size=len(vendor),
                    expected_sha256=expected_hash,
                )

    def test_vendor_checkout_must_be_at_manifest_revision(self):
        module = load_verifier()
        self.assertTrue(
            hasattr(module, "verify_git_revision"),
            "vendor revision verifier is missing",
        )
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory) / "vendor"
            repository.mkdir()
            subprocess.run(["git", "init", "-q"], cwd=repository, check=True)
            subprocess.run(["git", "config", "user.name", "Test"], cwd=repository, check=True)
            subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=repository, check=True)
            (repository / "marker").write_text("pinned", encoding="utf-8")
            subprocess.run(["git", "add", "marker"], cwd=repository, check=True)
            subprocess.run(["git", "commit", "-q", "-m", "fixture"], cwd=repository, check=True)
            revision = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                cwd=repository,
                check=True,
                text=True,
                stdout=subprocess.PIPE,
            ).stdout.strip()
            self.assertEqual(revision, module.verify_git_revision(repository, revision))
            with self.assertRaisesRegex(ValueError, "vendor revision mismatch"):
                module.verify_git_revision(repository, "0" * 40)

    def test_zip_integrity_uses_unzip_and_rejects_corruption(self):
        module = load_verifier()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            good = root / "good.zip"
            with zipfile.ZipFile(good, "w") as archive:
                archive.writestr("member", b"contents")
            result = module.verify_zip_with_unzip(good)
            self.assertEqual("verified", result["status"])
            self.assertEqual(good.name, result["name"])

            corrupt = root / "corrupt.zip"
            corrupt.write_bytes(good.read_bytes()[:-5])
            with self.assertRaisesRegex(ValueError, "unzip -t"):
                module.verify_zip_with_unzip(corrupt)

    def test_zip_integrity_rejects_unsafe_members_before_unzip(self):
        module = load_verifier()
        with tempfile.TemporaryDirectory() as directory:
            archive_path = Path(directory) / "unsafe.zip"
            with zipfile.ZipFile(archive_path, "w") as archive:
                archive.writestr("../escape", b"bad")
            with self.assertRaisesRegex(ValueError, "unsafe"):
                module.verify_zip_with_unzip(archive_path)


if __name__ == "__main__":
    unittest.main()
