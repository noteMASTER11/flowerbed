from pathlib import Path
import importlib.util
import json
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "sources" / "provenance.json"
FIRMWARE = ROOT / "sources" / "firmware.json"
RENDERER = ROOT / "scripts" / "render_provenance.py"
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


def load_renderer():
    if not RENDERER.is_file():
        raise AssertionError("provenance renderer is missing")
    spec = importlib.util.spec_from_file_location("render_provenance", RENDERER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ProvenanceTest(unittest.TestCase):
    def test_renderer_produces_deterministic_source_and_firmware_report(self):
        module = load_renderer()
        first = module.render(DATA, FIRMWARE)
        second = module.render(DATA, FIRMWARE)
        self.assertEqual(first, second)
        self.assertIn("mt6781-devs/android_device_xiaomi_fleur", first)
        self.assertIn("StasGr12/Infinity-X-Fleur", first)
        self.assertIn("OS1.0.10.0.TKEINXM", first)
        self.assertIn("`preloader_raw`", first)
        self.assertIn("No current LineageOS 23.x source/build thread", first)

    def test_firmware_registry_resolves_to_exact_payload_set(self):
        module = load_renderer()
        payload = module.load_firmware(FIRMWARE)
        partitions = {item["name"]: item for item in payload["partitions"]}
        self.assertEqual(EXPECTED_FIRMWARE, set(partitions))
        self.assertEqual(10, sum(item["xfuPrefixMatch"] is True for item in partitions.values()))
        self.assertIsNone(partitions["logo"]["xfuPrefixMatch"])
        self.assertEqual("9430b0e8c9e7915fcac5257c21d1c539acaf94c6", payload["vendorRevision"])

    def test_duplicate_firmware_partition_is_rejected(self):
        module = load_renderer()
        payload = {
            "schemaVersion": 1,
            "device": "fleur",
            "vendorRepository": "example/vendor",
            "vendorRevision": "0" * 40,
            "archivePackage": {
                "version": "test",
                "region": "test",
                "filename": "test.zip",
                "url": "https://example.com/test.zip",
                "sha256": "0" * 64,
            },
            "partitions": [
                {"name": "lk", "file": "radio/lk.img", "size": 1, "sha256": "1" * 64, "xfuPrefixMatch": True},
                {"name": "lk", "file": "radio/lk2.img", "size": 1, "sha256": "2" * 64, "xfuPrefixMatch": True},
            ],
            "metadataDiscrepancy": "test",
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "firmware.json"
            path.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "duplicate firmware partition"):
                module.load_firmware(path)

    def test_cli_writes_same_report_as_library(self):
        module = load_renderer()
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "source-provenance.md"
            result = subprocess.run(
                [
                    "python",
                    str(RENDERER),
                    str(DATA),
                    "--firmware",
                    str(FIRMWARE),
                    "--output",
                    str(output),
                ],
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
            )
            self.assertEqual(0, result.returncode, result.stdout)
            self.assertEqual(module.render(DATA, FIRMWARE), output.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
