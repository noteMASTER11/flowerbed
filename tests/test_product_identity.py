from pathlib import Path
import re
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
PATCH = ROOT / "patches/android_device_xiaomi_fleur/0006-fleur-expose-sku-market-names.patch"
APPLIER = ROOT / "scripts/ubuntu/apply_patches.sh"
EXPECTED_SKUS = {
    "fleur": "Redmi Note 11S",
    "miel": "Redmi Note 11S",
    "fleurp": "POCO M4 Pro",
    "mielp": "POCO M4 Pro",
}


class ProductIdentityTest(unittest.TestCase):
    def test_patch_contains_market_name_and_odm_model_for_every_sku(self):
        text = PATCH.read_text(encoding="utf-8")
        for sku, market_name in EXPECTED_SKUS.items():
            section = text.split(f"diff --git a/sku/build_{sku}.prop b/sku/build_{sku}.prop", 1)[1]
            section = section.split("\ndiff --git ", 1)[0]
            self.assertIn(f"+ro.product.marketname={market_name}", section)
            self.assertIn(f"+ro.product.odm.model={market_name}", section)

    def test_patch_is_valid_and_applies_to_sku_fixture(self):
        fixture_files = {
            "fleur": ("Redmi Note 11S", "Redmi", "fleur"),
            "miel": ("Redmi Note 11S", "Redmi", "miel"),
            "fleurp": ("POCO M4 Pro", "POCO", "fleur"),
            "mielp": ("POCO M4 Pro", "POCO", "miel"),
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "sku").mkdir()
            for sku, (market_name, brand, model) in fixture_files.items():
                (root / f"sku/build_{sku}.prop").write_text(
                    f"vendor.usb.product_string={market_name}\n"
                    f"ro.product.odm.brand={brand}\n"
                    f"ro.product.odm.model={model}\n",
                    encoding="utf-8",
                )
            subprocess.run(["git", "init", "-q"], cwd=root, check=True)
            subprocess.run(["git", "add", "sku"], cwd=root, check=True)
            subprocess.run(
                ["git", "-c", "user.name=Test", "-c", "user.email=test@example.invalid", "commit", "-qm", "fixture"],
                cwd=root,
                check=True,
            )
            result = subprocess.run(
                ["git", "apply", "--check", str(PATCH)],
                cwd=root,
                text=True,
                capture_output=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_patch_does_not_change_device_or_product_name(self):
        text = PATCH.read_text(encoding="utf-8")
        self.assertNotRegex(text, re.compile(r"^[+-].*PRODUCT_DEVICE", re.MULTILINE))
        self.assertNotRegex(text, re.compile(r"^[+-].*ro.product.odm.device", re.MULTILINE))
        self.assertNotRegex(text, re.compile(r"^[+-].*ro.product.odm.name", re.MULTILINE))

    def test_patch_is_registered_after_existing_fleur_patches(self):
        text = APPLIER.read_text(encoding="utf-8")
        old = text.index("0005-fleur-use-common-mediatek-vt-context.patch")
        new = text.index("0006-fleur-expose-sku-market-names.patch")
        self.assertLess(old, new)
