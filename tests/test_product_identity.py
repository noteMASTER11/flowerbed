from pathlib import Path
import re
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
            self.assertIn(f"sku/build_{sku}.prop", text)
            self.assertGreaterEqual(text.count(f"+ro.product.marketname={market_name}"), 1)
            self.assertGreaterEqual(text.count(f"+ro.product.odm.model={market_name}"), 1)

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
