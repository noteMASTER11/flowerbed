from pathlib import Path
import re
import unittest
import xml.etree.ElementTree as ET


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "manifests" / "fleur-lineage-23.2.xml"
EXPECTED = {
    "device/xiaomi/fleur": (
        "mt6781-devs/android_device_xiaomi_fleur",
        "45289f6f6e94fc90870d27477d42a89c735fcff5",
    ),
    "vendor/xiaomi/fleur": (
        "z3rh0/proprietary_vendor_xiaomi_fleur",
        "9430b0e8c9e7915fcac5257c21d1c539acaf94c6",
    ),
    "kernel/xiaomi/mt6781": (
        "mt6781-devs/android_kernel_xiaomi_mt6781",
        "9996b68a1808b38f2f9e7798b26479e721bc2a84",
    ),
    "hardware/mediatek": (
        "mt6781-devs/android_hardware_mediatek",
        "8d18fc6d5b3a63fe2abf9e935947f71c484db291",
    ),
    "device/mediatek/sepolicy_vndr": (
        "mt6781-devs/android_device_mediatek_sepolicy_vndr",
        "dc6d099b7a1b85a38151b80e675684888ef22683",
    ),
    "hardware/xiaomi": (
        "LineageOS/android_hardware_xiaomi",
        "1ad18efb60bc5c3cf794213fb29822837e38c1f8",
    ),
}


class ManifestTest(unittest.TestCase):
    def test_exact_projects_and_full_sha_pins(self):
        self.assertTrue(MANIFEST.is_file(), "candidate manifest is missing")
        root = ET.parse(MANIFEST).getroot()
        projects = {
            item.attrib["path"]: (item.attrib["name"], item.attrib["revision"])
            for item in root.findall("project")
        }
        self.assertEqual(EXPECTED, projects)
        for _, revision in projects.values():
            self.assertRegex(revision, re.compile(r"^[0-9a-f]{40}$"))

    def test_dedicated_github_remote_is_https_and_collision_free(self):
        self.assertTrue(MANIFEST.is_file(), "candidate manifest is missing")
        root = ET.parse(MANIFEST).getroot()
        remote = root.find("remote[@name='flowerbed-github']")
        self.assertIsNotNone(remote)
        self.assertEqual("https://github.com/", remote.attrib["fetch"])
        self.assertIsNone(root.find("remote[@name='github']"))
        self.assertTrue(
            all(
                project.attrib["remote"] == "flowerbed-github"
                for project in root.findall("project")
            )
        )


if __name__ == "__main__":
    unittest.main()
