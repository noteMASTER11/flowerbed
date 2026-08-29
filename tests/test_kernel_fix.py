from hashlib import sha256
import json
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
PATCH = ROOT / "patches/android_kernel_xiaomi_mt6781/0001-mdpm-cfi-function-pointer-signature.patch"
APPLIER = ROOT / "scripts/ubuntu/apply_patches.sh"
RECORD = ROOT / "sources/kernel-fix.json"
GIT_ATTRIBUTES = ROOT / ".gitattributes"
KERNEL_HEADER = Path(
    "drivers/misc/mediatek/base/power/include/mdpm_v2/mt6781/mtk_mdpm_platform.h"
)
PRE_FIX_BOOT_SHA256 = "9356e7d53016e8a6cf22267abe75b06d50dfeb8d9df90ba99e8e449c3e4544db"
FIXED_BOOT_SHA256 = "afcc938905b241053d3d34d5c9f95a8e2d8e706a67d13a493b52ee502676c0a9"
VERIFIED_PACKAGE_PATCH_SHA256 = "f7b629c87f44ea2e7a05cc56e44fa7d890793b8c696875c365fbcd74bf9d5274"


class KernelFixTest(unittest.TestCase):
    def test_patch_applies_and_restores_cfi_compatible_enum_signature(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            header = root / KERNEL_HEADER
            header.parent.mkdir(parents=True)
            header.write_text(
                "struct mdpm_scenario {\n"
                "\tchar scenario_name[MAX_MDPM_NAME_LEN];\n"
                "\tstruct scenario_power_type_t *scenario_power;\n"
                "\tenum tx_rat_type tx_power_rat[MAX_DBM_FUNC_NUM];\n"
                "\tint (*tx_power_func)(u32 *dbm_mem, u32 *old_dbm_mem, unsigned int rat,\n"
                "\t\tunsigned int power_type, struct md_power_status *md_power_s);\n"
                "};\n"
                "\n"
                "#ifdef MD_POWER_UT\n",
                encoding="utf-8",
                newline="\n",
            )
            subprocess.run(["git", "init", "-q"], cwd=root, check=True)
            result = subprocess.run(
                ["git", "apply", "--check", str(PATCH)],
                cwd=root,
                text=True,
                capture_output=True,
            )
            self.assertEqual(0, result.returncode, result.stderr)
            subprocess.run(["git", "apply", str(PATCH)], cwd=root, check=True)
            reverse = subprocess.run(
                ["git", "apply", "--reverse", "--check", str(PATCH)],
                cwd=root,
                text=True,
                capture_output=True,
            )
            self.assertEqual(0, reverse.returncode, reverse.stderr)
            text = header.read_text(encoding="utf-8")
            self.assertIn(
                "enum tx_rat_type rat, enum mdpm_power_type power_type,",
                text,
            )
            self.assertNotIn("unsigned int rat", text)
            self.assertNotIn("unsigned int power_type", text)

    def test_patch_changes_only_the_expected_callback_hunk(self):
        lines = PATCH.read_text(encoding="utf-8").splitlines()
        self.assertEqual(1, sum(line.startswith("diff --git ") for line in lines))
        self.assertEqual(1, sum(line.startswith("@@ ") for line in lines))
        changes = [
            line
            for line in lines
            if line.startswith(("+", "-"))
            and not line.startswith(("+++ ", "--- "))
        ]
        self.assertEqual(
            [
                "-\tint (*tx_power_func)(u32 *dbm_mem, u32 *old_dbm_mem, unsigned int rat,",
                "-\t\tunsigned int power_type, struct md_power_status *md_power_s);",
                "+\tint (*tx_power_func)(u32 *dbm_mem, u32 *old_dbm_mem,",
                "+\t\tenum tx_rat_type rat, enum mdpm_power_type power_type,",
                "+\t\tstruct md_power_status *md_power_s);",
            ],
            changes,
        )

    def test_patch_whitespace_exception_is_limited_to_this_one_patch(self):
        text = GIT_ATTRIBUTES.read_text(encoding="utf-8")
        self.assertNotIn(
            "patches/android_kernel_xiaomi_mt6781/*.patch whitespace=",
            text,
        )
        self.assertIn(
            "patches/android_kernel_xiaomi_mt6781/0001-mdpm-cfi-function-pointer-signature.patch whitespace=",
            text,
        )

    def test_patch_is_applied_after_fleur_identity_patch(self):
        text = APPLIER.read_text(encoding="utf-8")
        identity = text.index("0006-fleur-expose-sku-market-names.patch")
        kernel = text.index("kernel/xiaomi/mt6781|patches/android_kernel_xiaomi_mt6781/")
        self.assertLess(identity, kernel)

    def test_source_record_has_verified_provenance_and_hashes(self):
        record = json.loads(RECORD.read_text(encoding="utf-8"))
        self.assertEqual("kernel/xiaomi/mt6781", record["project"])
        self.assertEqual(str(KERNEL_HEADER), record["file"])
        self.assertEqual("9996b68a1808b38f2f9e7798b26479e721bc2a84", record["base_commit"])
        self.assertEqual(PRE_FIX_BOOT_SHA256, record["rejected_pre_fix_boot_sha256"])
        self.assertEqual(FIXED_BOOT_SHA256, record["hardware_tested_fixed_boot_sha256"])
        self.assertEqual(
            VERIFIED_PACKAGE_PATCH_SHA256,
            record["verified_package_patch_sha256"],
        )
        self.assertTrue(record["cfi_remains_enabled"])
        self.assertIn("function-pointer", record["root_cause"])

    def test_recorded_patch_digest_matches_patch_bytes(self):
        record = json.loads(RECORD.read_text(encoding="utf-8"))
        self.assertEqual(
            sha256(PATCH.read_bytes()).hexdigest(),
            record["patch_sha256"],
        )


if __name__ == "__main__":
    unittest.main()
