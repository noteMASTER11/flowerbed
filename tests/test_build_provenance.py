from __future__ import annotations

import hashlib
import io
import json
from contextlib import redirect_stdout
from pathlib import Path
import subprocess
import tempfile
import unittest
import zipfile

from scripts.ubuntu import build_provenance


class BuildProvenanceTest(unittest.TestCase):
    def _fixture(self, root: Path):
        kernel = root / "kernel"
        kernel.mkdir()
        source = kernel / "drivers/example.c"
        source.parent.mkdir()
        source.write_text("old\n", encoding="utf-8")
        for command in (("git", "init", "-q"), ("git", "config", "user.email", "test@example.invalid"), ("git", "config", "user.name", "Test"), ("git", "add", "."), ("git", "commit", "-qm", "base")):
            subprocess.run(command, cwd=kernel, check=True)
        base = subprocess.check_output(("git", "rev-parse", "HEAD"), cwd=kernel, text=True).strip()
        source.write_text("new\n", encoding="utf-8")
        patch = root / "fix.patch"
        patch.write_bytes(subprocess.check_output(("git", "diff", "--binary"), cwd=kernel))
        subprocess.run(("git", "checkout", "--", "drivers/example.c"), cwd=kernel, check=True)
        script = root / "apply.sh"
        script.write_text('PATCHES=("kernel/xiaomi/mt6781|fix.patch")\n', encoding="utf-8")
        policy = {
            "project": "kernel/xiaomi/mt6781", "file": "drivers/example.c", "base_commit": base,
            "patch_sha256": build_provenance.sha256_file(patch),
            "application_script": "scripts/ubuntu/apply_patches.sh",
            "application_script_sha256": build_provenance.sha256_file(script),
        }
        return kernel, patch, script, policy

    def test_prebuild_rejects_registered_but_unapplied_patch_then_finalizes_once(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            kernel, patch, script, policy = self._fixture(root)
            prebuild = root / "prebuild.json"
            with self.assertRaisesRegex(build_provenance.BuildProvenanceError, "unapplied"):
                build_provenance.create_pre_build_provenance(kernel, policy, patch, script, prebuild, timestamp="2026-08-29T00:00:00Z", nonce="a" * 64)
            subprocess.run(("git", "apply", patch), cwd=kernel, check=True)
            record = build_provenance.create_pre_build_provenance(kernel, policy, patch, script, prebuild, timestamp="2026-08-29T00:00:00Z", nonce="a" * 64)
            self.assertFalse(record["pre_build"]["forward_applicable"])
            self.assertTrue(record["pre_build"]["reverse_applicable"])
            target = root / "lineage_fleur-target_files.zip"
            with zipfile.ZipFile(target, "w") as archive:
                archive.writestr("IMAGES/boot.img", b"fixed-boot")
            final = root / "final.json"
            finalized = build_provenance.finalize_build_provenance(prebuild, target, final)
            self.assertEqual("finalized", finalized["state"])
            self.assertEqual(hashlib.sha256(b"fixed-boot").hexdigest(), finalized["unsigned_target_files"]["boot_raw_sha256"])
            build_provenance.validate_final_build_provenance(final, target, policy, patch, script)
            policy_path = root / "policy.json"
            policy_path.write_text(json.dumps(policy), encoding="utf-8")
            with redirect_stdout(io.StringIO()):
                self.assertEqual(
                    0,
                    build_provenance.main([
                        "validate", "--provenance", str(final),
                        "--unsigned-target-files", str(target),
                        "--kernel-policy", str(policy_path),
                        "--patch", str(patch),
                        "--application-script", str(script),
                    ]),
                )
            with self.assertRaisesRegex(build_provenance.BuildProvenanceError, "exists"):
                build_provenance.finalize_build_provenance(prebuild, target, final)

    def test_final_validation_rejects_wrong_application_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            kernel, patch, script, policy = self._fixture(root)
            subprocess.run(("git", "apply", patch), cwd=kernel, check=True)
            prebuild = root / "prebuild.json"
            build_provenance.create_pre_build_provenance(kernel, policy, patch, script, prebuild, timestamp="2026-08-29T00:00:00Z", nonce="b" * 64)
            target = root / "lineage_fleur-target_files.zip"
            with zipfile.ZipFile(target, "w") as archive:
                archive.writestr("IMAGES/boot.img", b"fixed")
            final = root / "final.json"
            build_provenance.finalize_build_provenance(prebuild, target, final)
            value = json.loads(final.read_text(encoding="utf-8"))
            value["pre_build"]["application_evidence_sha256"] = "0" * 64
            final.chmod(0o644)
            final.write_text(json.dumps(value), encoding="utf-8")
            with self.assertRaisesRegex(build_provenance.BuildProvenanceError, "application evidence"):
                build_provenance.validate_final_build_provenance(final, target, policy, patch, script)
