from __future__ import annotations

import hashlib
import io
import json
from contextlib import redirect_stdout
from pathlib import Path
import subprocess
import struct
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
            "rejected_pre_fix_boot_sha256": "0" * 64,
            "rejected_pre_fix_boot_content_sha256": "1" * 64,
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
            finalized = build_provenance.finalize_build_provenance(
                prebuild, target, final,
                kernel_root=kernel, policy=policy, patch=patch,
                application_script=script,
            )
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
                build_provenance.finalize_build_provenance(
                    prebuild, target, final,
                    kernel_root=kernel, policy=policy, patch=patch,
                    application_script=script,
                )

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
            build_provenance.finalize_build_provenance(
                prebuild, target, final,
                kernel_root=kernel, policy=policy, patch=patch,
                application_script=script,
            )
            value = json.loads(final.read_text(encoding="utf-8"))
            value["pre_build"]["application_evidence_sha256"] = "0" * 64
            final.chmod(0o644)
            final.write_text(json.dumps(value), encoding="utf-8")
            with self.assertRaisesRegex(build_provenance.BuildProvenanceError, "application evidence"):
                build_provenance.validate_final_build_provenance(final, target, policy, patch, script)

    def test_finalize_rechecks_live_kernel_and_rejects_revert_or_mutation(self):
        cases = {
            "revert": "unapplied",
            "extra-change": "post-build",
            "patch": "kernel patch differs",
            "script": "application script differs",
            "head": "base commit differs",
        }
        for mutation, expected_error in cases.items():
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                kernel, patch, script, policy = self._fixture(root)
                subprocess.run(("git", "apply", patch), cwd=kernel, check=True)
                prebuild = root / "prebuild.json"
                build_provenance.create_pre_build_provenance(
                    kernel, policy, patch, script, prebuild,
                    timestamp="2026-08-29T00:00:00Z", nonce="c" * 64,
                )
                source = kernel / policy["file"]
                if mutation == "revert":
                    subprocess.run(("git", "apply", "--reverse", patch), cwd=kernel, check=True)
                elif mutation == "extra-change":
                    source.write_text(source.read_text(encoding="utf-8") + "extra\n", encoding="utf-8")
                elif mutation == "patch":
                    patch.write_bytes(patch.read_bytes() + b"\n")
                elif mutation == "script":
                    script.write_text(
                        script.read_text(encoding="utf-8") + "# changed\n",
                        encoding="utf-8",
                    )
                else:
                    unrelated = kernel / "unrelated.txt"
                    unrelated.write_text("new commit\n", encoding="utf-8")
                    subprocess.run(("git", "add", "unrelated.txt"), cwd=kernel, check=True)
                    subprocess.run(("git", "commit", "-qm", "unrelated"), cwd=kernel, check=True)
                target = root / "lineage_fleur-target_files.zip"
                with zipfile.ZipFile(target, "w") as archive:
                    archive.writestr("IMAGES/boot.img", b"fixed")
                with self.assertRaisesRegex(
                    build_provenance.BuildProvenanceError,
                    expected_error,
                ):
                    build_provenance.finalize_build_provenance(
                        prebuild, target, root / "final.json",
                        kernel_root=kernel, policy=policy, patch=patch,
                        application_script=script,
                    )

    def test_finalize_rejects_non_exact_prebuild_schema(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            kernel, patch, script, policy = self._fixture(root)
            subprocess.run(("git", "apply", patch), cwd=kernel, check=True)
            prebuild = root / "prebuild.json"
            build_provenance.create_pre_build_provenance(
                kernel, policy, patch, script, prebuild,
                timestamp="2026-08-29T00:00:00Z", nonce="d" * 64,
            )
            value = json.loads(prebuild.read_text(encoding="utf-8"))
            value["unexpected"] = True
            prebuild.chmod(0o644)
            prebuild.write_text(json.dumps(value), encoding="utf-8")
            target = root / "lineage_fleur-target_files.zip"
            with zipfile.ZipFile(target, "w") as archive:
                archive.writestr("IMAGES/boot.img", b"fixed")
            with self.assertRaisesRegex(
                build_provenance.BuildProvenanceError, "pre-build.*exact"
            ):
                build_provenance.finalize_build_provenance(
                    prebuild, target, root / "final.json",
                    kernel_root=kernel, policy=policy, patch=patch,
                    application_script=script,
                )

    def test_finalize_rejects_pre_fix_raw_and_normalized_boot_identities(self):
        cases = {
            "raw": b"known-pre-fix-raw",
            "normalized": b"known-pre-fix-content" + struct.pack(
                ">4sIIQQQ28s",
                b"AVBf", 1, 0, len(b"known-pre-fix-content"), 0, 0, b"\0" * 28,
            ),
        }
        for name, boot in cases.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                kernel, patch, script, policy = self._fixture(root)
                subprocess.run(("git", "apply", patch), cwd=kernel, check=True)
                if name == "raw":
                    policy["rejected_pre_fix_boot_sha256"] = hashlib.sha256(boot).hexdigest()
                    policy["rejected_pre_fix_boot_content_sha256"] = "0" * 64
                else:
                    policy["rejected_pre_fix_boot_sha256"] = "0" * 64
                    policy["rejected_pre_fix_boot_content_sha256"] = hashlib.sha256(
                        b"known-pre-fix-content"
                    ).hexdigest()
                prebuild = root / "prebuild.json"
                build_provenance.create_pre_build_provenance(
                    kernel, policy, patch, script, prebuild,
                    timestamp="2026-08-29T00:00:00Z", nonce="e" * 64,
                )
                target = root / "lineage_fleur-target_files.zip"
                with zipfile.ZipFile(target, "w") as archive:
                    archive.writestr("IMAGES/boot.img", boot)
                with self.assertRaisesRegex(
                    build_provenance.BuildProvenanceError, "pre-fix boot",
                ):
                    build_provenance.finalize_build_provenance(
                        prebuild, target, root / "final.json",
                        kernel_root=kernel, policy=policy, patch=patch,
                        application_script=script,
                    )
