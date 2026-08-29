from __future__ import annotations

import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
import uuid
import zipfile


ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "scripts/ubuntu/avb_password_helper.py"


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
avb_vbmeta_vendor_key_path=build/make/target/product/security/testkey.pem
avb_vbmeta_vendor_algorithm=SHA256_RSA4096
'''


def write_target_files(path: Path) -> None:
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("META/apkcerts.txt", APK_CERTS)
        archive.writestr("META/apexkeys.txt", APEX_KEYS)
        archive.writestr("META/misc_info.txt", MISC_INFO)


class FakeRunner:
    def __init__(
        self, *, failure_tool: str | None = None, create_unexpected_entry: bool = False
    ):
        self.calls: list[tuple[tuple[str, ...], str | None, dict[str, str] | None]] = []
        self.failure_tool = failure_tool
        self.create_unexpected_entry = create_unexpected_entry

    def __call__(self, command, *, stdin=None, env=None):
        command = tuple(str(item) for item in command)
        copied_env = None if env is None else dict(env)
        self.calls.append((command, stdin, copied_env))
        if self.failure_tool and Path(command[0]).name == self.failure_tool:
            raise subprocess.CalledProcessError(1, command)

        if "-out" in command:
            output = Path(command[command.index("-out") + 1])
        elif "--output" in command:
            output = Path(command[command.index("--output") + 1])
        else:
            return
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_bytes((Path(command[0]).name + ":public-fixture").encode("ascii"))
        if self.create_unexpected_entry:
            staging = next(
                parent
                for parent in output.parents
                if parent.name.startswith(".keys.staging-")
            )
            (staging / "unexpected").mkdir(exist_ok=True)


class GenerateReleaseKeysTest(unittest.TestCase):
    def setUp(self):
        from scripts.ubuntu.generate_release_keys import (
            KeyGenerationError,
            build_key_plan,
            generate_keyset,
            validate_private_destination,
        )

        self.KeyGenerationError = KeyGenerationError
        self.build_key_plan = build_key_plan
        self.generate_keyset = generate_keyset
        self.validate_private_destination = validate_private_destination

    def private_temp(self):
        return tempfile.TemporaryDirectory(dir="/var/tmp")

    def test_rejects_repository_android_and_windows_mount_destinations(self):
        with self.private_temp() as directory:
            root = Path(directory)
            repo = root / "repo"
            android_root = root / "android"
            repo.mkdir()
            android_root.mkdir()

            with self.assertRaises(self.KeyGenerationError):
                self.validate_private_destination(repo / "keys", repo, android_root)
            with self.assertRaises(self.KeyGenerationError):
                self.validate_private_destination(
                    android_root / "keys", repo, android_root
                )
            with self.assertRaises(self.KeyGenerationError):
                self.validate_private_destination(
                    Path("/mnt/d/keys"), repo, android_root
                )
            with self.assertRaises(self.KeyGenerationError):
                self.validate_private_destination(Path("/tmp/keys"), repo, android_root)

    def test_rejects_non_wsl_ext4_destination(self):
        with self.private_temp() as directory:
            root = Path(directory)
            repo = root / "repo"
            android_root = root / "android"
            repo.mkdir()
            android_root.mkdir()
            with mock.patch(
                "scripts.ubuntu.generate_release_keys._is_wsl",
                return_value=False,
                create=True,
            ):
                with self.assertRaises(self.KeyGenerationError):
                    self.validate_private_destination(
                        root / "private/keys", repo, android_root
                    )

    def test_plan_uses_non_presigned_apex_and_all_discovered_avb_roles(self):
        with self.private_temp() as directory:
            target_files = Path(directory) / "target-files.zip"
            write_target_files(target_files)

            plan = self.build_key_plan(target_files)

        self.assertEqual(plan.android_roles, ("platform", "releasekey"))
        self.assertIn("com.android.art", plan.apex_names)
        self.assertNotIn("com.android.tzdata", plan.apex_names)
        self.assertEqual(
            plan.avb_roles, ("boot", "vbmeta", "vbmeta_system", "vbmeta_vendor")
        )

    def test_blank_or_mismatched_passphrase_fails_before_commands(self):
        with self.private_temp() as directory:
            root = Path(directory)
            target_files = root / "target-files.zip"
            write_target_files(target_files)
            repo = root / "repo"
            android_root = root / "android"
            private_parent = root / "private"
            repo.mkdir()
            android_root.mkdir()
            private_parent.mkdir()

            first = uuid.uuid4().hex
            second = uuid.uuid4().hex
            cases = {
                "blank": ("", ""),
                "mismatch": (first, second),
                "newline": (first + "\n", first + "\n"),
            }
            for name, answers in cases.items():
                with self.subTest(case=name):
                    runner = FakeRunner()
                    prompts = iter(answers)
                    with self.assertRaises(self.KeyGenerationError):
                        self.generate_keyset(
                            target_files,
                            android_root,
                            private_parent / "keys",
                            "/CN=fleur release/",
                            repo_root=repo,
                            runner=runner,
                            getpass_fn=lambda _prompt: next(prompts),
                        )
                    self.assertEqual(runner.calls, [])

    def test_partial_destination_fails_before_commands(self):
        with self.private_temp() as directory:
            root = Path(directory)
            target_files = root / "target-files.zip"
            write_target_files(target_files)
            repo = root / "repo"
            android_root = root / "android"
            keys_dir = root / "private" / "keys"
            repo.mkdir()
            android_root.mkdir()
            keys_dir.mkdir(parents=True)
            (keys_dir / "platform.pk8").write_bytes(b"private")
            runner = FakeRunner()

            with self.assertRaisesRegex(self.KeyGenerationError, "keyset.json"):
                self.generate_keyset(
                    target_files,
                    android_root,
                    keys_dir,
                    "/CN=fleur release/",
                    repo_root=repo,
                    runner=runner,
                    getpass_fn=lambda _prompt: self.fail("must not prompt"),
                )

            self.assertEqual(runner.calls, [])

    def test_abandoned_staging_directory_fails_before_commands(self):
        with self.private_temp() as directory:
            root = Path(directory)
            target_files = root / "target-files.zip"
            write_target_files(target_files)
            repo = root / "repo"
            android_root = root / "android"
            private_parent = root / "private"
            keys_dir = private_parent / "keys"
            repo.mkdir()
            android_root.mkdir()
            private_parent.mkdir(mode=0o700)
            abandoned = private_parent / ".keys.staging-abandoned"
            abandoned.mkdir(mode=0o700)
            (abandoned / "partial.pk8").write_bytes(b"private")
            runner = FakeRunner()

            with self.assertRaisesRegex(self.KeyGenerationError, "staging"):
                self.generate_keyset(
                    target_files,
                    android_root,
                    keys_dir,
                    "/CN=fleur release/",
                    repo_root=repo,
                    runner=runner,
                    getpass_fn=lambda _prompt: self.fail("must not prompt"),
                )

            self.assertEqual(runner.calls, [])

    def test_generates_complete_keyset_atomically_with_restricted_permissions(self):
        with self.private_temp() as directory:
            root = Path(directory)
            target_files = root / "target-files.zip"
            write_target_files(target_files)
            repo = root / "repo"
            android_root = root / "android"
            private_parent = root / "private"
            keys_dir = private_parent / "keys"
            repo.mkdir()
            android_root.mkdir()
            private_parent.mkdir(mode=0o700)
            runner = FakeRunner()
            secret = uuid.uuid4().hex + "!"
            prompts = iter((secret, secret))

            result = self.generate_keyset(
                target_files,
                android_root,
                keys_dir,
                "/CN=fleur release/",
                repo_root=repo,
                runner=runner,
                getpass_fn=lambda _prompt: next(prompts),
            )

            self.assertEqual(result, keys_dir)
            self.assertTrue((keys_dir / "platform.pk8").is_file())
            self.assertTrue((keys_dir / "platform.x509.pem").is_file())
            self.assertTrue((keys_dir / "com.android.art.pem").is_file())
            self.assertTrue((keys_dir / "com.android.art.pk8").is_file())
            self.assertTrue((keys_dir / "com.android.art.x509.pem").is_file())
            self.assertTrue(
                (keys_dir / "public/com.android.art.avbpubkey").is_file()
            )
            self.assertTrue((keys_dir / "avb_boot.pem").is_file())
            self.assertTrue((keys_dir / "public/avb_boot.avbpubkey").is_file())
            self.assertFalse(any(keys_dir.glob("*.raw.pem")))
            self.assertEqual(stat.S_IMODE(keys_dir.stat().st_mode), 0o700)
            self.assertEqual(
                stat.S_IMODE((keys_dir / "public").stat().st_mode), 0o700
            )
            for path in keys_dir.rglob("*"):
                if path.is_file():
                    self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600, path)

            manifest = json.loads((keys_dir / "keyset.json").read_text())
            self.assertEqual(manifest["schema_version"], 1)
            self.assertEqual(
                [entry["name"] for entry in manifest["apex"]],
                ["com.android.art"],
            )
            serialized_manifest = json.dumps(manifest, sort_keys=True)
            self.assertNotIn(secret, serialized_manifest)
            self.assertNotIn(".pk8", serialized_manifest)
            self.assertNotIn(".pem", serialized_manifest)

            argv_text = "\n".join(" ".join(call[0]) for call in runner.calls)
            self.assertNotIn(secret, argv_text)
            protected_calls = [call for call in runner.calls if call[1] is not None]
            self.assertTrue(protected_calls)
            self.assertTrue(all(call[1] == secret + "\n" for call in protected_calls))
            self.assertTrue(
                any(
                    call[0][:3] == ("openssl", "genrsa", "-traditional")
                    and call[0][-1] == "2048"
                    for call in runner.calls
                )
            )
            self.assertTrue(
                any(
                    call[0][:3] == ("openssl", "genrsa", "-traditional")
                    and call[0][-1] == "4096"
                    for call in runner.calls
                )
            )

    def test_command_failure_removes_staging_and_does_not_publish_destination(self):
        with self.private_temp() as directory:
            root = Path(directory)
            target_files = root / "target-files.zip"
            write_target_files(target_files)
            repo = root / "repo"
            android_root = root / "android"
            private_parent = root / "private"
            keys_dir = private_parent / "keys"
            repo.mkdir()
            android_root.mkdir()
            private_parent.mkdir(mode=0o700)
            runner = FakeRunner(failure_tool="openssl")
            secret = uuid.uuid4().hex

            with self.assertRaises(self.KeyGenerationError):
                self.generate_keyset(
                    target_files,
                    android_root,
                    keys_dir,
                    "/CN=fleur release/",
                    repo_root=repo,
                    runner=runner,
                    getpass_fn=lambda _prompt: secret,
                )

            self.assertFalse(keys_dir.exists())
            self.assertEqual(list(private_parent.glob(".keys.staging-*")), [])

    def test_unexpected_staging_entry_prevents_publication(self):
        with self.private_temp() as directory:
            root = Path(directory)
            target_files = root / "target-files.zip"
            write_target_files(target_files)
            repo = root / "repo"
            android_root = root / "android"
            private_parent = root / "private"
            keys_dir = private_parent / "keys"
            repo.mkdir()
            android_root.mkdir()
            private_parent.mkdir(mode=0o700)
            runner = FakeRunner(create_unexpected_entry=True)
            secret = uuid.uuid4().hex

            with self.assertRaises(self.KeyGenerationError):
                self.generate_keyset(
                    target_files,
                    android_root,
                    keys_dir,
                    "/CN=fleur release/",
                    repo_root=repo,
                    runner=runner,
                    getpass_fn=lambda _prompt: secret,
                )

            self.assertFalse(keys_dir.exists())


class PasswordHelperTest(unittest.TestCase):
    def setUp(self):
        from scripts.ubuntu.avb_password_helper import (
            PasswordLookupError,
            lookup_password,
        )

        self.PasswordLookupError = PasswordLookupError
        self.lookup_password = lookup_password

    def write_passwords(self, path: Path, text: str, mode: int = 0o600) -> None:
        path.write_text(text, encoding="utf-8")
        path.chmod(mode)

    def run_helper(self, password_file: Path, requested: str):
        environment = os.environ.copy()
        environment["TMP__KEY_FILE_NAME"] = requested
        return subprocess.run(
            [sys.executable, str(HELPER), str(password_file)],
            cwd=ROOT,
            env=environment,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

    def test_helper_outputs_only_exact_requested_entry(self):
        with tempfile.TemporaryDirectory() as directory:
            password_file = Path(directory) / "passwords"
            wanted = uuid.uuid4().hex
            unrelated = uuid.uuid4().hex
            self.write_passwords(
                password_file,
                f"/secure/key.pem={wanted}\n/secure/key.pem.other={unrelated}\n",
            )

            result = self.run_helper(password_file, "/secure/key.pem")

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, wanted + "\n")
            self.assertNotIn(unrelated, result.stdout + result.stderr)

    def test_helper_rejects_missing_duplicate_and_malformed_entries_without_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            secret = uuid.uuid4().hex
            fixtures = {
                "missing": f"/secure/other.pem={secret}\n",
                "duplicate": f"/secure/key.pem={secret}\n/secure/key.pem={secret}\n",
                "malformed": f"/secure/key.pem={secret}\nnot-an-entry\n",
            }
            for name, content in fixtures.items():
                with self.subTest(name=name):
                    password_file = root / name
                    self.write_passwords(password_file, content)
                    result = self.run_helper(password_file, "/secure/key.pem")
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual(result.stdout, "")
                    self.assertNotIn(secret, result.stderr)

    def test_helper_rejects_symlink_and_overly_permissive_file(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target"
            link = root / "link"
            secret = uuid.uuid4().hex
            self.write_passwords(target, f"/secure/key.pem={secret}\n")
            link.symlink_to(target)

            with self.assertRaises(self.PasswordLookupError):
                self.lookup_password(link, "/secure/key.pem")

            target.chmod(0o640)
            with self.assertRaises(self.PasswordLookupError):
                self.lookup_password(target, "/secure/key.pem")

            with self.assertRaises(self.PasswordLookupError):
                self.lookup_password(root / "missing", "/secure/key.pem")


if __name__ == "__main__":
    unittest.main()
