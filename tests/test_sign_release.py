from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
import uuid
import zipfile


ROOT = Path(__file__).resolve().parents[1]
SIGNING_HELPER = ROOT / "scripts/ubuntu/avb_signing_helper.py"

APK_CERTS = '''\
name="framework-res.apk" certificate="build/make/target/product/security/platform.x509.pem" private_key="build/make/target/product/security/platform.pk8"
name="Settings.apk" certificate="vendor/example/security/releasekey.x509.pem" private_key="vendor/example/security/releasekey.pk8"
'''

APEX_KEYS = '''\
name="com.android.art.apex" public_key="build/make/target/product/security/com.android.art.avbpubkey" private_key="build/make/target/product/security/com.android.art.pem" container_certificate="build/make/target/product/security/platform.x509.pem" container_private_key="build/make/target/product/security/platform.pk8" partition="system"
name="com.android.tzdata.apex" public_key="PRESIGNED" private_key="PRESIGNED" container_certificate="PRESIGNED" container_private_key="PRESIGNED" partition="system"
'''

MISC_INFO = '''\
ab_update=true
virtual_ab=true
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


def digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def file_digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_fake_keyset(keys_dir: Path, secret: str) -> None:
    keys_dir.mkdir(mode=0o700)
    public_dir = keys_dir / "public"
    public_dir.mkdir(mode=0o700)
    android = ("platform", "releasekey")
    apex = ("com.android.art",)
    avb = ("avb_boot", "avb_vbmeta", "avb_vbmeta_system", "avb_vbmeta_vendor")
    for role in android:
        (keys_dir / f"{role}.pk8").write_bytes((role + "-pk8").encode("ascii"))
        (keys_dir / f"{role}.x509.pem").write_text(role + "-certificate\n", encoding="utf-8")
    for role in apex:
        (keys_dir / f"{role}.pem").write_bytes((role + "-encrypted").encode("ascii"))
        (keys_dir / f"{role}.pk8").write_bytes((role + "-pk8").encode("ascii"))
        (keys_dir / f"{role}.x509.pem").write_text(role + "-certificate\n", encoding="utf-8")
        (public_dir / f"{role}.avbpubkey").write_bytes((role + "-avb-public").encode("ascii"))
    for role in avb:
        (keys_dir / f"{role}.pem").write_bytes((role + "-encrypted").encode("ascii"))
        (public_dir / f"{role}.avbpubkey").write_bytes((role + "-avb-public").encode("ascii"))
    private_files = [
        *(keys_dir / role for role in android),
        *(path for role in apex for path in (keys_dir / role, keys_dir / f"{role}.pem")),
        *(keys_dir / f"{role}.pem" for role in avb),
    ]
    password_file = keys_dir / "passwords"
    password_file.write_text(
        "".join(f"[[[ {secret} ]]] {path}\n" for path in sorted(private_files)),
        encoding="utf-8",
    )
    manifest = {
        "schema_version": 1,
        "android": [
            {
                "name": role,
                "certificate_sha256": file_digest(keys_dir / f"{role}.x509.pem"),
            }
            for role in android
        ],
        "apex": [
            {
                "name": role,
                "certificate_sha256": file_digest(keys_dir / f"{role}.x509.pem"),
                "avb_public_key_sha256": file_digest(public_dir / f"{role}.avbpubkey"),
            }
            for role in apex
        ],
        "avb": [
            {
                "name": role,
                "partition": role.removeprefix("avb_"),
                "avb_public_key_sha256": file_digest(public_dir / f"{role}.avbpubkey"),
            }
            for role in avb
        ],
    }
    (keys_dir / "keyset.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    for path in keys_dir.rglob("*"):
        if path.is_file():
            path.chmod(0o600)


def write_fake_host_tools(android_root: Path) -> None:
    tools = android_root / "out/host/linux-x86/bin"
    tools.mkdir(parents=True)
    for name in ("sign_target_files_apks", "ota_from_target_files", "img_from_target_files"):
        path = tools / name
        path.write_text("#!/bin/sh\nexit 99\n", encoding="utf-8")
        path.chmod(0o755)


class FakeCryptoRunner:
    def __init__(self, secret: str):
        self.secret_digest = digest(secret)
        self.calls = []

    def __call__(self, command, *, input_data, pass_fds):
        rendered = "\0".join(command)
        self.assert_secret_absent(rendered)
        password_arg = next(item for item in command if item.startswith("fd:"))
        password_fd = int(password_arg.removeprefix("fd:"))
        observed = os.pread(password_fd, 4096, 0).decode("utf-8").rstrip("\n")
        if digest(observed) != self.secret_digest:
            raise AssertionError("wrong password selected")
        output_fd = int(command[command.index("-out") + 1].rsplit("/", 1)[1])
        os.write(output_fd, b"-----BEGIN PUBLIC KEY-----\nfixture\n-----END PUBLIC KEY-----\n")
        self.calls.append(tuple(command))
        return b""

    def assert_secret_absent(self, rendered: str) -> None:
        for offset in range(max(0, len(rendered) - 64) + 1):
            if digest(rendered[offset : offset + 64]) == self.secret_digest:
                raise AssertionError("secret exposed in command")


class FakeReleaseRunner:
    def __init__(self, final_output: Path, *, fail_tool=None, legacy_ota=False):
        self.final_output = final_output
        self.fail_tool = fail_tool
        self.legacy_ota = legacy_ota
        self.calls = []

    def __call__(self, command, *, env):
        command = tuple(str(item) for item in command)
        tool = Path(command[0]).name
        if self.final_output.exists():
            raise AssertionError("final output published before all commands completed")
        self.calls.append((command, dict(env)))
        if tool == self.fail_tool:
            raise subprocess.CalledProcessError(7, command)
        output = Path(command[-1])
        output.parent.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(output, "w") as archive:
            if tool == "sign_target_files_apks":
                archive.writestr("META/misc_info.txt", MISC_INFO)
            elif tool == "ota_from_target_files":
                archive.writestr(
                    "META-INF/com/android/metadata",
                    "ota-type=AB\npre-device=fleur\n",
                )
                if not self.legacy_ota:
                    archive.writestr("payload.bin", b"payload-fixture")
            elif tool == "img_from_target_files":
                archive.writestr("android-info.txt", "require product=fleur\n")


class ReleaseOrchestrationTest(unittest.TestCase):
    def setUp(self):
        from scripts.ubuntu.sign_release import (
            ReleaseSigningError,
            SigningPaths,
            sign_release,
        )

        self.ReleaseSigningError = ReleaseSigningError
        self.SigningPaths = SigningPaths
        self.sign_release = sign_release

    def make_fixture(self, root: Path):
        target_files = root / "unsigned-target-files.zip"
        android_root = root / "android"
        keys_dir = root / "keys"
        output_dir = root / "20260829T123456Z"
        secret = uuid.uuid4().hex + uuid.uuid4().hex
        write_target_files(target_files)
        write_fake_host_tools(android_root)
        write_fake_keyset(keys_dir, secret)
        paths = self.SigningPaths(target_files, android_root, keys_dir, output_dir)
        return paths, secret

    def test_publishes_complete_release_atomically_with_sanitized_report(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            paths, secret = self.make_fixture(root)
            tool_runner = FakeReleaseRunner(paths.output_dir)
            crypto_runner = FakeCryptoRunner(secret)
            moments = iter(("2026-08-29T12:34:56Z", "2026-08-29T12:35:56Z"))

            published = self.sign_release(
                paths,
                runner=tool_runner,
                openssl_runner=crypto_runner,
                timestamp=lambda: next(moments),
            )

            self.assertEqual(published, paths.output_dir)
            self.assertTrue(paths.signed_target_files.is_file())
            self.assertTrue(paths.ota_zip.is_file())
            self.assertTrue(paths.fastboot_zip.is_file())
            self.assertTrue(paths.report.is_file())
            self.assertTrue(paths.checksums.is_file())
            self.assertTrue(paths.public_keys_dir.is_dir())
            self.assertFalse(any(path.name == ".signing-runtime" for path in paths.output_dir.rglob("*")))
            public_names = {path.name for path in paths.public_keys_dir.iterdir()}
            self.assertIn("avb_boot.avbpubkey", public_names)
            self.assertIn("avb_boot.public.pem", public_names)
            self.assertIn("platform.x509.pem", public_names)
            self.assertFalse(any(name.endswith(".pk8") for name in public_names))
            self.assertFalse(any(name.endswith(".pem") and not name.endswith((".x509.pem", ".public.pem")) for name in public_names))

            report_text = paths.report.read_text(encoding="utf-8")
            report = json.loads(report_text)
            self.assertNotIn(secret, report_text)
            self.assertNotIn(str(paths.keys_dir), report_text)
            self.assertEqual(report["build_id"], "20260829T123456Z")
            self.assertEqual(report["build_properties"], {"ab_update": True, "virtual_ab": True})
            self.assertEqual(report["timestamps"]["started_at"], "2026-08-29T12:34:56Z")
            self.assertEqual(report["timestamps"]["completed_at"], "2026-08-29T12:35:56Z")
            self.assertEqual(
                report["input"]["sha256"],
                file_digest(paths.target_files),
            )
            self.assertEqual(set(report["outputs"]), {paths.signed_target_files.name, paths.ota_zip.name, paths.fastboot_zip.name})
            self.assertTrue(report["public_fingerprints"])
            self.assertTrue(all(name.startswith("-") for name in report["sanitized_options"]["sign_target_files_apks"]))
            sums = paths.checksums.read_text(encoding="utf-8")
            self.assertIn(paths.ota_zip.name, sums)
            self.assertIn("public-keys/avb_boot.public.pem", sums)
            self.assertIn("signing-report.json", sums)

            self.assertEqual(len(crypto_runner.calls), 5)
            self.assertEqual([Path(call[0][0]).name for call in tool_runner.calls], ["sign_target_files_apks", "ota_from_target_files", "img_from_target_files"])
            sign_env = tool_runner.calls[0][1]
            ota_env = tool_runner.calls[1][1]
            img_env = tool_runner.calls[2][1]
            self.assertIn("ANDROID_PW_FILE", sign_env)
            self.assertIn("ANDROID_PW_FILE", ota_env)
            self.assertNotIn("ANDROID_PW_FILE", img_env)
            self.assertTrue(all("ANDROID_SECURE_STORAGE_CMD" not in env for _, env in tool_runner.calls))

    def test_existing_output_fails_before_crypto_or_release_commands(self):
        with tempfile.TemporaryDirectory() as directory:
            paths, _secret = self.make_fixture(Path(directory))
            paths.output_dir.mkdir()
            runner = FakeReleaseRunner(paths.output_dir)

            with self.assertRaisesRegex(self.ReleaseSigningError, "exists"):
                self.sign_release(
                    paths,
                    runner=runner,
                    openssl_runner=lambda *_args, **_kwargs: self.fail("crypto must not run"),
                )

            self.assertEqual(runner.calls, [])

    def test_existing_output_fails_before_password_file_is_read(self):
        with tempfile.TemporaryDirectory() as directory:
            paths, _secret = self.make_fixture(Path(directory))
            paths.output_dir.mkdir()
            (paths.keys_dir / "passwords").write_text("malformed-secret-state\n", encoding="utf-8")
            (paths.keys_dir / "passwords").chmod(0o600)

            with self.assertRaisesRegex(self.ReleaseSigningError, "output directory already exists"):
                self.sign_release(paths)

    def test_rejects_non_private_key_directory_before_crypto(self):
        with tempfile.TemporaryDirectory() as directory:
            paths, _secret = self.make_fixture(Path(directory))
            paths.keys_dir.chmod(0o750)

            with self.assertRaisesRegex(self.ReleaseSigningError, "0700"):
                self.sign_release(
                    paths,
                    runner=lambda *_args, **_kwargs: self.fail("release tool must not run"),
                    openssl_runner=lambda *_args, **_kwargs: self.fail("crypto must not run"),
                )

    def test_crypto_failure_is_sanitized_and_removes_staging(self):
        from scripts.ubuntu.avb_signing_helper import AvbSigningError

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            paths, _secret = self.make_fixture(root)

            def fail_crypto(*_args, **_kwargs):
                raise AvbSigningError("sensitive OpenSSL detail")

            with self.assertRaisesRegex(self.ReleaseSigningError, "public key") as caught:
                self.sign_release(
                    paths,
                    runner=lambda *_args, **_kwargs: self.fail("release tool must not run"),
                    openssl_runner=fail_crypto,
                )

            self.assertNotIn("sensitive", str(caught.exception))
            self.assertFalse(paths.output_dir.exists())
            self.assertEqual(list(root.glob(".20260829T123456Z.staging-*")), [])

    def test_dry_run_validates_keyset_without_creating_output(self):
        from scripts.ubuntu.sign_release import main

        with tempfile.TemporaryDirectory() as directory:
            paths, _secret = self.make_fixture(Path(directory))
            arguments = [
                "--target-files",
                str(paths.target_files),
                "--android-root",
                str(paths.android_root),
                "--keys-dir",
                str(paths.keys_dir),
                "--output-dir",
                str(paths.output_dir),
                "--dry-run",
            ]
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                self.assertEqual(main(arguments), 0)
            self.assertIn("dry-run", stdout.getvalue())
            self.assertFalse(paths.output_dir.exists())
            self.assertEqual(list(paths.output_dir.parent.glob(".20260829T123456Z.staging-*")), [])

            (paths.keys_dir / "keyset.json").unlink()
            stderr = io.StringIO()
            with redirect_stderr(stderr):
                self.assertEqual(main(arguments), 1)
            self.assertIn("key", stderr.getvalue())

    def test_command_failure_removes_staging_and_publishes_nothing(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            paths, secret = self.make_fixture(root)
            runner = FakeReleaseRunner(paths.output_dir, fail_tool="ota_from_target_files")

            with self.assertRaisesRegex(self.ReleaseSigningError, "ota_from_target_files"):
                self.sign_release(
                    paths,
                    runner=runner,
                    openssl_runner=FakeCryptoRunner(secret),
                )

            self.assertFalse(paths.output_dir.exists())
            self.assertEqual(list(root.glob(".20260829T123456Z.staging-*")), [])

    def test_rejects_legacy_non_payload_ota_without_publication(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            paths, secret = self.make_fixture(root)
            runner = FakeReleaseRunner(paths.output_dir, legacy_ota=True)

            with self.assertRaisesRegex(self.ReleaseSigningError, "payload.bin"):
                self.sign_release(
                    paths,
                    runner=runner,
                    openssl_runner=FakeCryptoRunner(secret),
                )

            self.assertFalse(paths.output_dir.exists())
            self.assertEqual(list(root.glob(".20260829T123456Z.staging-*")), [])


class SigningCommandTest(unittest.TestCase):
    def setUp(self):
        from scripts.ubuntu.sign_release import (
            ReleaseSigningError,
            SigningPaths,
            build_child_environment,
            build_signing_commands,
        )
        from scripts.ubuntu.signing_metadata import load_signing_inventory

        self.ReleaseSigningError = ReleaseSigningError
        self.SigningPaths = SigningPaths
        self.build_child_environment = build_child_environment
        self.build_signing_commands = build_signing_commands
        self.load_signing_inventory = load_signing_inventory

    def test_builds_all_metadata_derived_commands_without_secret_transport(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target_files = root / "unsigned.zip"
            write_target_files(target_files)
            paths = self.SigningPaths(
                target_files=target_files,
                android_root=root / "android",
                keys_dir=root / "keys",
                output_dir=root / "20260829T123456Z",
            )
            public_pems = paths.output_dir / ".signing-runtime/public-pem"
            inventory = self.load_signing_inventory(target_files)

            commands = self.build_signing_commands(
                inventory,
                paths,
                signing_helper=SIGNING_HELPER,
                public_key_dir=public_pems,
            )
            environment = self.build_child_environment(paths, root / "helper.json")

        sign = list(commands.sign_target_files)
        self.assertIn("--tag_changes", sign)
        self.assertIn("-test-keys,+release-keys", sign)
        self.assertIn("--avb_boot_key", sign)
        self.assertIn(str(public_pems / "avb_boot.public.pem"), sign)
        self.assertIn("--avb_boot_extra_args", sign)
        self.assertIn(f"--signing_helper {SIGNING_HELPER}", sign)
        self.assertIn(
            "build/make/target/product/security/platform="
            + str(paths.keys_dir / "platform"),
            sign,
        )
        self.assertIn(
            "vendor/example/security/releasekey="
            + str(paths.keys_dir / "releasekey"),
            sign,
        )
        self.assertIn(
            "com.android.art.apex=" + str(paths.keys_dir / "com.android.art"),
            sign,
        )
        self.assertIn(
            "com.android.art.apex="
            + str(public_pems / "com.android.art.public.pem"),
            sign,
        )
        self.assertNotIn("com.android.tzdata.apex", "\n".join(sign))
        self.assertEqual(
            commands.ota_from_target_files[-2:],
            (str(paths.signed_target_files), str(paths.ota_zip)),
        )
        self.assertIn("--block", commands.ota_from_target_files)
        self.assertIn("--backup=true", commands.ota_from_target_files)
        self.assertEqual(
            commands.img_from_target_files[-2:],
            (str(paths.signed_target_files), str(paths.fastboot_zip)),
        )
        self.assertEqual(environment["ANDROID_PW_FILE"], str(paths.keys_dir / "passwords"))
        self.assertNotIn("ANDROID_SECURE_STORAGE_CMD", environment)
        self.assertEqual(environment["FLEUR_AVB_SIGNING_CONFIG"], str(root / "helper.json"))
        serialized = json.dumps(
            {
                "commands": [
                    commands.sign_target_files,
                    commands.ota_from_target_files,
                    commands.img_from_target_files,
                ],
                "environment": environment,
            },
            sort_keys=True,
        )
        self.assertNotIn("[[[", serialized)
        self.assertNotIn("pass:", serialized)

    def test_rejects_generated_role_collisions(self):
        from scripts.ubuntu.signing_metadata import (
            ApexKey,
            ApkCertificate,
            SigningInventory,
        )

        inventory = SigningInventory(
            apk_certificates=(
                ApkCertificate("Example.apk", "source/com.android.art", "source/com.android.art"),
            ),
            apexes=(
                ApexKey(
                    "com.android.art.apex",
                    "source/apex",
                    "source/apex",
                    "source/container",
                    "source/container",
                    "system",
                    False,
                ),
            ),
            avb_keys=(),
            misc_info={"ab_update": "true", "virtual_ab": "true"},
            source_key_stems=frozenset(),
            android_roles=frozenset({"com.android.art"}),
            uses_test_build_tags=True,
        )
        paths = self.SigningPaths(
            Path("/tmp/input.zip"),
            Path("/tmp/android"),
            Path("/tmp/keys"),
            Path("/tmp/20260829T123456Z"),
        )

        with self.assertRaisesRegex(self.ReleaseSigningError, "collid"):
            self.build_signing_commands(
                inventory,
                paths,
                signing_helper=SIGNING_HELPER,
                public_key_dir=Path("/tmp/public-pem"),
            )

    def test_paths_require_utc_build_id_and_exact_artifact_names(self):
        paths = self.SigningPaths(
            Path("/tmp/input.zip"),
            Path("/tmp/android"),
            Path("/tmp/keys"),
            Path("/tmp/20260829T123456Z"),
        )

        self.assertEqual(paths.signed_target_files.name, "lineage_fleur-SIGNED-target_files.zip")
        self.assertEqual(paths.ota_zip.name, "lineage-23.2-20260829T123456Z-SIGNED-fleur.zip")
        self.assertEqual(paths.fastboot_zip.name, "lineage_fleur-SIGNED-img.zip")
        with self.assertRaisesRegex(self.ReleaseSigningError, "UTC"):
            self.SigningPaths(
                Path("/tmp/input.zip"),
                Path("/tmp/android"),
                Path("/tmp/keys"),
                Path("/tmp/not-a-build-id"),
            )
        with self.assertRaisesRegex(self.ReleaseSigningError, "UTC"):
            self.SigningPaths(
                Path("/tmp/input.zip"),
                Path("/tmp/android"),
                Path("/tmp/keys"),
                Path("/tmp/20261340T256199Z"),
            )

    def test_paths_must_be_absolute_for_exact_helper_mappings(self):
        with self.assertRaisesRegex(self.ReleaseSigningError, "absolute"):
            self.SigningPaths(
                Path("input.zip"),
                Path("/tmp/android"),
                Path("/tmp/keys"),
                Path("/tmp/20260829T123456Z"),
            )


class AvbSigningHelperTest(unittest.TestCase):
    def setUp(self):
        from scripts.ubuntu.avb_signing_helper import (
            AvbSigningError,
            export_public_key,
            sign_payload,
        )

        self.AvbSigningError = AvbSigningError
        self.export_public_key = export_public_key
        self.sign_payload = sign_payload

    def test_signs_avb_stdin_with_password_only_on_inherited_fd(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            private_key = root / "avb_boot.pem"
            public_key = root / "public-pem/avb_boot.public.pem"
            password_file = root / "passwords"
            config = root / "helper.json"
            public_key.parent.mkdir()
            private_key.write_text("encrypted-private-fixture", encoding="utf-8")
            public_key.write_text("public-fixture", encoding="utf-8")
            secret = uuid.uuid4().hex
            password_file.write_text(f"[[[ {secret} ]]] {private_key}\n", encoding="utf-8")
            config.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "password_file": str(password_file),
                        "keys": {str(public_key): str(private_key)},
                    }
                ),
                encoding="utf-8",
            )
            for path in (private_key, password_file, config):
                path.chmod(0o600)
            observations = {}

            def runner(command, *, input_data, pass_fds):
                rendered = "\0".join(command)
                self.assertNotIn(secret, rendered)
                self.assertNotIn("pass:", rendered)
                self.assertEqual(input_data, b"padded-hash")
                self.assertEqual(len(pass_fds), 2)
                passin = next(item for item in command if item.startswith("fd:"))
                password_fd = int(passin.removeprefix("fd:"))
                observations["password_digest"] = digest(
                    os.pread(password_fd, 4096, 0).decode("utf-8").rstrip("\n")
                )
                observations["command"] = tuple(command)
                return b"S" * 512

            signature = self.sign_payload(
                config,
                "SHA256_RSA4096",
                public_key,
                b"padded-hash",
                runner=runner,
            )

        self.assertEqual(signature, b"S" * 512)
        self.assertEqual(observations["password_digest"], digest(secret))
        self.assertIn("-passin", observations["command"])
        self.assertTrue(any(item.startswith("/proc/self/fd/") for item in observations["command"]))

    def test_rejects_unknown_public_key_and_algorithm_before_openssl(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            private_key = root / "avb_boot.pem"
            public_key = root / "avb_boot.public.pem"
            password_file = root / "passwords"
            config = root / "helper.json"
            private_key.write_bytes(b"private")
            public_key.write_bytes(b"public")
            password_file.write_text(f"[[[ secret ]]] {private_key}\n", encoding="utf-8")
            config.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "password_file": str(password_file),
                        "keys": {str(public_key): str(private_key)},
                    }
                ),
                encoding="utf-8",
            )
            for path in (private_key, password_file, config):
                path.chmod(0o600)
            runner = lambda *_args, **_kwargs: self.fail("openssl must not run")

            with self.assertRaisesRegex(self.AvbSigningError, "algorithm"):
                self.sign_payload(config, "SHA512_RSA4096", public_key, b"data", runner=runner)
            with self.assertRaisesRegex(self.AvbSigningError, "public key"):
                self.sign_payload(
                    config,
                    "SHA256_RSA4096",
                    root / "other.public.pem",
                    b"data",
                    runner=runner,
                )

    def test_rejects_non_object_helper_config_without_traceback_or_openssl(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            public_key = root / "avb_boot.public.pem"
            config = root / "helper.json"
            public_key.write_bytes(b"public")
            config.write_text("[]\n", encoding="utf-8")
            config.chmod(0o600)

            with self.assertRaisesRegex(self.AvbSigningError, "config"):
                self.sign_payload(
                    config,
                    "SHA256_RSA4096",
                    public_key,
                    b"data",
                    runner=lambda *_args, **_kwargs: self.fail("openssl must not run"),
                )

    def test_exports_public_pem_without_password_in_command_and_without_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            private_key = root / "avb_boot.pem"
            public_key = root / "avb_boot.public.pem"
            password_file = root / "passwords"
            private_key.write_bytes(b"private")
            secret = uuid.uuid4().hex
            password_file.write_text(f"[[[ {secret} ]]] {private_key}\n", encoding="utf-8")
            private_key.chmod(0o600)
            password_file.chmod(0o600)

            def runner(command, *, input_data, pass_fds):
                self.assertIsNone(input_data)
                self.assertNotIn(secret, "\0".join(command))
                output_fd = int(command[command.index("-out") + 1].rsplit("/", 1)[1])
                os.write(output_fd, b"PUBLIC PEM FIXTURE\n")
                return b""

            self.export_public_key(private_key, public_key, password_file, runner=runner)
            self.assertEqual(public_key.read_bytes(), b"PUBLIC PEM FIXTURE\n")
            with self.assertRaisesRegex(self.AvbSigningError, "exists"):
                self.export_public_key(private_key, public_key, password_file, runner=runner)


if __name__ == "__main__":
    unittest.main()
