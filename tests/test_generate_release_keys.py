from __future__ import annotations

from dataclasses import dataclass
import hashlib
import io
import json
import os
from pathlib import Path
import re
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
name="Settings.apk" certificate="build/make/target/product/security/testkey.x509.pem" private_key="build/make/target/product/security/testkey.pk8"
name="CtsCompilationApp.apk" certificate="cts/hostsidetests/compilation/certs/testkey.x509.pem" private_key="cts/hostsidetests/compilation/certs/testkey.pk8"
'''

APEX_KEYS = '''\
name="com.android.art.apex" public_key="build/make/target/product/security/com.android.art.avbpubkey" private_key="build/make/target/product/security/com.android.art.pem" container_certificate="build/make/target/product/security/platform.x509.pem" container_private_key="build/make/target/product/security/platform.pk8" partition="system"
name="com.android.tzdata.apex" public_key="PRESIGNED" private_key="PRESIGNED" container_certificate="PRESIGNED" container_private_key="PRESIGNED" partition="system"
'''

MISC_INFO = '''\
ab_update=true
virtual_ab=true
avb_boot_key_path=build/make/target/product/security/testkey.pem
avb_boot_algorithm=SHA256_RSA4096
avb_vbmeta_key_path=build/make/target/product/security/testkey.pem
avb_vbmeta_algorithm=SHA256_RSA4096
avb_vbmeta_system_key_path=build/make/target/product/security/testkey.pem
avb_vbmeta_system_algorithm=SHA256_RSA4096
avb_vbmeta_vendor_key_path=build/make/target/product/security/testkey.pem
avb_vbmeta_vendor_algorithm=SHA256_RSA4096
'''

SYSTEM_BUILD_PROP = '''\
ro.product.system.device=fleur
ro.system.build.tags=test-keys
ro.build.tags=test-keys
'''


def write_target_files(
    path: Path, *, apkcerts: str = APK_CERTS, misc_info: str = MISC_INFO
) -> None:
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("META/apkcerts.txt", apkcerts)
        archive.writestr("META/apexkeys.txt", APEX_KEYS)
        archive.writestr("META/misc_info.txt", misc_info)
        archive.writestr("META/otakeys.txt", "\n")
        archive.writestr("SYSTEM/build.prop", SYSTEM_BUILD_PROP)


def write_fake_avbtool(android_root: Path) -> Path:
    avbtool = android_root / "out/host/linux-x86/bin/avbtool"
    avbtool.parent.mkdir(parents=True)
    avbtool.write_text("#!/bin/sh\nexit 99\n", encoding="utf-8")
    avbtool.chmod(0o755)
    return avbtool


def digest_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def contains_text_digest(
    value: str, expected_digest: str, expected_length: int
) -> bool:
    if expected_length <= 0 or len(value) < expected_length:
        return False
    return any(
        digest_text(value[offset : offset + expected_length]) == expected_digest
        for offset in range(len(value) - expected_length + 1)
    )


@dataclass(frozen=True)
class RecordedCall:
    command: tuple[str, ...]
    stdin_digest: str | None
    environment: tuple[tuple[str, str], ...]
    pass_fds: tuple[int, ...]
    fd_targets: tuple[tuple[int, str], ...]


class FakeRunner:
    def __init__(
        self,
        *,
        failure_tool: str | None = None,
        create_unexpected_entry: bool = False,
        forbidden_secret: str | None = None,
        raise_error: BaseException | None = None,
        mutate_after_first=None,
        replace_first_output_with_symlink_to: Path | None = None,
        write_outputs_in_child: bool = False,
    ):
        self.calls: list[RecordedCall] = []
        self.failure_tool = failure_tool
        self.create_unexpected_entry = create_unexpected_entry
        self._forbidden_digest = (
            None if forbidden_secret is None else digest_text(forbidden_secret)
        )
        self._forbidden_length = (
            0 if forbidden_secret is None else len(forbidden_secret)
        )
        self.raise_error = raise_error
        self.mutate_after_first = mutate_after_first
        self.replace_first_output_with_symlink_to = replace_first_output_with_symlink_to
        self.write_outputs_in_child = write_outputs_in_child

    def __call__(self, command, *, stdin=None, env=None, pass_fds=()):
        command = tuple(str(item) for item in command)
        environment = tuple(sorted((env or {}).items()))
        if self._forbidden_digest is not None:
            exposed = any(
                contains_text_digest(
                    item, self._forbidden_digest, self._forbidden_length
                )
                for item in command
            )
            exposed = exposed or any(
                contains_text_digest(
                    key, self._forbidden_digest, self._forbidden_length
                )
                or contains_text_digest(
                    value, self._forbidden_digest, self._forbidden_length
                )
                for key, value in environment
            )
            if exposed:
                raise AssertionError("secret exposed outside stdin")
        self.calls.append(
            RecordedCall(
                command=command,
                stdin_digest=None if stdin is None else digest_text(stdin),
                environment=environment,
                pass_fds=tuple(pass_fds),
                fd_targets=tuple(
                    (descriptor, os.readlink(f"/proc/self/fd/{descriptor}"))
                    for descriptor in pass_fds
                ),
            )
        )
        if self.raise_error is not None:
            raise self.raise_error
        if self.failure_tool and Path(command[0]).name == self.failure_tool:
            raise subprocess.CalledProcessError(1, command)

        if "-out" in command:
            output = Path(command[command.index("-out") + 1])
        elif "--output" in command:
            output = Path(command[command.index("--output") + 1])
        else:
            return
        output.parent.mkdir(parents=True, exist_ok=True)
        if (
            len(self.calls) == 1
            and self.replace_first_output_with_symlink_to is not None
        ):
            named_output = output.resolve()
            named_output.unlink()
            named_output.symlink_to(self.replace_first_output_with_symlink_to)
        payload = (Path(command[0]).name + ":public-fixture").encode("ascii")
        if self.write_outputs_in_child:
            subprocess.run(
                [
                    sys.executable,
                    "-c",
                    (
                        "import os,sys; "
                        "fd=os.open(sys.argv[1], os.O_WRONLY|os.O_TRUNC); "
                        "os.write(fd, b'child-public-fixture'); os.close(fd)"
                    ),
                    str(output),
                ],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        else:
            output.write_bytes(payload)
        if self.create_unexpected_entry:
            staging = next(
                parent
                for parent in output.resolve().parents
                if parent.name.startswith(".keys.staging-")
            )
            (staging / "unexpected").mkdir(exist_ok=True)
        if len(self.calls) == 1 and self.mutate_after_first is not None:
            self.mutate_after_first()


class GenerateReleaseKeysTest(unittest.TestCase):
    def setUp(self):
        from scripts.ubuntu.generate_release_keys import (
            KeyGenerationError,
            build_key_plan,
            generate_keyset,
            main,
            validate_private_destination,
        )

        self.KeyGenerationError = KeyGenerationError
        self.build_key_plan = build_key_plan
        self.generate_keyset = generate_keyset
        self.main = main
        self.validate_private_destination = validate_private_destination

    def private_temp(self):
        return tempfile.TemporaryDirectory(dir="/home/administrator")

    def test_fake_runner_keeps_only_redacted_secret_state(self):
        secret = uuid.uuid4().hex
        secret_digest = digest_text(secret)
        runner = FakeRunner(forbidden_secret=secret)

        self.assertFalse("forbidden_secret" in vars(runner))
        self.assertTrue(runner._forbidden_length == len(secret))
        self.assertTrue(runner._forbidden_digest == secret_digest)
        self.assertFalse(
            any(
                isinstance(value, str)
                and contains_text_digest(value, secret_digest, len(secret))
                for value in vars(runner).values()
            )
        )
        with self.assertRaisesRegex(AssertionError, "secret exposed outside stdin"):
            runner(["tool", secret])
        self.assertEqual(len(runner.calls), 0)

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

        self.assertEqual(
            plan.android_roles,
            ("platform", "releasekey", "testkey-f88799ce31c1"),
        )
        self.assertEqual(
            tuple(
                (mapping.source_stem, mapping.destination_role)
                for mapping in plan.android_mappings
            ),
            (
                ("build/make/target/product/security/platform", "platform"),
                ("build/make/target/product/security/testkey", "releasekey"),
                (
                    "cts/hostsidetests/compilation/certs/testkey",
                    "testkey-f88799ce31c1",
                ),
            ),
        )
        self.assertIn("com.android.art", plan.apex_names)
        self.assertNotIn("com.android.tzdata", plan.apex_names)
        self.assertEqual(
            plan.avb_roles, ("boot", "vbmeta", "vbmeta_system", "vbmeta_vendor")
        )

    def test_plan_always_includes_releasekey_without_a_releasekey_source_stem(self):
        platform_only = APK_CERTS.splitlines(keepends=True)[0]
        with self.private_temp() as directory:
            target_files = Path(directory) / "target-files.zip"
            write_target_files(target_files, apkcerts=platform_only)

            plan = self.build_key_plan(target_files)

        self.assertEqual(plan.android_roles, ("platform", "releasekey"))
        self.assertEqual(
            tuple(
                (mapping.source_stem, mapping.destination_role)
                for mapping in plan.android_mappings
            ),
            (("build/make/target/product/security/platform", "platform"),),
        )

    def test_plan_rejects_extra_ota_key_collision_with_apk_mapping(self):
        with self.private_temp() as directory:
            target_files = Path(directory) / "target-files.zip"
            write_target_files(
                target_files,
                misc_info=(
                    MISC_INFO
                    + "extra_recovery_keys="
                    + "build/make/target/product/security/platform\n"
                ),
            )

            with self.assertRaisesRegex(self.KeyGenerationError, "collid"):
                self.build_key_plan(target_files)

    def test_dry_run_rejects_missing_android_host_avbtool(self):
        with self.private_temp() as directory:
            root = Path(directory)
            target_files = root / "target-files.zip"
            write_target_files(target_files)
            android_root = root / "android"
            private_parent = root / "private"
            android_root.mkdir()
            private_parent.mkdir(mode=0o700)

            with mock.patch("sys.stderr", new_callable=io.StringIO) as stderr:
                result = self.main(
                    [
                        "--target-files",
                        str(target_files),
                        "--android-root",
                        str(android_root),
                        "--keys-dir",
                        str(private_parent / "keys"),
                        "--subject",
                        "/CN=fleur release/",
                        "--dry-run",
                    ]
                )

            self.assertEqual(result, 1)
            self.assertIn("required Android host tool avbtool", stderr.getvalue())
            self.assertFalse((private_parent / "keys").exists())

    def test_dry_run_rejects_non_executable_android_host_avbtool(self):
        with self.private_temp() as directory:
            root = Path(directory)
            target_files = root / "target-files.zip"
            write_target_files(target_files)
            android_root = root / "android"
            private_parent = root / "private"
            write_fake_avbtool(android_root).chmod(0o644)
            private_parent.mkdir(mode=0o700)

            with mock.patch("sys.stderr", new_callable=io.StringIO) as stderr:
                result = self.main(
                    [
                        "--target-files",
                        str(target_files),
                        "--android-root",
                        str(android_root),
                        "--keys-dir",
                        str(private_parent / "keys"),
                        "--subject",
                        "/CN=fleur release/",
                        "--dry-run",
                    ]
                )

            self.assertEqual(result, 1)
            self.assertIn("required Android host tool avbtool", stderr.getvalue())
            self.assertFalse((private_parent / "keys").exists())

    def test_missing_android_host_avbtool_fails_before_passphrase(self):
        with self.private_temp() as directory:
            root = Path(directory)
            target_files = root / "target-files.zip"
            write_target_files(target_files)
            repo = root / "repo"
            android_root = root / "android"
            private_parent = root / "private"
            repo.mkdir()
            android_root.mkdir()
            private_parent.mkdir(mode=0o700)
            prompts: list[str] = []
            secret = uuid.uuid4().hex
            runner = FakeRunner(failure_tool="avbtool")

            with self.assertRaisesRegex(self.KeyGenerationError, "avbtool"):
                self.generate_keyset(
                    target_files,
                    android_root,
                    private_parent / "keys",
                    "/CN=fleur release/",
                    repo_root=repo,
                    runner=runner,
                    getpass_fn=lambda prompt: prompts.append(prompt) or secret,
                )

            self.assertEqual(prompts, [])
            self.assertEqual(runner.calls, [])
            self.assertFalse((private_parent / "keys").exists())

    def test_blank_or_mismatched_passphrase_fails_before_commands(self):
        with self.private_temp() as directory:
            root = Path(directory)
            target_files = root / "target-files.zip"
            write_target_files(target_files)
            repo = root / "repo"
            android_root = root / "android"
            private_parent = root / "private"
            repo.mkdir()
            write_fake_avbtool(android_root)
            private_parent.mkdir()

            first = uuid.uuid4().hex
            second = uuid.uuid4().hex
            cases = {
                "blank": ("", ""),
                "whitespace": ("   ", "   "),
                "mismatch": (first, second),
                "newline": (first + "\n", first + "\n"),
                "unicode-line-separator": (first + "\u2028", first + "\u2028"),
                "control": (first + "\x1f", first + "\x1f"),
                "delimiter": (first + "]]]", first + "]]]"),
                "leading-space": (" " + first, " " + first),
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

    def test_password_path_and_untrusted_ancestor_fail_before_commands(self):
        with self.private_temp() as directory:
            root = Path(directory)
            target_files = root / "target-files.zip"
            write_target_files(target_files)
            repo = root / "repo"
            android_root = root / "android"
            repo.mkdir()
            write_fake_avbtool(android_root)
            secret = uuid.uuid4().hex

            unsafe_parent = root / "private space"
            unsafe_parent.mkdir(mode=0o700)
            runner = FakeRunner(forbidden_secret=secret)
            with self.assertRaises(self.KeyGenerationError):
                self.generate_keyset(
                    target_files,
                    android_root,
                    unsafe_parent / "keys",
                    "/CN=fleur release/",
                    repo_root=repo,
                    runner=runner,
                    getpass_fn=lambda _prompt: secret,
                )
            self.assertEqual(runner.calls, [])

            real_parent = root / "real-parent"
            linked_parent = root / "linked-parent"
            real_parent.mkdir(mode=0o700)
            linked_parent.symlink_to(real_parent, target_is_directory=True)
            runner = FakeRunner(forbidden_secret=secret)
            with self.assertRaises(self.KeyGenerationError):
                self.generate_keyset(
                    target_files,
                    android_root,
                    linked_parent / "keys",
                    "/CN=fleur release/",
                    repo_root=repo,
                    runner=runner,
                    getpass_fn=lambda _prompt: secret,
                )
            self.assertEqual(runner.calls, [])

            writable_parent = root / "writable"
            writable_parent.mkdir()
            writable_parent.chmod(0o770)
            runner = FakeRunner(forbidden_secret=secret)
            with self.assertRaises(self.KeyGenerationError):
                self.generate_keyset(
                    target_files,
                    android_root,
                    writable_parent / "keys",
                    "/CN=fleur release/",
                    repo_root=repo,
                    runner=runner,
                    getpass_fn=lambda _prompt: secret,
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
            write_fake_avbtool(android_root)
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
            write_fake_avbtool(android_root)
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
            avbtool = write_fake_avbtool(android_root)
            private_parent.mkdir(mode=0o700)
            secret = uuid.uuid4().hex + "!"
            runner = FakeRunner(
                forbidden_secret=secret,
                write_outputs_in_child=True,
            )
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
            self.assertFalse(secret in serialized_manifest)
            self.assertNotIn(".pk8", serialized_manifest)
            self.assertNotIn(".pem", serialized_manifest)

            protected_calls = [
                call for call in runner.calls if call.stdin_digest is not None
            ]
            self.assertTrue(protected_calls)
            expected_stdin_digest = digest_text(secret + "\n")
            self.assertTrue(
                all(
                    call.stdin_digest == expected_stdin_digest
                    for call in protected_calls
                )
            )
            avb_calls = [
                call
                for call in runner.calls
                if Path(call.command[0]).name == "avbtool"
            ]
            self.assertTrue(avb_calls)
            self.assertTrue(
                all(call.command[0] == str(avbtool) for call in avb_calls)
            )
            self.assertTrue(all(not call.environment for call in avb_calls))
            self.assertTrue(
                all(
                    dict(call.fd_targets)[
                        int(
                            call.command[call.command.index("--key") + 1]
                            .split("/")[4]
                        )
                    ].endswith(".raw.pem")
                    for call in avb_calls
                )
            )
            self.assertTrue(
                any(
                    call.command[:3] == ("openssl", "genrsa", "-traditional")
                    and call.command[-1] == "2048"
                    for call in runner.calls
                )
            )
            self.assertTrue(
                any(
                    call.command[:3] == ("openssl", "genrsa", "-traditional")
                    and call.command[-1] == "4096"
                    for call in runner.calls
                )
            )
            for call in runner.calls:
                for option in ("-out", "--output"):
                    if option in call.command:
                        output = call.command[call.command.index(option) + 1]
                        self.assertTrue(
                            output.startswith(f"/proc/{os.getpid()}/fd/")
                        )
                        descriptor = int(output.split("/", 5)[4])
                        self.assertIn(descriptor, call.pass_fds)

            from scripts.ubuntu.avb_password_helper import parse_password_file

            password_entries = parse_password_file(keys_dir / "passwords")
            self.assertEqual(
                set(password_entries),
                {
                    str(keys_dir / "platform"),
                    str(keys_dir / "releasekey"),
                    str(keys_dir / "testkey-f88799ce31c1"),
                    str(keys_dir / "com.android.art"),
                    str(keys_dir / "com.android.art.pem"),
                    str(keys_dir / "avb_boot.pem"),
                    str(keys_dir / "avb_vbmeta.pem"),
                    str(keys_dir / "avb_vbmeta_system.pem"),
                    str(keys_dir / "avb_vbmeta_vendor.pem"),
                },
            )
            self.assertTrue(
                all(
                    digest_text(value) == digest_text(secret)
                    for value in password_entries.values()
                )
            )
            lineage_pattern = re.compile(r"^\[\[\[\s*(.*?)\s*\]\]\]\s*(\S+)$")
            written_lines = (keys_dir / "passwords").read_text().splitlines()
            matches = [lineage_pattern.fullmatch(line) for line in written_lines]
            self.assertTrue(all(match is not None for match in matches))
            self.assertEqual(
                {match.group(2) for match in matches if match is not None},
                set(password_entries),
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
            write_fake_avbtool(android_root)
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
            write_fake_avbtool(android_root)
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

    def test_parent_revalidation_blocks_permission_change_during_generation(self):
        with self.private_temp() as directory:
            root = Path(directory)
            target_files = root / "target-files.zip"
            write_target_files(target_files)
            repo = root / "repo"
            android_root = root / "android"
            private_parent = root / "private"
            keys_dir = private_parent / "keys"
            repo.mkdir()
            write_fake_avbtool(android_root)
            private_parent.mkdir(mode=0o700)
            secret = uuid.uuid4().hex
            runner = FakeRunner(
                forbidden_secret=secret,
                mutate_after_first=lambda: private_parent.chmod(0o770),
            )

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

    def test_replaced_output_path_cannot_redirect_raw_material(self):
        with self.private_temp() as directory:
            root = Path(directory)
            target_files = root / "target-files.zip"
            write_target_files(target_files)
            repo = root / "repo"
            android_root = root / "android"
            private_parent = root / "private"
            keys_dir = private_parent / "keys"
            trap = root / "trap"
            repo.mkdir()
            write_fake_avbtool(android_root)
            private_parent.mkdir(mode=0o700)
            trap.write_bytes(b"")
            secret = uuid.uuid4().hex
            runner = FakeRunner(
                forbidden_secret=secret,
                replace_first_output_with_symlink_to=trap,
            )

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

            self.assertEqual(trap.read_bytes(), b"")
            self.assertFalse(keys_dir.exists())
            self.assertEqual(list(private_parent.glob(".keys.staging-*")), [])

    def test_base_exceptions_preserve_error_and_remove_all_staging_material(self):
        with self.private_temp() as directory:
            root = Path(directory)
            target_files = root / "target-files.zip"
            write_target_files(target_files)
            repo = root / "repo"
            android_root = root / "android"
            repo.mkdir()
            write_fake_avbtool(android_root)
            secret = uuid.uuid4().hex

            for name, error in (
                ("interrupt", KeyboardInterrupt()),
                ("unexpected", RuntimeError("redacted runner failure")),
            ):
                with self.subTest(case=name):
                    private_parent = root / name
                    private_parent.mkdir(mode=0o700)
                    keys_dir = private_parent / "keys"
                    runner = FakeRunner(
                        forbidden_secret=secret,
                        raise_error=error,
                    )
                    with self.assertRaises(type(error)) as caught:
                        self.generate_keyset(
                            target_files,
                            android_root,
                            keys_dir,
                            "/CN=fleur release/",
                            repo_root=repo,
                            runner=runner,
                            getpass_fn=lambda _prompt: secret,
                        )
                    self.assertIs(caught.exception, error)
                    self.assertFalse(keys_dir.exists())
                    self.assertEqual(
                        list(private_parent.glob(".keys.staging-*")), []
                    )

    def test_workspace_open_interrupt_removes_new_staging_directory(self):
        import scripts.ubuntu.generate_release_keys as generator

        with self.private_temp() as directory:
            root = Path(directory)
            target_files = root / "target-files.zip"
            write_target_files(target_files)
            repo = root / "repo"
            android_root = root / "android"
            private_parent = root / "private"
            keys_dir = private_parent / "keys"
            repo.mkdir()
            write_fake_avbtool(android_root)
            private_parent.mkdir(mode=0o700)
            secret = uuid.uuid4().hex
            original_open = generator.os.open

            def interrupt_staging_open(path, flags, *args, **kwargs):
                if str(path).startswith(".keys.staging-"):
                    raise KeyboardInterrupt()
                return original_open(path, flags, *args, **kwargs)

            with mock.patch.object(
                generator.os, "open", side_effect=interrupt_staging_open
            ):
                with self.assertRaises(KeyboardInterrupt):
                    self.generate_keyset(
                        target_files,
                        android_root,
                        keys_dir,
                        "/CN=fleur release/",
                        repo_root=repo,
                        runner=FakeRunner(forbidden_secret=secret),
                        getpass_fn=lambda _prompt: secret,
                    )

            self.assertFalse(keys_dir.exists())
            self.assertEqual(list(private_parent.glob(".keys.staging-*")), [])

    def test_post_rename_interrupt_preserves_complete_destination(self):
        import scripts.ubuntu.generate_release_keys as generator

        with self.private_temp() as directory:
            root = Path(directory)
            target_files = root / "target-files.zip"
            write_target_files(target_files)
            repo = root / "repo"
            android_root = root / "android"
            private_parent = root / "private"
            keys_dir = private_parent / "keys"
            repo.mkdir()
            write_fake_avbtool(android_root)
            private_parent.mkdir(mode=0o700)
            secret = uuid.uuid4().hex
            original_rename = generator._rename_no_replace_at

            def rename_then_interrupt(*args, **kwargs):
                original_rename(*args, **kwargs)
                raise KeyboardInterrupt()

            with mock.patch.object(
                generator,
                "_rename_no_replace_at",
                side_effect=rename_then_interrupt,
            ):
                with self.assertRaises(KeyboardInterrupt):
                    self.generate_keyset(
                        target_files,
                        android_root,
                        keys_dir,
                        "/CN=fleur release/",
                        repo_root=repo,
                        runner=FakeRunner(forbidden_secret=secret),
                        getpass_fn=lambda _prompt: secret,
                    )

            if keys_dir.exists():
                plan = self.build_key_plan(target_files)
                actual_files = {
                    str(path.relative_to(keys_dir))
                    for path in keys_dir.rglob("*")
                    if path.is_file()
                }
                self.assertEqual(actual_files, generator._expected_files(plan))
                self.assertFalse((keys_dir / ".raw").exists())
            self.assertEqual(list(private_parent.glob(".keys.staging-*")), [])

    def test_base_exception_at_each_publication_boundary_is_atomic(self):
        import scripts.ubuntu.generate_release_keys as generator

        with self.private_temp() as directory:
            root = Path(directory)
            target_files = root / "target-files.zip"
            write_target_files(target_files)
            repo = root / "repo"
            android_root = root / "android"
            repo.mkdir()
            write_fake_avbtool(android_root)
            secret = uuid.uuid4().hex
            plan = self.build_key_plan(target_files)
            boundaries = (
                "_remove_raw_directory",
                "_write_password_file_at",
                "_write_keyset_manifest",
                "_validate_complete_staging",
                "_rename_no_replace_at",
            )

            for boundary in boundaries:
                with self.subTest(boundary=boundary):
                    private_parent = root / boundary
                    private_parent.mkdir(mode=0o700)
                    keys_dir = private_parent / "keys"
                    with mock.patch.object(
                        generator, boundary, side_effect=KeyboardInterrupt()
                    ):
                        with self.assertRaises(KeyboardInterrupt):
                            self.generate_keyset(
                                target_files,
                                android_root,
                                keys_dir,
                                "/CN=fleur release/",
                                repo_root=repo,
                                runner=FakeRunner(forbidden_secret=secret),
                                getpass_fn=lambda _prompt: secret,
                            )
                    self.assertFalse(keys_dir.exists())
                    self.assertEqual(
                        list(private_parent.glob(".keys.staging-*")), []
                    )

            private_parent = root / "post-rename-fsync"
            private_parent.mkdir(mode=0o700)
            keys_dir = private_parent / "keys"
            original_fsync = generator.os.fsync

            def interrupt_published_fsync(descriptor):
                if keys_dir.exists():
                    raise KeyboardInterrupt()
                return original_fsync(descriptor)

            with mock.patch.object(
                generator.os, "fsync", side_effect=interrupt_published_fsync
            ):
                with self.assertRaises(KeyboardInterrupt):
                    self.generate_keyset(
                        target_files,
                        android_root,
                        keys_dir,
                        "/CN=fleur release/",
                        repo_root=repo,
                        runner=FakeRunner(forbidden_secret=secret),
                        getpass_fn=lambda _prompt: secret,
                    )

            actual_files = {
                str(path.relative_to(keys_dir))
                for path in keys_dir.rglob("*")
                if path.is_file()
            }
            self.assertEqual(actual_files, generator._expected_files(plan))
            self.assertFalse((keys_dir / ".raw").exists())
            self.assertEqual(list(private_parent.glob(".keys.staging-*")), [])

    def test_cleanup_refuses_to_traverse_swapped_child_directory(self):
        import scripts.ubuntu.generate_release_keys as generator

        with self.private_temp() as directory:
            root = Path(directory)
            staging = root / "staging"
            child = staging / "child"
            held = staging / "held-original"
            replacement = root / "replacement"
            child.mkdir(parents=True)
            replacement.mkdir()
            (child / "original-marker").write_bytes(b"original")
            (replacement / "replacement-marker").write_bytes(b"replacement")
            staging_fd = os.open(staging, os.O_RDONLY | os.O_DIRECTORY)
            original_open = generator.os.open
            swapped = False

            def swap_before_open(path, flags, *args, **kwargs):
                nonlocal swapped
                if (
                    not swapped
                    and path == "child"
                    and kwargs.get("dir_fd") == staging_fd
                ):
                    swapped = True
                    child.rename(held)
                    replacement.rename(child)
                return original_open(path, flags, *args, **kwargs)

            try:
                with mock.patch.object(
                    generator.os, "open", side_effect=swap_before_open
                ):
                    with self.assertRaises(generator.KeyGenerationError):
                        generator._remove_tree_contents(staging_fd)
            finally:
                os.close(staging_fd)

            self.assertTrue((held / "original-marker").is_file())
            self.assertTrue((child / "replacement-marker").is_file())

    def test_post_generation_error_removes_passwords_and_staging_material(self):
        with self.private_temp() as directory:
            root = Path(directory)
            target_files = root / "target-files.zip"
            write_target_files(target_files)
            repo = root / "repo"
            android_root = root / "android"
            private_parent = root / "private"
            keys_dir = private_parent / "keys"
            repo.mkdir()
            write_fake_avbtool(android_root)
            private_parent.mkdir(mode=0o700)
            secret = uuid.uuid4().hex
            marker = RuntimeError("redacted manifest failure")
            runner = FakeRunner(forbidden_secret=secret)

            with mock.patch(
                "scripts.ubuntu.generate_release_keys._write_keyset_manifest",
                side_effect=marker,
            ):
                with self.assertRaises(RuntimeError) as caught:
                    self.generate_keyset(
                        target_files,
                        android_root,
                        keys_dir,
                        "/CN=fleur release/",
                        repo_root=repo,
                        runner=runner,
                        getpass_fn=lambda _prompt: secret,
                    )

            self.assertIs(caught.exception, marker)
            self.assertFalse(keys_dir.exists())
            self.assertEqual(list(private_parent.glob(".keys.staging-*")), [])

    def test_cleanup_error_does_not_mask_original_exception(self):
        import scripts.ubuntu.generate_release_keys as generator

        with self.private_temp() as directory:
            root = Path(directory)
            target_files = root / "target-files.zip"
            write_target_files(target_files)
            repo = root / "repo"
            android_root = root / "android"
            private_parent = root / "private"
            keys_dir = private_parent / "keys"
            repo.mkdir()
            write_fake_avbtool(android_root)
            private_parent.mkdir(mode=0o700)
            secret = uuid.uuid4().hex
            marker = RuntimeError("redacted runner failure")
            runner = FakeRunner(forbidden_secret=secret, raise_error=marker)
            original_cleanup = generator._cleanup_workspace

            def cleanup_then_fail(workspace):
                original_cleanup(workspace)
                raise OSError("redacted cleanup failure")

            with mock.patch.object(
                generator, "_cleanup_workspace", side_effect=cleanup_then_fail
            ):
                with self.assertRaises(RuntimeError) as caught:
                    self.generate_keyset(
                        target_files,
                        android_root,
                        keys_dir,
                        "/CN=fleur release/",
                        repo_root=repo,
                        runner=runner,
                        getpass_fn=lambda _prompt: secret,
                    )

            self.assertIs(caught.exception, marker)
            self.assertFalse(keys_dir.exists())
            self.assertEqual(list(private_parent.glob(".keys.staging-*")), [])


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
                f"[[[ {wanted} ]]] /secure/key.pem\n"
                f"[[[ {unrelated} ]]] /secure/key.pem.other\n",
            )

            result = self.run_helper(password_file, "/secure/key.pem")

            self.assertTrue(result.returncode == 0)
            self.assertEqual(len(result.stdout), len(wanted))
            self.assertEqual(digest_text(result.stdout), digest_text(wanted))
            self.assertFalse(unrelated in result.stdout + result.stderr)

    def test_helper_rejects_missing_duplicate_and_malformed_entries_without_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            secret = uuid.uuid4().hex
            fixtures = {
                "missing": f"[[[ {secret} ]]] /secure/other.pem\n",
                "duplicate": (
                    f"[[[ {secret} ]]] /secure/key.pem\n"
                    f"[[[ {secret} ]]] /secure/key.pem\n"
                ),
                "malformed": f"[[[ {secret} ]]] /secure/key.pem\nnot-an-entry\n",
            }
            for name, content in fixtures.items():
                with self.subTest(name=name):
                    password_file = root / name
                    self.write_passwords(password_file, content)
                    result = self.run_helper(password_file, "/secure/key.pem")
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual(len(result.stdout), 0)
                    self.assertFalse(secret in result.stderr)

    def test_helper_rejects_symlink_and_overly_permissive_file(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target"
            link = root / "link"
            secret = uuid.uuid4().hex
            self.write_passwords(target, f"[[[ {secret} ]]] /secure/key.pem\n")
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
