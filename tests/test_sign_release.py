from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import hashlib
import io
import json
import os
from pathlib import Path
import shlex
import stat
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import uuid
import zipfile


ROOT = Path(__file__).resolve().parents[1]
SIGNING_HELPER = ROOT / "scripts/ubuntu/avb_signing_helper.py"
MAC_ROLES = (
    "platform",
    "sdk_sandbox",
    "bluetooth",
    "media",
    "networkstack",
    "nfc",
)


def fixture_der(name: str, *, release: bool = False) -> bytes:
    payload = (f"{'release' if release else 'source'}-{name}").encode()
    return b"\x30" + bytes((len(payload),)) + payload


def fixture_pem(value: bytes) -> bytes:
    import base64

    return (
        b"-----BEGIN CERTIFICATE-----\n"
        + base64.b64encode(value)
        + b"\n-----END CERTIFICATE-----\n"
    )

APK_CERTS = '''\
name="framework-res.apk" certificate="build/make/target/product/security/platform.x509.pem" private_key="build/make/target/product/security/platform.pk8"
name="SdkSandbox.apk" certificate="build/make/target/product/security/sdk_sandbox.x509.pem" private_key="build/make/target/product/security/sdk_sandbox.pk8"
name="Bluetooth.apk" certificate="build/make/target/product/security/bluetooth.x509.pem" private_key="build/make/target/product/security/bluetooth.pk8"
name="Media.apk" certificate="build/make/target/product/security/media.x509.pem" private_key="build/make/target/product/security/media.pk8"
name="NetworkStack.apk" certificate="build/make/target/product/security/networkstack.x509.pem" private_key="build/make/target/product/security/networkstack.pk8"
name="Nfc.apk" certificate="build/make/target/product/security/nfc.x509.pem" private_key="build/make/target/product/security/nfc.pk8"
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
    path: Path,
    *,
    system_build_prop: str = SYSTEM_BUILD_PROP,
    misc_info: str = MISC_INFO,
    otakeys: str = "\n",
) -> None:
    unsigned_otacerts = io.BytesIO()
    with zipfile.ZipFile(unsigned_otacerts, "w") as archive:
        archive.writestr("lineage.x509.pem", b"lineage-certificate")
        archive.writestr("testkey.x509.pem", b"test-certificate")
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("META/apkcerts.txt", APK_CERTS)
        archive.writestr("META/apexkeys.txt", APEX_KEYS)
        archive.writestr("META/misc_info.txt", misc_info)
        archive.writestr("META/otakeys.txt", otakeys)
        archive.writestr("SYSTEM/build.prop", system_build_prop)
        archive.writestr("IMAGES/boot.img", b"fixed-kernel-boot")
        for name in (
            "BOOT/RAMDISK/system/etc/security/otacerts.zip",
            "SYSTEM/etc/security/otacerts.zip",
        ):
            archive.writestr(name, unsigned_otacerts.getvalue())
        plat_signers = b"".join(
            b'<signer signature="'
            + fixture_der(role).hex().encode()
            + b'"><seinfo value="'
            + ("network_stack" if role == "networkstack" else role).encode()
            + b'"/></signer>'
            for role in MAC_ROLES
        )
        archive.writestr(
            "SYSTEM/etc/selinux/plat_mac_permissions.xml",
            b'<?xml version="1.0" encoding="iso-8859-1"?><policy>'
            + plat_signers
            + b"</policy>",
        )
        archive.writestr(
            "VENDOR/etc/selinux/vendor_mac_permissions.xml",
            b'<?xml version="1.0" encoding="iso-8859-1"?><policy><signer signature="'
            + fixture_der("platform").hex().encode()
            + b'"><seinfo value="platform"/></signer></policy>',
        )
        for partition in ("ODM", "PRODUCT", "SYSTEM_EXT"):
            archive.writestr(
                f"{partition}/etc/selinux/{partition.lower()}_mac_permissions.xml",
                b'<?xml version="1.0" encoding="iso-8859-1"?><policy></policy>',
            )


def write_zip_symlink(
    archive: zipfile.ZipFile,
    name: str,
    target: bytes,
    *,
    mode: int = 0o777,
) -> None:
    member = zipfile.ZipInfo(name)
    member.create_system = 3
    member.external_attr = (stat.S_IFLNK | mode) << 16
    archive.writestr(member, target)


def write_build_provenance(path: Path, target_files: Path) -> None:
    policy = json.loads((ROOT / "sources/kernel-fix.json").read_text(encoding="utf-8"))
    fields = {
        name: policy[name]
        for name in (
            "project", "file", "base_commit", "patch_sha256",
            "application_script", "application_script_sha256",
            "rejected_pre_fix_boot_sha256",
            "rejected_pre_fix_boot_content_sha256",
        )
    }
    evidence = {**fields, "post_fix_source_sha256": "1" * 64, "forward_applicable": False, "reverse_applicable": True}
    with zipfile.ZipFile(target_files) as archive:
        boot = archive.read("IMAGES/boot.img")
    target_record = {
        "filename": target_files.name,
        "size": target_files.stat().st_size,
        "sha256": file_digest(target_files),
        "boot_raw_sha256": hashlib.sha256(boot).hexdigest(),
        "boot_content_sha256": hashlib.sha256(boot).hexdigest(),
    }
    record = {
        "schema_version": 1, "state": "finalized", "device": "fleur", "session_nonce": "a" * 64,
        "pre_build": {
            **evidence,
            "timestamp": "2026-08-29T12:30:00Z",
            "application_evidence_sha256": hashlib.sha256(json.dumps(evidence, sort_keys=True, separators=(",", ":")).encode()).hexdigest(),
        },
        "unsigned_target_files": target_record,
    }
    path.write_text(json.dumps(record), encoding="utf-8")


def digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def file_digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def file_binding(path: Path) -> dict[str, object]:
    metadata = path.stat()
    return {
        "device": metadata.st_dev,
        "inode": metadata.st_ino,
        "size": metadata.st_size,
        "sha256": file_digest(path),
    }


def helper_config(private_key: Path, public_key: Path, password_file: Path) -> dict[str, object]:
    return {
        "schema_version": 2,
        "password_file": str(password_file),
        "keys": {
            str(public_key): {
                "private_key": str(private_key),
                "private_identity": file_binding(private_key),
                "public_identity": file_binding(public_key),
            }
        },
    }


def write_fake_keyset(keys_dir: Path, secret: str) -> None:
    keys_dir.mkdir(mode=0o700)
    public_dir = keys_dir / "public"
    public_dir.mkdir(mode=0o700)
    android = tuple(sorted((*MAC_ROLES, "releasekey", "testkey-f88799ce31c1")))
    apex = ("com.android.art",)
    avb = ("avb_boot", "avb_vbmeta", "avb_vbmeta_system", "avb_vbmeta_vendor")
    for role in android:
        (keys_dir / f"{role}.pk8").write_bytes((role + "-pk8").encode("ascii"))
        (keys_dir / f"{role}.x509.pem").write_bytes(
            fixture_pem(fixture_der(role, release=True))
        )
    for role in apex:
        (keys_dir / f"{role}.pem").write_bytes((role + "-encrypted").encode("ascii"))
        (keys_dir / f"{role}.pk8").write_bytes((role + "-pk8").encode("ascii"))
        (keys_dir / f"{role}.x509.pem").write_bytes(
            fixture_pem(fixture_der(role, release=True))
        )
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
    for role in (*MAC_ROLES, "testkey"):
        certificate = (
            android_root
            / "build/make/target/product/security"
            / f"{role}.x509.pem"
        )
        certificate.parent.mkdir(parents=True, exist_ok=True)
        certificate.write_bytes(fixture_pem(fixture_der(role)))
    cts_certificate = (
        android_root
        / "cts/hostsidetests/compilation/certs/testkey.x509.pem"
    )
    cts_certificate.parent.mkdir(parents=True, exist_ok=True)
    cts_certificate.write_bytes(fixture_pem(fixture_der("cts-testkey")))


def write_fake_android_jdk(android_root: Path) -> Path:
    java = android_root / "prebuilts/jdk/jdk21/linux-x86/bin/java"
    java.parent.mkdir(parents=True)
    java.write_text("#!/bin/sh\nexit 99\n", encoding="utf-8")
    java.chmod(0o755)
    return java


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
        self.signing_input_bytes = None
        self.signing_mac_permissions = None
        self.container_material = {}
        self.config_bytes = None
        self.password_entry_paths = ()
        self.working_directories = []

    def _record_container_stem(self, stem: Path) -> None:
        for suffix in (".pk8", ".x509.pem"):
            path = Path(f"{stem}{suffix}")
            self.container_material[path.name] = path.read_bytes()

    def __call__(self, command, *, env):
        command = tuple(str(item) for item in command)
        tool = Path(command[0]).name
        if self.final_output.exists():
            raise AssertionError("final output published before all commands completed")
        self.calls.append((command, dict(env)))
        self.working_directories.append(Path.cwd())
        if tool == "sign_target_files_apks":
            self.signing_input_bytes = Path(command[-2]).read_bytes()
            with zipfile.ZipFile(Path(command[-2])) as signing_input:
                self.signing_mac_permissions = signing_input.read(
                    "SYSTEM/etc/selinux/plat_mac_permissions.xml"
                )
            self.config_bytes = Path(env["FLEUR_AVB_SIGNING_CONFIG"]).read_bytes()
            password_lines = Path(env["ANDROID_PW_FILE"]).read_text(
                encoding="utf-8"
            ).splitlines()
            self.password_entry_paths = tuple(
                line.split("]]]", 1)[1].strip()
                for line in password_lines
                if line.strip()
            )
            default_directory = Path(command[command.index("-d") + 1])
            self._record_container_stem(default_directory / "releasekey")
            for index, value in enumerate(command):
                if value == "-k":
                    self._record_container_stem(
                        Path(command[index + 1].split("=", 1)[1])
                    )
                elif value == "--extra_apks":
                    self._record_container_stem(
                        Path(command[index + 1].split("=", 1)[1])
                    )
        elif tool == "ota_from_target_files":
            self._record_container_stem(Path(command[command.index("-k") + 1]))
        if tool == self.fail_tool:
            raise subprocess.CalledProcessError(7, command)
        output = Path(command[-1])
        output.parent.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(output, "w") as archive:
            if tool == "sign_target_files_apks":
                canonical_otacerts = io.BytesIO()
                with zipfile.ZipFile(canonical_otacerts, "w") as trust_archive:
                    trust_archive.writestr(
                        "releasekey.x509.pem",
                        self.container_material["releasekey.x509.pem"],
                    )
                with zipfile.ZipFile(Path(command[-2])) as signing_input:
                    for member in signing_input.infolist():
                        payload = signing_input.read(member)
                        if member.filename.endswith("/otacerts.zip"):
                            payload = canonical_otacerts.getvalue()
                        archive.writestr(member, payload)
            elif tool == "ota_from_target_files":
                archive.writestr(
                    "META-INF/com/android/metadata",
                    "ota-type=AB\npre-device=fleur\n",
                )
                if not self.legacy_ota:
                    archive.writestr("payload.bin", b"payload-fixture")
            elif tool == "img_from_target_files":
                archive.writestr("android-info.txt", "require product=fleur\n")


class PolicyMutatingReleaseRunner(FakeReleaseRunner):
    def __call__(self, command, *, env):
        super().__call__(command, env=env)
        command = tuple(str(item) for item in command)
        if Path(command[0]).name != "sign_target_files_apks":
            return
        output = Path(command[-1])
        with zipfile.ZipFile(output) as archive:
            entries = [(member, archive.read(member)) for member in archive.infolist()]
        policy_name = "SYSTEM/etc/selinux/plat_mac_permissions.xml"
        with zipfile.ZipFile(output, "w") as archive:
            for member, payload in entries:
                if member.filename == policy_name:
                    payload = payload.replace(
                        fixture_der("platform", release=True).hex().encode(),
                        fixture_der("platform").hex().encode(),
                        1,
                    )
                archive.writestr(member, payload)


class OtaCertMutatingReleaseRunner(FakeReleaseRunner):
    def __call__(self, command, *, env):
        super().__call__(command, env=env)
        command = tuple(str(item) for item in command)
        if Path(command[0]).name != "sign_target_files_apks":
            return
        output = Path(command[-1])
        with zipfile.ZipFile(output) as archive:
            entries = [(member, archive.read(member)) for member in archive.infolist()]
        unsafe_otacerts = io.BytesIO()
        with zipfile.ZipFile(unsafe_otacerts, "w") as trust_archive:
            trust_archive.writestr(
                "proc/1/fd/7/releasekey.x509.pem",
                self.container_material["releasekey.x509.pem"],
            )
        with zipfile.ZipFile(output, "w") as archive:
            for member, payload in entries:
                if member.filename == "SYSTEM/etc/security/otacerts.zip":
                    payload = unsafe_otacerts.getvalue()
                archive.writestr(member, payload)


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
        target_files = root / "lineage_fleur-target_files.zip"
        android_root = root / "android"
        keys_dir = root / "keys"
        output_dir = root / "20260829T123456Z"
        secret = uuid.uuid4().hex + uuid.uuid4().hex
        write_target_files(target_files)
        build_provenance = root / "build-provenance.json"
        write_build_provenance(build_provenance, target_files)
        write_fake_host_tools(android_root)
        write_fake_android_jdk(android_root)
        write_fake_keyset(keys_dir, secret)
        paths = self.SigningPaths(
            target_files, android_root, keys_dir, output_dir,
            build_provenance=build_provenance,
        )
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
            self.assertEqual(2, report["schema_version"])
            self.assertEqual(report["build_properties"], {"ab_update": True, "virtual_ab": True})
            self.assertEqual(report["timestamps"]["started_at"], "2026-08-29T12:34:56Z")
            self.assertEqual(report["timestamps"]["completed_at"], "2026-08-29T12:35:56Z")
            self.assertEqual(
                report["input"]["sha256"],
                file_digest(paths.target_files),
            )
            self.assertEqual(set(report["outputs"]), {paths.signed_target_files.name, paths.ota_zip.name, paths.fastboot_zip.name})
            self.assertTrue(report["public_fingerprints"])
            self.assertEqual(
                {"com.android.tzdata.apex"},
                set(report["presigned_allowlist"]["apex"]),
            )
            self.assertEqual([], report["presigned_allowlist"]["apk"])
            self.assertEqual(
                {
                    "META/apkcerts.txt",
                    "META/apexkeys.txt",
                    "META/misc_info.txt",
                    "META/otakeys.txt",
                    "SYSTEM/build.prop",
                },
                set(report["input_metadata_sha256"]),
            )
            self.assertTrue(report["key_plan"]["android_mappings"])
            self.assertIn("avb_boot", report["key_plan"]["avb_roles"])
            self.assertEqual(paths.build_provenance.name, report["build_provenance"]["filename"])
            self.assertEqual(file_digest(paths.build_provenance), report["build_provenance"]["sha256"])
            self.assertEqual(file_digest(paths.target_files), report["build_provenance"]["unsigned_target_files"]["sha256"])
            sanitized = report["sanitized_options"]["sign_target_files_apks"]
            self.assertTrue(all(name.startswith("-") for name in sanitized))
            self.assertTrue(all("/" not in name for name in sanitized))
            self.assertNotIn("--signing_helper", sanitized)
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
            sign_command = tool_runner.calls[0][0]
            helper_values = [
                value
                for value in sign_command
                if value.startswith("--signing_helper=")
            ]
            self.assertTrue(helper_values)
            self.assertTrue(
                all(
                    value.startswith(f"--signing_helper=/proc/{os.getpid()}/fd/")
                    for value in helper_values
                )
            )
            self.assertNotEqual(
                tool_runner.signing_input_bytes, paths.target_files.read_bytes()
            )
            for role in MAC_ROLES:
                self.assertIn(
                    fixture_der(role, release=True).hex().encode(),
                    tool_runner.signing_mac_permissions,
                )
            self.assertTrue(sign_command[-2].startswith(f"/proc/{os.getpid()}/fd/"))
            runtime_key_dir = Path(sign_command[sign_command.index("-d") + 1])
            self.assertEqual(Path("."), runtime_key_dir)
            self.assertEqual(
                "container-keys", tool_runner.working_directories[0].name
            )
            self.assertNotEqual(paths.keys_dir, tool_runner.working_directories[0])
            self.assertNotEqual(runtime_key_dir, paths.keys_dir)
            self.assertNotIn(str(paths.keys_dir), "\n".join(sign_command))
            self.assertTrue(
                sign_env["FLEUR_AVB_SIGNING_CONFIG"].startswith(
                    f"/proc/{os.getpid()}/fd/"
                )
            )
            self.assertTrue(
                sign_env["ANDROID_PW_FILE"].startswith(
                    f"/proc/{os.getpid()}/fd/"
                )
            )

            expected_runtime_stems = {
                role
                for role in (
                    *MAC_ROLES,
                    "releasekey",
                    "testkey-f88799ce31c1",
                    "com.android.art",
                )
            }
            expected_runtime_stems.add("./releasekey")
            self.assertEqual(set(tool_runner.password_entry_paths), expected_runtime_stems)
            self.assertEqual(
                (paths.public_keys_dir / "platform.x509.pem").read_bytes(),
                tool_runner.container_material["platform.x509.pem"],
            )
            self.assertEqual(
                (paths.public_keys_dir / "com.android.art.x509.pem").read_bytes(),
                tool_runner.container_material["com.android.art.x509.pem"],
            )

    def test_rewrites_mac_permissions_before_partition_image_signing(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            paths, secret = self.make_fixture(root)
            runner = FakeReleaseRunner(paths.output_dir)

            self.sign_release(
                paths,
                runner=runner,
                openssl_runner=FakeCryptoRunner(secret),
            )

            prepared_policy = runner.signing_mac_permissions
            with zipfile.ZipFile(paths.target_files) as unsigned:
                unsigned_policy = unsigned.read(
                    "SYSTEM/etc/selinux/plat_mac_permissions.xml"
                )
            with zipfile.ZipFile(paths.signed_target_files) as signed:
                signed_policy = signed.read(
                    "SYSTEM/etc/selinux/plat_mac_permissions.xml"
                )
                for trust_name in (
                    "BOOT/RAMDISK/system/etc/security/otacerts.zip",
                    "SYSTEM/etc/security/otacerts.zip",
                ):
                    with zipfile.ZipFile(
                        io.BytesIO(signed.read(trust_name))
                    ) as trust_archive:
                        self.assertEqual(
                            ["releasekey.x509.pem"], trust_archive.namelist()
                        )
                        self.assertEqual(
                            (paths.public_keys_dir / "releasekey.x509.pem").read_bytes(),
                            trust_archive.read("releasekey.x509.pem"),
                        )
            for role in MAC_ROLES:
                self.assertIn(fixture_der(role).hex().encode(), unsigned_policy)
                self.assertNotIn(fixture_der(role).hex().encode(), prepared_policy)
                self.assertIn(
                    fixture_der(role, release=True).hex().encode(), prepared_policy
                )
            self.assertEqual(prepared_policy, signed_policy)
            report = json.loads(paths.report.read_text(encoding="utf-8"))
            self.assertEqual(
                set(MAC_ROLES), set(report["selinux_mac_permissions"]["roles"])
            )

    def test_rejects_signed_target_files_that_drift_from_prepared_policy(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            paths, secret = self.make_fixture(root)
            runner = PolicyMutatingReleaseRunner(paths.output_dir)

            with self.assertRaisesRegex(
                self.ReleaseSigningError, "signed SELinux signer policy"
            ):
                self.sign_release(
                    paths,
                    runner=runner,
                    openssl_runner=FakeCryptoRunner(secret),
                )

            self.assertEqual(
                ["sign_target_files_apks"],
                [Path(call[0][0]).name for call in runner.calls],
            )
            self.assertFalse(paths.output_dir.exists())

    def test_rejects_unsafe_nested_otacerts_before_ota_generation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            paths, secret = self.make_fixture(root)
            runner = OtaCertMutatingReleaseRunner(paths.output_dir)

            with self.assertRaisesRegex(
                self.ReleaseSigningError, "signed OTA certificate inventory"
            ):
                self.sign_release(
                    paths,
                    runner=runner,
                    openssl_runner=FakeCryptoRunner(secret),
                )

            self.assertEqual(
                ["sign_target_files_apks"],
                [Path(call[0][0]).name for call in runner.calls],
            )
            self.assertFalse(paths.output_dir.exists())

    def test_rejects_unsafe_unselected_input_before_crypto_subprocess(self):
        for label, member in (
            ("unsafe", zipfile.ZipInfo("../unselected")),
            ("special-file", zipfile.ZipInfo("SYSTEM/bin/unselected-fifo")),
        ):
            if label == "special-file":
                member.create_system = 3
                member.external_attr = (stat.S_IFIFO | 0o600) << 16
            with self.subTest(label=label), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                paths, _secret = self.make_fixture(root)
                with zipfile.ZipFile(paths.target_files, "a") as archive:
                    archive.writestr(member, b"unselected")
                write_build_provenance(paths.build_provenance, paths.target_files)

                with self.assertRaisesRegex(self.ReleaseSigningError, label):
                    self.sign_release(
                        paths,
                        runner=lambda *_args, **_kwargs: self.fail(
                            "release tool must not run"
                        ),
                        openssl_runner=lambda *_args, **_kwargs: self.fail(
                            "crypto must not run"
                        ),
                    )

                self.assertFalse(paths.output_dir.exists())

    def test_generated_zip_validation_rejects_unsafe_members(self):
        from scripts.ubuntu.sign_release import _validate_zip

        with tempfile.TemporaryDirectory() as directory:
            archive_path = Path(directory) / "signed.zip"
            with zipfile.ZipFile(archive_path, "w") as archive:
                archive.writestr("../escape", b"bad")
            with self.assertRaisesRegex(self.ReleaseSigningError, "unsafe"):
                _validate_zip(archive_path)

    def test_zip_validators_reject_terminal_dot_but_allow_directory_entries(self):
        from scripts.ubuntu.sign_release import (
            _validate_signed_target_files,
            _validate_zip,
        )

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            unsigned = root / "unsigned.zip"
            with zipfile.ZipFile(unsigned, "w") as archive:
                archive.writestr("dir/", b"")

            valid = root / "valid-directory.zip"
            with zipfile.ZipFile(valid, "w") as archive:
                archive.writestr("dir/", b"")
            _validate_zip(valid)
            _validate_signed_target_files(valid, unsigned)

            for unsafe_name in (".", "dir/."):
                with self.subTest(validator="generic", member=unsafe_name):
                    generic = root / f"generic-{unsafe_name.replace('/', '-')}.zip"
                    with zipfile.ZipFile(generic, "w") as archive:
                        archive.writestr(unsafe_name, b"unsafe")
                    with self.assertRaisesRegex(self.ReleaseSigningError, "unsafe"):
                        _validate_zip(generic)

                with self.subTest(validator="signed-target", member=unsafe_name):
                    signed = root / f"signed-{unsafe_name.replace('/', '-')}.zip"
                    with zipfile.ZipFile(signed, "w") as archive:
                        archive.writestr(unsafe_name, b"unsafe")
                    with self.assertRaisesRegex(self.ReleaseSigningError, "unsafe"):
                        _validate_signed_target_files(signed, unsigned)

    def test_signed_target_files_symlink_manifest_must_match_unsigned(self):
        from scripts.ubuntu.sign_release import _validate_signed_target_files

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            unsigned = root / "unsigned.zip"
            expected = {
                "BOOT/RAMDISK/adb_keys": b"/product/etc/security/adb_keys",
                "SYSTEM/bin/tool": b"../lib64/tool",
            }
            with zipfile.ZipFile(unsigned, "w") as archive:
                archive.writestr("META/misc_info.txt", "fixture\n")
                for name, target in expected.items():
                    write_zip_symlink(archive, name, target)

            matching = root / "matching.zip"
            with zipfile.ZipFile(matching, "w") as archive:
                archive.writestr("META/misc_info.txt", "signed\n")
                for name, target in expected.items():
                    write_zip_symlink(archive, name, target)
            _validate_signed_target_files(matching, unsigned)

            variants = {
                "added": {
                    **expected,
                    "SYSTEM/bin/added": b"/system/lib64/added",
                },
                "removed": {
                    "BOOT/RAMDISK/adb_keys": expected["BOOT/RAMDISK/adb_keys"],
                },
                "retargeted": {
                    **expected,
                    "SYSTEM/bin/tool": b"../lib64/other",
                },
            }
            for label, links in variants.items():
                with self.subTest(change=label):
                    candidate = root / f"{label}.zip"
                    with zipfile.ZipFile(candidate, "w") as archive:
                        archive.writestr("META/misc_info.txt", "signed\n")
                        for name, target in links.items():
                            write_zip_symlink(archive, name, target)
                    with self.assertRaisesRegex(
                        self.ReleaseSigningError, "symlink manifest"
                    ):
                        _validate_signed_target_files(candidate, unsigned)

            mode_changed = root / "mode-changed.zip"
            with zipfile.ZipFile(mode_changed, "w") as archive:
                archive.writestr("META/misc_info.txt", "signed\n")
                for name, target in expected.items():
                    write_zip_symlink(
                        archive,
                        name,
                        target,
                        mode=0o755 if name == "SYSTEM/bin/tool" else 0o777,
                    )
            with self.assertRaisesRegex(self.ReleaseSigningError, "symlink manifest"):
                _validate_signed_target_files(mode_changed, unsigned)

    def test_signed_target_files_rejects_other_special_files(self):
        from scripts.ubuntu.sign_release import _validate_signed_target_files

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            unsigned = root / "unsigned.zip"
            signed = root / "signed.zip"
            for path in (unsigned, signed):
                with zipfile.ZipFile(path, "w") as archive:
                    special = zipfile.ZipInfo("SYSTEM/bin/fifo")
                    special.create_system = 3
                    special.external_attr = (stat.S_IFIFO | 0o600) << 16
                    archive.writestr(special, b"")

            with self.assertRaisesRegex(self.ReleaseSigningError, "special"):
                _validate_signed_target_files(signed, unsigned)

    def test_generic_ota_and_fastboot_validation_still_rejects_symlinks(self):
        from scripts.ubuntu.sign_release import _validate_zip

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for filename in ("ota.zip", "fastboot.zip"):
                with self.subTest(filename=filename):
                    archive_path = root / filename
                    with zipfile.ZipFile(archive_path, "w") as archive:
                        write_zip_symlink(
                            archive,
                            "META/link",
                            b"/system/etc/target",
                        )
                    with self.assertRaisesRegex(self.ReleaseSigningError, "symlink"):
                        _validate_zip(archive_path)

    def test_signing_accepts_unchanged_target_files_symlink_manifest(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            paths, secret = self.make_fixture(root)
            with zipfile.ZipFile(paths.target_files, "a") as archive:
                write_zip_symlink(
                    archive,
                    "BOOT/RAMDISK/adb_keys",
                    b"/product/etc/security/adb_keys",
                )
            write_build_provenance(paths.build_provenance, paths.target_files)
            base_runner = FakeReleaseRunner(paths.output_dir)

            def preserving_runner(command, *, env):
                base_runner(command, env=env)

            published = self.sign_release(
                paths,
                runner=preserving_runner,
                openssl_runner=FakeCryptoRunner(secret),
            )

            self.assertEqual(published, paths.output_dir)

    def test_rejects_source_filename_device_and_concurrent_replacement(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            paths, secret = self.make_fixture(root)

            wrong_name = paths.target_files.with_name("unsigned-target-files.zip")
            paths.target_files.rename(wrong_name)
            wrong_paths = self.SigningPaths(
                wrong_name,
                paths.android_root,
                paths.keys_dir,
                paths.output_dir,
            )
            with self.assertRaisesRegex(self.ReleaseSigningError, "filename"):
                self.sign_release(
                    wrong_paths,
                    runner=lambda *_args, **_kwargs: self.fail("release tool must not run"),
                    openssl_runner=lambda *_args, **_kwargs: self.fail("crypto must not run"),
                )

            wrong_name.rename(paths.target_files)
            write_target_files(
                paths.target_files,
                system_build_prop=SYSTEM_BUILD_PROP.replace("fleur", "other"),
            )
            with self.assertRaisesRegex(self.ReleaseSigningError, "provenance|device"):
                self.sign_release(
                    paths,
                    runner=lambda *_args, **_kwargs: self.fail("release tool must not run"),
                    openssl_runner=lambda *_args, **_kwargs: self.fail("crypto must not run"),
                )

            write_target_files(paths.target_files)
            base_runner = FakeReleaseRunner(paths.output_dir)

            def replacing_runner(command, *, env):
                base_runner(command, env=env)
                if Path(command[0]).name == "sign_target_files_apks":
                    replacement = root / "replacement.zip"
                    write_target_files(replacement)
                    os.replace(replacement, paths.target_files)

            with self.assertRaisesRegex(self.ReleaseSigningError, "changed"):
                self.sign_release(
                    paths,
                    runner=replacing_runner,
                    openssl_runner=FakeCryptoRunner(secret),
                )
            self.assertFalse(paths.output_dir.exists())

    def test_rejects_concurrent_helper_replacement_while_executing_pinned_inode(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            paths, secret = self.make_fixture(root)
            helper = root / "avb_signing_helper.py"
            helper.write_bytes(SIGNING_HELPER.read_bytes())
            helper.chmod(0o755)
            replacement = root / "replacement-helper.py"
            replacement.write_text("#!/usr/bin/env python3\nraise SystemExit(99)\n", encoding="utf-8")
            replacement.chmod(0o755)
            base_runner = FakeReleaseRunner(paths.output_dir)

            def replacing_runner(command, *, env):
                base_runner(command, env=env)
                if Path(command[0]).name == "sign_target_files_apks":
                    os.replace(replacement, helper)

            with self.assertRaisesRegex(self.ReleaseSigningError, "helper.*changed"):
                self.sign_release(
                    paths,
                    runner=replacing_runner,
                    openssl_runner=FakeCryptoRunner(secret),
                    signing_helper=helper,
                )
            self.assertFalse(paths.output_dir.exists())

    def test_rejects_concurrent_helper_config_replacement_while_using_held_config(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            paths, secret = self.make_fixture(root)
            base_runner = FakeReleaseRunner(paths.output_dir)

            def replacing_runner(command, *, env):
                if Path(command[0]).name == "sign_target_files_apks":
                    held_config = Path(env["FLEUR_AVB_SIGNING_CONFIG"])
                    original_config = held_config.read_bytes()
                    output = Path(command[-1])
                    named_config = output.parent / ".signing-runtime/avb-helper.json"
                    replacement = root / "replacement-helper.json"
                    replacement.write_text('{"schema_version": 2}\n', encoding="utf-8")
                    replacement.chmod(0o600)
                    os.replace(replacement, named_config)
                    self.assertEqual(held_config.read_bytes(), original_config)
                base_runner(command, env=env)

            with self.assertRaisesRegex(self.ReleaseSigningError, "config.*changed"):
                self.sign_release(
                    paths,
                    runner=replacing_runner,
                    openssl_runner=FakeCryptoRunner(secret),
                )
            self.assertFalse(paths.output_dir.exists())

    def test_rejects_apk_and_apex_container_source_key_replacement(self):
        cases = (("platform", ".pk8"), ("com.android.art", ".x509.pem"))
        for role, suffix in cases:
            with self.subTest(role=role, suffix=suffix), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                paths, secret = self.make_fixture(root)
                base_runner = FakeReleaseRunner(paths.output_dir)
                original_bytes = (paths.keys_dir / f"{role}{suffix}").read_bytes()

                def replacing_runner(command, *, env):
                    if Path(command[0]).name == "sign_target_files_apks":
                        source = paths.keys_dir / f"{role}{suffix}"
                        replacement = root / f"replacement-{role}{suffix}"
                        replacement.write_bytes(b"replacement-container-key")
                        replacement.chmod(0o600)
                        os.replace(replacement, source)
                    base_runner(command, env=env)

                with self.assertRaisesRegex(
                    self.ReleaseSigningError, "container key.*changed"
                ):
                    self.sign_release(
                        paths,
                        runner=replacing_runner,
                        openssl_runner=FakeCryptoRunner(secret),
                    )
                self.assertEqual(
                    base_runner.container_material[f"{role}{suffix}"],
                    original_bytes,
                )
                self.assertFalse(paths.output_dir.exists())

    def test_allows_zipwrite_metadata_round_trip_on_runtime_container_certificate(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            paths, secret = self.make_fixture(root)
            base_runner = FakeReleaseRunner(paths.output_dir)

            def zipwrite_runner(command, *, env):
                if Path(command[0]).name == "sign_target_files_apks":
                    runtime_key_dir = Path(command[command.index("-d") + 1])
                    certificate = runtime_key_dir / "releasekey.x509.pem"
                    original = certificate.stat(follow_symlinks=False)
                    certificate.chmod(0o644)
                    os.utime(
                        certificate,
                        ns=(original.st_atime_ns, original.st_mtime_ns + 1_000_000),
                    )
                    certificate.chmod(0o400)
                    os.utime(
                        certificate,
                        ns=(original.st_atime_ns, original.st_mtime_ns),
                    )
                    restored = certificate.stat(follow_symlinks=False)
                    self.assertEqual(stat.S_IMODE(restored.st_mode), 0o400)
                    self.assertEqual(restored.st_mtime_ns, original.st_mtime_ns)
                    self.assertNotEqual(restored.st_ctime_ns, original.st_ctime_ns)
                base_runner(command, env=env)

            published = self.sign_release(
                paths,
                runner=zipwrite_runner,
                openssl_runner=FakeCryptoRunner(secret),
            )

            self.assertEqual(published, paths.output_dir)
            self.assertTrue(paths.signed_target_files.is_file())

    def test_rejects_runtime_container_snapshot_content_size_or_mode_change(self):
        cases = ("content", "size", "mode")
        for mutation in cases:
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                paths, secret = self.make_fixture(root)
                base_runner = FakeReleaseRunner(paths.output_dir)

                def mutating_runner(command, *, env):
                    if Path(command[0]).name == "sign_target_files_apks":
                        runtime_key_dir = Path(command[command.index("-d") + 1])
                        snapshot = runtime_key_dir / "releasekey.x509.pem"
                        original = snapshot.read_bytes()
                        if mutation == "mode":
                            snapshot.chmod(0o444)
                        else:
                            snapshot.chmod(0o600)
                            snapshot.write_bytes(
                                (b"X" + original[1:])
                                if mutation == "content"
                                else original + b"X"
                            )
                            snapshot.chmod(0o400)
                    base_runner(command, env=env)

                with self.assertRaisesRegex(
                    self.ReleaseSigningError, "container key snapshot.*changed"
                ):
                    self.sign_release(
                        paths,
                        runner=mutating_runner,
                        openssl_runner=FakeCryptoRunner(secret),
                    )
                self.assertFalse(paths.output_dir.exists())

    def test_rejects_runtime_container_snapshot_replacement(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            paths, secret = self.make_fixture(root)
            base_runner = FakeReleaseRunner(paths.output_dir)

            def replacing_runner(command, *, env):
                if Path(command[0]).name == "sign_target_files_apks":
                    runtime_key_dir = Path(command[command.index("-d") + 1])
                    snapshot = runtime_key_dir / "releasekey.pk8"
                    runtime_key_dir.chmod(0o700)
                    replacement = root / "replacement-releasekey.pk8"
                    replacement.write_bytes(b"replacement-container-key")
                    replacement.chmod(0o400)
                    os.replace(replacement, snapshot)
                base_runner(command, env=env)

            with self.assertRaisesRegex(
                self.ReleaseSigningError, "container key snapshot.*changed"
            ):
                self.sign_release(
                    paths,
                    runner=replacing_runner,
                    openssl_runner=FakeCryptoRunner(secret),
                )
            self.assertFalse(paths.output_dir.exists())

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

    def test_rejects_build_provenance_replacement_during_signing(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            paths, secret = self.make_fixture(root)
            base = FakeReleaseRunner(paths.output_dir)

            def runner(command, *, env):
                if not base.calls:
                    replacement = root / "replacement-provenance.json"
                    replacement.write_text("{}", encoding="utf-8")
                    os.replace(replacement, paths.build_provenance)
                return base(command, env=env)

            with self.assertRaisesRegex(self.ReleaseSigningError, "build provenance.*changed"):
                self.sign_release(
                    paths, runner=runner, openssl_runner=FakeCryptoRunner(secret)
                )
            self.assertFalse(paths.output_dir.exists())

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
                "--build-provenance",
                str(paths.build_provenance),
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

    def test_dry_run_rejects_missing_android_jdk_java_despite_caller_path(self):
        from scripts.ubuntu.sign_release import main

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            paths, _secret = self.make_fixture(root)
            java = paths.android_root / "prebuilts/jdk/jdk21/linux-x86/bin/java"
            java.unlink()
            caller_bin = root / "caller-bin"
            caller_bin.mkdir()
            fallback_java = caller_bin / "java"
            fallback_java.write_text("#!/bin/sh\nexit 99\n", encoding="utf-8")
            fallback_java.chmod(0o755)
            arguments = [
                "--target-files", str(paths.target_files),
                "--android-root", str(paths.android_root),
                "--keys-dir", str(paths.keys_dir),
                "--output-dir", str(paths.output_dir),
                "--build-provenance", str(paths.build_provenance),
                "--dry-run",
            ]

            stderr = io.StringIO()
            with patch.dict(os.environ, {"PATH": str(caller_bin)}), redirect_stderr(stderr):
                self.assertEqual(main(arguments), 1)

            self.assertIn("JDK21 java", stderr.getvalue())
            self.assertFalse(paths.output_dir.exists())

    def test_dry_run_rejects_incomplete_mac_permissions_policy(self):
        from scripts.ubuntu.sign_release import main

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            paths, _secret = self.make_fixture(root)
            with zipfile.ZipFile(paths.target_files) as archive:
                entries = {
                    member.filename: archive.read(member)
                    for member in archive.infolist()
                }
            policy_name = "SYSTEM/etc/selinux/plat_mac_permissions.xml"
            entries[policy_name] = entries[policy_name].replace(
                b'<signer signature="'
                + fixture_der("nfc").hex().encode()
                + b'"><seinfo value="nfc"/></signer>',
                b"",
            )
            with zipfile.ZipFile(paths.target_files, "w") as archive:
                for name, value in entries.items():
                    archive.writestr(name, value)
            write_build_provenance(paths.build_provenance, paths.target_files)
            arguments = [
                "--target-files", str(paths.target_files),
                "--android-root", str(paths.android_root),
                "--keys-dir", str(paths.keys_dir),
                "--output-dir", str(paths.output_dir),
                "--build-provenance", str(paths.build_provenance),
                "--dry-run",
            ]
            stderr = io.StringIO()
            with redirect_stderr(stderr):
                self.assertEqual(1, main(arguments))
            self.assertIn("SELinux signer policy", stderr.getvalue())
            self.assertFalse(paths.output_dir.exists())

    def test_signing_rejects_missing_android_jdk_java_before_subprocess(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            paths, _secret = self.make_fixture(root)
            java = paths.android_root / "prebuilts/jdk/jdk21/linux-x86/bin/java"
            java.unlink()

            with self.assertRaisesRegex(self.ReleaseSigningError, "JDK21 java"):
                self.sign_release(
                    paths,
                    runner=lambda *_args, **_kwargs: self.fail("release tool must not run"),
                    openssl_runner=lambda *_args, **_kwargs: self.fail("crypto must not run"),
                )

            self.assertFalse(paths.output_dir.exists())
            self.assertEqual(list(root.glob(".20260829T123456Z.staging-*")), [])

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
            build_public_environment,
            build_signing_commands,
        )
        from scripts.ubuntu.signing_metadata import load_signing_inventory

        self.ReleaseSigningError = ReleaseSigningError
        self.SigningPaths = SigningPaths
        self.build_child_environment = build_child_environment
        self.build_public_environment = build_public_environment
        self.build_signing_commands = build_signing_commands
        self.load_signing_inventory = load_signing_inventory

    def test_builds_all_metadata_derived_commands_without_secret_transport(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target_files = root / "lineage_fleur-target_files.zip"
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
        self.assertIn(f"--signing_helper={SIGNING_HELPER}", sign)
        self.assertIn(
            "build/make/target/product/security/platform=platform",
            sign,
        )
        self.assertIn(
            "cts/hostsidetests/compilation/certs/testkey=testkey-f88799ce31c1",
            sign,
        )
        self.assertFalse(
            any(
                value.startswith("build/make/target/product/security/testkey=")
                for value in sign
            )
        )
        self.assertIn(
            "com.android.art.apex=com.android.art",
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

        nested = sign[sign.index("--avb_apex_extra_args") + 1]
        self.assertEqual(nested, f"--signing_helper={SIGNING_HELPER}")
        # apex_utils quotes this value as apexer's --signing_args operand;
        # apexer then applies shlex.split before extending the avbtool command.
        apexer_argv = shlex.split(f'--signing_args "{nested}"')
        signing_args = apexer_argv[apexer_argv.index("--signing_args") + 1]
        self.assertEqual(
            shlex.split(signing_args),
            [f"--signing_helper={SIGNING_HELPER}"],
        )

    def test_child_environments_prepend_android_jdk21_independently_of_caller_path(self):
        paths = self.SigningPaths(
            target_files=Path("/tmp/input.zip"),
            android_root=Path("/opt/android"),
            keys_dir=Path("/tmp/keys"),
            output_dir=Path("/tmp/20260829T123456Z"),
        )
        expected = (
            str(paths.host_tools),
            "/opt/android/prebuilts/jdk/jdk21/linux-x86/bin",
            "/caller-only",
        )

        with patch.dict(os.environ, {"PATH": "/caller-only"}):
            private_environment = self.build_child_environment(
                paths, Path("/tmp/helper.json")
            )
            public_environment = self.build_public_environment(paths)

        self.assertEqual(tuple(private_environment["PATH"].split(os.pathsep)), expected)
        self.assertEqual(tuple(public_environment["PATH"].split(os.pathsep)), expected)

    def test_removes_redundant_fleur_extra_recovery_key_mapping(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target_files = root / "lineage_fleur-target_files.zip"
            write_target_files(
                target_files,
                misc_info=(
                    MISC_INFO
                    + "extra_recovery_keys="
                    + "vendor/lineage/build/target/product/security/lineage\n"
                ),
            )
            paths = self.SigningPaths(
                target_files=target_files,
                android_root=root / "android",
                keys_dir=root / "keys",
                output_dir=root / "20260829T123456Z",
            )
            inventory = self.load_signing_inventory(target_files)

            commands = self.build_signing_commands(
                inventory,
                paths,
                signing_helper=SIGNING_HELPER,
                public_key_dir=paths.output_dir / ".signing-runtime/public-pem",
            )

        sign = list(commands.sign_target_files)
        expected = (
            "vendor/lineage/build/target/product/security/lineage="
            + str(paths.keys_dir / "releasekey")
        )
        self.assertFalse(
            any(sign[index : index + 2] == ["-k", expected] for index in range(len(sign) - 1))
        )
        self.assertEqual(".", sign[sign.index("-d") + 1])
        self.assertEqual("releasekey", commands.ota_from_target_files[2])

    def test_maps_nonblank_otakeys_source_to_releasekey(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target_files = root / "lineage_fleur-target_files.zip"
            write_target_files(
                target_files,
                otakeys="vendor/custom/security/ota.x509.pem\n",
            )
            paths = self.SigningPaths(
                target_files=target_files,
                android_root=root / "android",
                keys_dir=root / "keys",
                output_dir=root / "20260829T123456Z",
            )
            inventory = self.load_signing_inventory(target_files)

            commands = self.build_signing_commands(
                inventory,
                paths,
                signing_helper=SIGNING_HELPER,
                public_key_dir=paths.output_dir / ".signing-runtime/public-pem",
            )

        sign = list(commands.sign_target_files)
        expected = "vendor/custom/security/ota=" + str(paths.keys_dir / "releasekey")
        self.assertFalse(
            any(sign[index : index + 2] == ["-k", expected] for index in range(len(sign) - 1))
        )

    def test_disambiguates_android_role_collisions_with_apex_roles(self):
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
            device="fleur",
            build_tags=frozenset({"test-keys"}),
            uses_test_build_tags=True,
        )
        paths = self.SigningPaths(
            Path("/tmp/input.zip"),
            Path("/tmp/android"),
            Path("/tmp/keys"),
            Path("/tmp/20260829T123456Z"),
        )

        commands = self.build_signing_commands(
            inventory,
            paths,
            signing_helper=SIGNING_HELPER,
            public_key_dir=Path("/tmp/public-pem"),
        )

        suffix = hashlib.sha256(b"source/com.android.art").hexdigest()[:12]
        self.assertIn(
            f"source/com.android.art=com.android.art-{suffix}",
            commands.sign_target_files,
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

    def test_proc_fd_config_uses_real_loader_and_rejects_post_use_replacement(self):
        from scripts.ubuntu.sign_release import (
            ReleaseSigningError,
            _pin_private_runtime_file,
        )

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            private_key = root / "avb_boot.pem"
            public_key = root / "avb_boot.public.pem"
            password_file = root / "passwords"
            config = root / "helper.json"
            private_key.write_bytes(b"original-private")
            public_key.write_bytes(b"original-public")
            password_file.write_text(
                f"[[[ secret ]]] {private_key}\n", encoding="utf-8"
            )
            config.write_text(
                json.dumps(helper_config(private_key, public_key, password_file)),
                encoding="utf-8",
            )
            for path in (private_key, password_file, config):
                path.chmod(0o600)
            original_config = config.read_bytes()

            with _pin_private_runtime_file(
                config, "AVB helper config"
            ) as pinned_config:

                def replacing_runner(command, *, input_data, pass_fds):
                    replacement = root / "replacement-helper.json"
                    replacement.write_text(
                        '{"schema_version": 2}\n', encoding="utf-8"
                    )
                    replacement.chmod(0o600)
                    os.replace(replacement, config)
                    self.assertEqual(
                        pinned_config.proc_path.read_bytes(), original_config
                    )
                    return b"S" * 512

                signature = self.sign_payload(
                    pinned_config.proc_path,
                    "SHA256_RSA4096",
                    public_key,
                    b"padded-hash",
                    runner=replacing_runner,
                )

                self.assertEqual(signature, b"S" * 512)
                with self.assertRaisesRegex(
                    ReleaseSigningError, "config.*changed"
                ):
                    pinned_config.verify_named(
                        "AVB helper config", verify_hash=True
                    )

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
            config.write_text(json.dumps(helper_config(private_key, public_key, password_file)), encoding="utf-8")
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
            config.write_text(json.dumps(helper_config(private_key, public_key, password_file)), encoding="utf-8")
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

    def test_rejects_private_key_replacement_during_signing_after_using_held_fd(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            private_key = root / "avb_boot.pem"
            public_key = root / "avb_boot.public.pem"
            password_file = root / "passwords"
            config = root / "helper.json"
            private_key.write_bytes(b"original-private")
            public_key.write_bytes(b"original-public")
            password_file.write_text(f"[[[ secret ]]] {private_key}\n", encoding="utf-8")
            config.write_text(
                json.dumps(helper_config(private_key, public_key, password_file)),
                encoding="utf-8",
            )
            for path in (private_key, password_file, config):
                path.chmod(0o600)

            def replacing_runner(command, *, input_data, pass_fds):
                private_fd = int(command[command.index("-inkey") + 1].rsplit("/", 1)[1])
                self.assertEqual(os.pread(private_fd, 4096, 0), b"original-private")
                replacement = root / "replacement.pem"
                replacement.write_bytes(b"replacement-private")
                replacement.chmod(0o600)
                os.replace(replacement, private_key)
                return b"S" * 512

            with self.assertRaisesRegex(self.AvbSigningError, "identity"):
                self.sign_payload(
                    config,
                    "SHA256_RSA4096",
                    public_key,
                    b"padded-hash",
                    runner=replacing_runner,
                )

    def test_rejects_public_key_replacement_before_openssl(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            private_key = root / "avb_boot.pem"
            public_key = root / "avb_boot.public.pem"
            password_file = root / "passwords"
            config = root / "helper.json"
            private_key.write_bytes(b"original-private")
            public_key.write_bytes(b"original-public")
            password_file.write_text(f"[[[ secret ]]] {private_key}\n", encoding="utf-8")
            config.write_text(
                json.dumps(helper_config(private_key, public_key, password_file)),
                encoding="utf-8",
            )
            replacement = root / "replacement.pem"
            replacement.write_bytes(b"replacement-public")
            os.replace(replacement, public_key)
            for path in (private_key, public_key, password_file, config):
                path.chmod(0o600)

            with self.assertRaisesRegex(self.AvbSigningError, "identity"):
                self.sign_payload(
                    config,
                    "SHA256_RSA4096",
                    public_key,
                    b"padded-hash",
                    runner=lambda *_args, **_kwargs: self.fail("openssl must not run"),
                )


if __name__ == "__main__":
    unittest.main()
