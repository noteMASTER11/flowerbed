from pathlib import Path
import os
import subprocess
import tempfile
import uuid
import unittest


ROOT = Path(__file__).resolve().parents[1]
PACKAGES = {
    "bc",
    "bison",
    "build-essential",
    "ccache",
    "curl",
    "flex",
    "g++-multilib",
    "gcc-multilib",
    "git",
    "git-lfs",
    "gnupg",
    "gperf",
    "imagemagick",
    "lib32readline-dev",
    "lib32z1-dev",
    "libelf-dev",
    "libncurses-dev",
    "libssl-dev",
    "libxml2-utils",
    "lz4",
    "lzop",
    "pngcrush",
    "python-is-python3",
    "python3",
    "python3-protobuf",
    "python3-six",
    "repo",
    "rsync",
    "schedtool",
    "software-properties-common",
    "squashfs-tools",
    "xsltproc",
    "zip",
    "zlib1g-dev",
}


def shell_path(path: Path) -> str:
    resolved = path.resolve()
    if os.name != "nt":
        return str(resolved)
    drive, tail = os.path.splitdrive(str(resolved))
    return f"/mnt/{drive[0].lower()}/{tail.lstrip('\\/').replace('\\', '/')}"


def run_bash(*args: str) -> subprocess.CompletedProcess:
    if os.name == "nt":
        command = ["wsl.exe", "-d", "Ubuntu", "--", "bash", *args]
    else:
        command = ["bash", *args]
    return subprocess.run(
        command,
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )


def run_script(relative: str, *args: str) -> subprocess.CompletedProcess:
    return run_bash(shell_path(ROOT / relative), *args)


def run_script_with_env(
    relative: str, environment: dict[str, str], *args: str
) -> subprocess.CompletedProcess:
    assignments = [f"{key}={value}" for key, value in environment.items()]
    script = shell_path(ROOT / relative)
    if os.name == "nt":
        command = [
            "wsl.exe",
            "-d",
            "Ubuntu",
            "--",
            "env",
            *assignments,
            "bash",
            script,
            *args,
        ]
    else:
        command = ["env", *assignments, "bash", script, *args]
    return subprocess.run(
        command,
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )


class ScriptTest(unittest.TestCase):
    def test_bootstrap_uses_current_ubuntu_package_names(self):
        result = run_script("scripts/ubuntu/bootstrap.sh", "--print-packages")
        self.assertEqual(0, result.returncode, result.stdout)
        packages = set(result.stdout.splitlines())
        self.assertIn("lz4", packages)
        self.assertNotIn("liblz4-tool", packages)
        self.assertNotIn("libxml2", packages)

    def test_bootstrap_prints_exact_package_set_without_installing(self):
        result = run_script("scripts/ubuntu/bootstrap.sh", "--print-packages")
        self.assertEqual(0, result.returncode, result.stdout)
        self.assertEqual(PACKAGES, set(result.stdout.splitlines()))

    def test_bootstrap_dry_run_reports_every_external_change(self):
        result = run_script("scripts/ubuntu/bootstrap.sh", "--dry-run")
        self.assertEqual(0, result.returncode, result.stdout)
        self.assertIn("DRY-RUN sudo add-apt-repository -y universe", result.stdout)
        self.assertIn("DRY-RUN sudo apt-get update", result.stdout)
        self.assertIn("DRY-RUN sudo apt-get install -y", result.stdout)
        self.assertIn("DRY-RUN git lfs install", result.stdout)
        self.assertIn("DRY-RUN ccache -M 100G", result.stdout)

    def test_workspace_guard_rejects_windows_mount_before_existence_check(self):
        common = shell_path(ROOT / "scripts/ubuntu/lib/common.sh")
        result = run_bash(
            "-c",
            f"source '{common}'; require_ext4_workspace /mnt/d/path-that-does-not-exist",
        )
        self.assertNotEqual(0, result.returncode)
        self.assertIn("must not be under /mnt", result.stdout)

    def test_sync_dry_run_is_side_effect_free_and_complete(self):
        workspace = f"/tmp/flowerbed-sync-{uuid.uuid4().hex}"
        result = run_script("scripts/ubuntu/sync.sh", "--dry-run", workspace)
        self.assertEqual(0, result.returncode, result.stdout)
        self.assertIn(
            "repo init -u https://github.com/LineageOS/android.git -b lineage-23.2",
            result.stdout,
        )
        self.assertIn("fleur-lineage-23.2.xml", result.stdout)
        self.assertIn("repo sync", result.stdout)
        self.assertIn("repo manifest -r", result.stdout)
        existence = run_bash("-c", f"test ! -e '{workspace}'")
        self.assertEqual(0, existence.returncode, existence.stdout)

    def test_sync_validation_rejects_windows_mount(self):
        result = run_script(
            "scripts/ubuntu/sync.sh",
            "--validate-workspace",
            "/mnt/d/android",
        )
        self.assertNotEqual(0, result.returncode)
        self.assertIn("must not be under /mnt", result.stdout)

    def test_sync_stops_immediately_when_repo_sync_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fake_bin = root / "bin"
            fake_bin.mkdir()
            trace = root / "commands.trace"
            fake_repo = fake_bin / "repo"
            fake_repo.write_text(
                "#!/usr/bin/env bash\n"
                "printf 'repo %s\\n' \"$*\" >>\"$SYNC_TRACE_FILE\"\n"
                "if [[ \"$1\" == sync ]]; then exit 42; fi\n",
                encoding="utf-8",
                newline="\n",
            )
            fake_git = fake_bin / "git"
            fake_git.write_text(
                "#!/usr/bin/env bash\n"
                "printf 'git %s\\n' \"$*\" >>\"$SYNC_TRACE_FILE\"\n",
                encoding="utf-8",
                newline="\n",
            )
            fake_git_lfs = fake_bin / "git-lfs"
            fake_git_lfs.write_text("#!/usr/bin/env bash\n", encoding="utf-8", newline="\n")
            chmod = run_bash(
                "-c",
                "chmod 755 "
                f"'{shell_path(fake_repo)}' '{shell_path(fake_git)}' "
                f"'{shell_path(fake_git_lfs)}'",
            )
            self.assertEqual(0, chmod.returncode, chmod.stdout)

            home = run_bash("-lc", "printf '%s' \"$HOME\"").stdout
            workspace = f"{home}/.cache/flowerbed-tests/sync-failure-{uuid.uuid4().hex}"
            try:
                result = run_script_with_env(
                    "scripts/ubuntu/sync.sh",
                    {
                        "PATH": f"{shell_path(fake_bin)}:/usr/bin:/bin",
                        "SYNC_TRACE_FILE": shell_path(trace),
                    },
                    workspace,
                )
                self.assertEqual(42, result.returncode, result.stdout)
                calls = trace.read_text(encoding="utf-8").splitlines()
                self.assertTrue(any(call.startswith("repo init ") for call in calls))
                self.assertTrue(any(call.startswith("repo sync ") for call in calls))
                self.assertFalse(any(call.startswith("repo manifest ") for call in calls))
                self.assertFalse(any(call.startswith("git ") for call in calls))
            finally:
                self.assertTrue(workspace.startswith(f"{home}/.cache/flowerbed-tests/"))
                cleanup = run_bash("-c", f"rm -rf -- '{workspace}'")
                self.assertEqual(0, cleanup.returncode, cleanup.stdout)

    def test_build_dry_run_is_side_effect_free_and_selects_fleur(self):
        workspace = f"/tmp/flowerbed-build-{uuid.uuid4().hex}"
        result = run_script("scripts/ubuntu/build.sh", "--dry-run", workspace)
        self.assertEqual(0, result.returncode, result.stdout)
        self.assertIn("source build/envsetup.sh", result.stdout)
        self.assertIn("breakfast fleur", result.stdout)
        self.assertIn("m bacon -j8", result.stdout)
        self.assertIn("USE_CCACHE=1", result.stdout)
        existence = run_bash("-c", f"test ! -e '{workspace}'")
        self.assertEqual(0, existence.returncode, existence.stdout)

    def test_build_rejects_non_positive_jobs(self):
        for value in ("0", "-1", "not-a-number"):
            with self.subTest(jobs=value):
                result = run_script(
                    "scripts/ubuntu/build.sh",
                    "--dry-run",
                    "--jobs",
                    value,
                    "/tmp/unused-build-workspace",
                )
                self.assertNotEqual(0, result.returncode)
                self.assertIn("jobs must be a positive integer", result.stdout.lower())

    def test_device_collection_dry_run_has_no_side_effects(self):
        output = f"/tmp/flowerbed-device-{uuid.uuid4().hex}"
        result = run_script(
            "scripts/ubuntu/collect_device_logs.sh",
            "--dry-run",
            output,
        )
        self.assertEqual(0, result.returncode, result.stdout)
        self.assertIn("adb shell getprop ro.product.device", result.stdout)
        self.assertIn("adb shell getprop ro.miui.build.region", result.stdout)
        self.assertIn("adb shell ls -l /dev/block/bootdevice/by-name", result.stdout)
        self.assertIn("adb logcat -b all -d -v threadtime", result.stdout)
        existence = run_bash("-c", f"test ! -e '{output}'")
        self.assertEqual(0, existence.returncode, existence.stdout)

    def test_device_collection_executes_only_read_only_adb_commands(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fake_bin = root / "bin"
            fake_bin.mkdir()
            trace = root / "adb.trace"
            output = root / "device-output"
            fake_adb = fake_bin / "adb"
            fake_adb.write_text(
                "#!/usr/bin/env bash\n"
                "printf '%s\\n' \"$*\" >>\"$ADB_TRACE_FILE\"\n"
                "if [[ \"$*\" == get-state ]]; then printf 'device\\n'; exit 0; fi\n"
                "if [[ \"$*\" == 'shell dmesg' ]]; then printf 'permission denied\\n'; exit 1; fi\n"
                "printf 'fixture: %s\\n' \"$*\"\n",
                encoding="utf-8",
                newline="\n",
            )
            fake_bin_wsl = shell_path(fake_bin)
            trace_wsl = shell_path(trace)
            output_wsl = shell_path(output)
            chmod = run_bash("-c", f"chmod 755 '{shell_path(fake_adb)}'")
            self.assertEqual(0, chmod.returncode, chmod.stdout)
            result = run_script_with_env(
                "scripts/ubuntu/collect_device_logs.sh",
                {
                    "PATH": f"{fake_bin_wsl}:/usr/bin:/bin",
                    "ADB_TRACE_FILE": trace_wsl,
                },
                output_wsl,
            )
            self.assertEqual(0, result.returncode, result.stdout)
            calls = trace.read_text(encoding="utf-8").splitlines()
            self.assertIn("get-state", calls)
            self.assertIn("shell getprop ro.product.device", calls)
            self.assertIn("shell ls -l /dev/block/bootdevice/by-name", calls)
            self.assertIn("shell dmesg", calls)
            forbidden = ("reboot", "sideload", "flash", "erase", "wipe", "get-serialno")
            self.assertFalse(any(token in call for call in calls for token in forbidden))
            self.assertTrue((output / "properties.txt").is_file())
            self.assertTrue((output / "partitions.txt").is_file())
            self.assertIn("permission denied", (output / "dmesg.txt").read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
