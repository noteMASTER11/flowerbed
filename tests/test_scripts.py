from pathlib import Path
import os
import subprocess
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
    "liblz4-tool",
    "libncurses-dev",
    "libssl-dev",
    "libxml2",
    "libxml2-utils",
    "lzop",
    "pngcrush",
    "python-is-python3",
    "python3",
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


class ScriptTest(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
