from pathlib import Path
import subprocess
import unittest


ROOT = Path(__file__).resolve().parents[1]


class RepositoryContractTest(unittest.TestCase):
    def test_ubuntu_scripts_are_stored_with_lf_line_endings(self):
        result = subprocess.run(
            ["git", "check-attr", "eol", "--", "scripts/ubuntu/build.sh"],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        self.assertEqual(0, result.returncode, result.stdout)
        self.assertEqual(
            "scripts/ubuntu/build.sh: eol: lf",
            result.stdout.strip(),
        )

    def test_private_and_large_outputs_are_ignored(self):
        samples = (
            "artifacts/lineage-fleur.zip",
            "logs/build.log",
            "reports/private/device/getprop.txt",
            ".cache/repo/state",
            "out/target/product/fleur/boot.img",
        )
        for sample in samples:
            with self.subTest(path=sample):
                result = subprocess.run(
                    ["git", "check-ignore", "--quiet", "--", sample],
                    cwd=ROOT,
                    text=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                )
                self.assertEqual(0, result.returncode, result.stdout)


if __name__ == "__main__":
    unittest.main()
