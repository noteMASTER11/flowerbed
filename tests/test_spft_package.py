from pathlib import Path
import copy
import hashlib
import json
import subprocess
import tempfile
import unittest
import xml.etree.ElementTree as ET
import zipfile


ROOT = Path(__file__).resolve().parents[1]
PACKAGER = ROOT / "scripts" / "ubuntu" / "package_spft.py"

BUILD_IMAGES = {
    "boot.img",
    "dtbo.img",
    "vbmeta.img",
    "vbmeta_system.img",
    "vbmeta_vendor.img",
    "super.img",
}
FIRMWARE_IMAGES = {
    "audio_dsp.img",
    "gz.img",
    "lk.img",
    "logo.img",
    "md1img.img",
    "pi_img.img",
    "preloader_raw.img",
    "scp.img",
    "spmfw.img",
    "sspm.img",
    "tee.img",
}
ENABLED = {
    "vbmeta_a": "vbmeta.img",
    "vbmeta_system_a": "vbmeta_system.img",
    "vbmeta_vendor_a": "vbmeta_vendor.img",
    "md1img_a": "md1img.img",
    "spmfw_a": "spmfw.img",
    "audio_dsp_a": "audio_dsp.img",
    "pi_img_a": "pi_img.img",
    "scp_a": "scp.img",
    "sspm_a": "sspm.img",
    "gz_a": "gz.img",
    "lk_a": "lk.img",
    "boot_a": "boot.img",
    "dtbo_a": "dtbo.img",
    "tee_a": "tee.img",
    "logo_a": "logo.bin",
    "super": "super.img",
}


def partition_xml(name: str, file_name: str, enabled: bool, size: str) -> str:
    return f"""
    <partition_index name="{name}">
      <partition_name>{name}</partition_name>
      <file_name>{file_name}</file_name>
      <is_download>{str(enabled).lower()}</is_download>
      <type>NORMAL_ROM</type>
      <linear_start_addr>0x0</linear_start_addr>
      <physical_start_addr>0x0</physical_start_addr>
      <partition_size>{size}</partition_size>
      <region>EMMC_USER</region>
      <storage>HW_STORAGE_EMMC</storage>
      <boundary_check>true</boundary_check>
      <is_reserved>false</is_reserved>
      <operation_type>UPDATE</operation_type>
      <is_upgradable>true</is_upgradable>
      <empty_boot_needed>false</empty_boot_needed>
      <combo_partsize_check>false</combo_partsize_check>
      <reserve>0x00</reserve>
    </partition_index>"""


def write_template(path: Path, *, boot_size: str = "0x100") -> None:
    partitions = []
    for name, file_name in ENABLED.items():
        size = boot_size if name == "boot_a" else "0x100"
        partitions.append(partition_xml(name, file_name, True, size))
    for name, file_name in {
        "preloader": "preloader_fleur.bin",
        "preloader_backup": "preloader_fleur.bin",
        "cust": "cust.img",
        "rescue": "rescue.img",
        "userdata": "userdata.img",
        "logo_b": "logo.bin",
        "boot_b": "boot.img",
        "unknown": "unknown.img",
    }.items():
        partitions.append(partition_xml(name, file_name, True, "0x100"))
    path.write_text(
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
        "<root><general name=\"MTK_PLATFORM_CFG\"><config_version name=\"V2.2.0\">"
        "<platform>MT6781</platform><project>fleur</project>"
        "</config_version></general><storage_type name=\"EMMC\">"
        + "".join(partitions)
        + "</storage_type></root>\n",
        encoding="utf-8",
    )


class SpftPackageTest(unittest.TestCase):
    def make_fixture(self, root: Path, *, boot_bytes: bytes = b"boot"):
        product = root / "product"
        firmware = root / "firmware"
        product.mkdir()
        firmware.mkdir()
        for name in BUILD_IMAGES:
            (product / name).write_bytes(boot_bytes if name == "boot.img" else name.encode())
        for name in FIRMWARE_IMAGES:
            (firmware / name).write_bytes(name.encode())
        template = root / "MT6781_Android_scatter.xml"
        write_template(template)
        download_agent = root / "download_agent"
        download_agent.mkdir()
        (download_agent / "DA_BR.bin").write_bytes(b"official-download-agent")
        (download_agent / "flash.xml").write_text(
            "<?xml version=\"1.0\" encoding=\"UTF-8\" ?>\n"
            "<flash-mode><project>fleur</project><dagent>DA_BR.bin</dagent>"
            "<scatter>../MT6781_Android_scatter.xml</scatter>"
            "<version>1.0</version><arch>A32</arch></flash-mode>\n",
            encoding="utf-8",
        )
        (download_agent / "flash.xsd").write_text(
            "<?xml version=\"1.0\"?><xs:schema xmlns:xs=\"http://www.w3.org/2001/XMLSchema\"/>",
            encoding="utf-8",
        )
        manifest = root / "firmware.json"
        manifest.write_text(
            json.dumps(
                {
                    "schemaVersion": 1,
                    "device": "fleur",
                    "partitions": [
                        {
                            "name": path.stem,
                            "file": f"radio/{path.name}",
                            "size": path.stat().st_size,
                            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                        }
                        for path in sorted(firmware.iterdir())
                    ],
                }
            ),
            encoding="utf-8",
        )
        return template, product, firmware, manifest, download_agent

    def run_packager(
        self,
        root: Path,
        template: Path,
        product: Path,
        firmware: Path,
        manifest: Path,
        download_agent: Path,
    ):
        return subprocess.run(
            [
                "python",
                str(PACKAGER),
                "--scatter-xml",
                str(template),
                "--product-out",
                str(product),
                "--firmware-dir",
                str(firmware),
                "--firmware-manifest",
                str(manifest),
                "--download-agent-dir",
                str(download_agent),
                "--output-dir",
                str(root / "output"),
                "--name",
                "lineage-fleur-spft-reference",
            ],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )

    def test_package_enables_only_approved_a_slot_images(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            template, product, firmware, manifest, download_agent = self.make_fixture(root)
            result = self.run_packager(
                root, template, product, firmware, manifest, download_agent
            )
            self.assertEqual(0, result.returncode, result.stdout)

            report = json.loads(result.stdout)
            package = Path(report["directory"])
            download_xml = package / "images" / "MT6781_Android_scatter.xml"
            tree = ET.parse(download_xml)
            self.assertEqual("MT6781", tree.findtext("./general/config_version/platform"))
            self.assertEqual("fleur", tree.findtext("./general/config_version/project"))
            actual = {
                item.findtext("partition_name"): item.findtext("file_name")
                for item in tree.findall("./storage_type/partition_index")
                if item.findtext("is_download") == "true"
            }
            self.assertEqual(ENABLED, actual)

            image_names = {item.name for item in (package / "images").iterdir()}
            self.assertEqual(
                BUILD_IMAGES
                | (FIRMWARE_IMAGES - {"logo.img"})
                | {"logo.bin", "MT6781_Android_scatter.xml", "download_agent"},
                image_names,
            )
            readme = (package / "README.txt").read_text(encoding="utf-8")
            self.assertIn("Authentication", readme)
            self.assertIn("leave it blank", readme)
            self.assertIn("preloader", readme)
            self.assertIn("disabled", readme)

            sums = (package / "SHA256SUMS").read_text(encoding="utf-8").splitlines()
            expected_line = (
                f"{hashlib.sha256((package / 'images' / 'boot.img').read_bytes()).hexdigest()}"
                "  images/boot.img"
            )
            self.assertIn(expected_line, sums)
            archive = Path(report["archive"])
            with zipfile.ZipFile(archive) as handle:
                self.assertIsNone(handle.testzip())
                self.assertIn(
                    "lineage-fleur-spft-reference/images/MT6781_Android_scatter.xml",
                    handle.namelist(),
                )

    def test_package_rejects_an_image_larger_than_its_partition(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            template, product, firmware, manifest, download_agent = self.make_fixture(
                root, boot_bytes=b"x" * 257
            )
            result = self.run_packager(
                root, template, product, firmware, manifest, download_agent
            )
            self.assertNotEqual(0, result.returncode)
            self.assertIn("boot.img is 257 bytes", result.stdout)
            self.assertIn("boot_a allows 256 bytes", result.stdout)
            self.assertFalse((root / "output" / "lineage-fleur-spft-reference").exists())
            self.assertFalse((root / "output" / "lineage-fleur-spft-reference.zip").exists())

    def test_report_identifies_each_storage_variant_in_the_download_xml(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            template, product, firmware, manifest, download_agent = self.make_fixture(root)
            tree = ET.parse(template)
            emmc = tree.find("./storage_type")
            ufs = copy.deepcopy(emmc)
            ufs.set("name", "UFS")
            tree.getroot().append(ufs)
            tree.write(template, encoding="utf-8", xml_declaration=True)

            result = self.run_packager(
                root, template, product, firmware, manifest, download_agent
            )
            self.assertEqual(0, result.returncode, result.stdout)
            report = json.loads(result.stdout)
            self.assertEqual(
                {"EMMC", "UFS"},
                {item["storage"] for item in report["enabledPartitions"]},
            )

    def test_package_rejects_firmware_that_differs_from_the_pinned_manifest(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            template, product, firmware, manifest, download_agent = self.make_fixture(root)
            (firmware / "tee.img").write_bytes(b"changed")
            result = self.run_packager(
                root, template, product, firmware, manifest, download_agent
            )
            self.assertNotEqual(0, result.returncode)
            self.assertIn("firmware SHA-256 mismatch for tee.img", result.stdout)

    def test_package_emits_the_v6_flash_wrapper_and_download_agent(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            template, product, firmware, manifest, download_agent = self.make_fixture(root)
            result = self.run_packager(
                root, template, product, firmware, manifest, download_agent
            )
            self.assertEqual(0, result.returncode, result.stdout)
            package = Path(json.loads(result.stdout)["directory"])
            wrapper = package / "images" / "download_agent" / "flash.xml"
            tree = ET.parse(wrapper)
            self.assertEqual("fleur", tree.findtext("./project"))
            self.assertEqual("DA_BR.bin", tree.findtext("./dagent"))
            self.assertEqual("../MT6781_Android_scatter.xml", tree.findtext("./scatter"))
            self.assertEqual(
                b"official-download-agent",
                (wrapper.parent / "DA_BR.bin").read_bytes(),
            )
            readme = (package / "README.txt").read_text(encoding="utf-8")
            self.assertIn("images/download_agent/flash.xml", readme)


if __name__ == "__main__":
    unittest.main()
