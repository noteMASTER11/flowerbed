from pathlib import Path
import os
import shutil
import subprocess
import tempfile
import uuid
import unittest
import zipfile


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
    def _target_files_runner_fixture(self, root: Path, mode: str) -> tuple[Path, Path]:
        repo = root / "repo"
        workspace = root / "android"
        fake_bin = root / "bin"
        trace = root / "trace.txt"
        (repo / "scripts/ubuntu/lib").mkdir(parents=True)
        (repo / "sources").mkdir()
        (repo / "patches/android_kernel_xiaomi_mt6781").mkdir(parents=True)
        (workspace / "build").mkdir(parents=True)
        (workspace / "device/xiaomi/fleur").mkdir(parents=True)
        (workspace / "vendor/xiaomi/fleur").mkdir(parents=True)
        (workspace / "kernel/xiaomi/mt6781").mkdir(parents=True)
        fake_bin.mkdir()
        shutil.copy2(ROOT / "scripts/ubuntu/build_target_files.sh", repo / "scripts/ubuntu")
        shutil.copy2(ROOT / "scripts/ubuntu/lib/common.sh", repo / "scripts/ubuntu/lib")
        (repo / "sources/kernel-fix.json").write_text("{}\n", encoding="utf-8")
        (repo / "patches/android_kernel_xiaomi_mt6781/0001-mdpm-cfi-function-pointer-signature.patch").write_text("patch\n", encoding="utf-8")
        (repo / "scripts/ubuntu/apply_patches.sh").write_text("#!/usr/bin/env bash\n", encoding="utf-8")
        (repo / "scripts/ubuntu/build_provenance.py").write_text(
            "#!/usr/bin/env python3\n"
            "import os\n"
            "from pathlib import Path\n"
            "import sys\n"
            "command = sys.argv[1]\n"
            "with Path(os.environ['TRACE']).open('a', encoding='utf-8') as trace:\n"
            "    trace.write(command + '\\n')\n"
            "if os.environ['FIXTURE_MODE'] == 'prebuild' and command == 'pre-build':\n"
            "    raise SystemExit(71)\n"
            "if os.environ['FIXTURE_MODE'] == 'finalize' and command == 'finalize':\n"
            "    raise SystemExit(72)\n"
            "Path(sys.argv[sys.argv.index('--output') + 1]).write_text(command + '\\n', encoding='utf-8')\n",
            encoding="utf-8",
        )
        (workspace / "build/envsetup.sh").write_text(
            "if [[ \"${FIXTURE_MODE:-}\" == envsetup ]]; then return 61; fi\n"
            "breakfast() {\n"
            "  printf 'breakfast\\n' >>\"$TRACE\"\n"
            "  [[ \"${FIXTURE_MODE:-}\" != breakfast ]] || return 62\n"
            "}\n"
            "m() {\n"
            "  printf 'm:%s\\n' \"$*\" >>\"$TRACE\"\n"
            "  [[ \"${FIXTURE_MODE:-}\" != m ]] || return 63\n"
            "  case \"${FIXTURE_MODE:-}\" in\n"
            "    stale) printf 'Packaging target files: out/target/product/fleur/obj/PACKAGING/target_files_intermediates/lineage_fleur-target_files.zip\\n' ;;\n"
            "    touch) touch \"$target_files\"; printf 'Packaging target files: out/target/product/fleur/obj/PACKAGING/target_files_intermediates/lineage_fleur-target_files.zip\\n' ;;\n"
            "    copy) cp \"$(find \"$(dirname \"$target_files\")\" -maxdepth 1 -name \"lineage_fleur-target_files.zip.pre-run-*\" -print -quit)\" \"$target_files\"; printf 'Packaging target files: out/target/product/fleur/obj/PACKAGING/target_files_intermediates/lineage_fleur-target_files.zip\\n' ;;\n"
            "    *) make_target \"$target_files\"; printf 'Packaging target files: out/target/product/fleur/obj/PACKAGING/target_files_intermediates/lineage_fleur-target_files.zip\\n' ;;\n"
            "  esac\n"
            "}\n",
            encoding="utf-8",
        )
        (fake_bin / "ccache").write_text(
            "#!/usr/bin/env bash\n"
            "printf 'ccache:%s\\n' \"$*\" >>\"$TRACE\"\n"
            "if [[ \"${FIXTURE_MODE:-}\" == ccache-resource && \"$*\" == -s ]]; then exit 75; fi\n"
            "[[ \"${FIXTURE_MODE:-}\" != ccache ]] || exit 60\n",
            encoding="utf-8",
        )
        (fake_bin / "tee").write_text(
            "#!/usr/bin/env bash\n"
            "if [[ \"${FIXTURE_MODE:-}\" == tee-delay ]]; then sleep 0.2; fi\n"
            "if [[ \"${FIXTURE_MODE:-}\" == tee-failure ]]; then /bin/cat >\"$1\"; exit 70; fi\n"
            "exec /usr/bin/tee \"$@\"\n",
            encoding="utf-8",
        )
        (fake_bin / "free").write_text(
            "#!/usr/bin/env bash\n"
            "printf 'free\\n' >>\"$TRACE\"\n"
            "[[ \"${FIXTURE_MODE:-}\" != free ]] || exit 73\n"
            "exec /usr/bin/free \"$@\"\n",
            encoding="utf-8",
        )
        (fake_bin / "df").write_text(
            "#!/usr/bin/env bash\n"
            "printf 'df\\n' >>\"$TRACE\"\n"
            "[[ \"${FIXTURE_MODE:-}\" != df ]] || exit 74\n"
            "exec /usr/bin/df \"$@\"\n",
            encoding="utf-8",
        )
        (fake_bin / "cat").write_text(
            "#!/usr/bin/env bash\n"
            "printf 'cat\\n' >>\"$TRACE\"\n"
            "[[ \"${FIXTURE_MODE:-}\" != resource-write ]] || exit 77\n"
            "exec /bin/cat \"$@\"\n",
            encoding="utf-8",
        )
        (fake_bin / "python3").write_text(
            "#!/usr/bin/env bash\n"
            "if [[ \"$1\" == - && \"$#\" -eq 16 ]]; then\n"
            "  printf 'metadata\\n' >>\"$TRACE\"\n"
            "  [[ \"${FIXTURE_MODE:-}\" != metadata ]] || exit 76\n"
            "fi\n"
            "exec /usr/bin/python3 \"$@\"\n",
            encoding="utf-8",
        )
        (fake_bin / "repo").write_text(
            "#!/usr/bin/env bash\n"
            "printf 'manifest\\n' >>\"$TRACE\"\n"
            "[[ \"${FIXTURE_MODE:-}\" != manifest ]] || exit 64\n"
            "printf '<manifest/>\\n'\n",
            encoding="utf-8",
        )
        (fake_bin / "make_target").write_text(
            "#!/usr/bin/env python3\n"
            "from pathlib import Path\n"
            "import sys\n"
            "import zipfile\n"
            "target = Path(sys.argv[1])\n"
            "target.parent.mkdir(parents=True, exist_ok=True)\n"
            "with zipfile.ZipFile(target, 'w') as archive:\n"
            "    archive.writestr('IMAGES/boot.img', b'new-boot')\n",
            encoding="utf-8",
        )
        for executable in (
            repo / "scripts/ubuntu/build_target_files.sh",
            repo / "scripts/ubuntu/build_provenance.py",
            repo / "scripts/ubuntu/apply_patches.sh",
            fake_bin / "ccache", fake_bin / "repo", fake_bin / "make_target",
            fake_bin / "tee", fake_bin / "free", fake_bin / "df", fake_bin / "cat",
            fake_bin / "python3",
        ):
            executable.chmod(0o755)
        target = workspace / "out/target/product/fleur/obj/PACKAGING/target_files_intermediates/lineage_fleur-target_files.zip"
        target.parent.mkdir(parents=True)
        with zipfile.ZipFile(target, "w") as archive:
            archive.writestr("IMAGES/boot.img", b"previous-boot")
        return repo, workspace

    def test_target_files_runner_waits_for_logger_and_finalizes_after_all_evidence(self):
        cache_root = Path.home() / ".cache/flowerbed-tests"
        cache_root.mkdir(parents=True, exist_ok=True)
        expected_exit_codes = {
            "ccache": 60, "envsetup": 61, "breakfast": 62,
            "prebuild": 71, "m": 63, "tee-failure": 70, "finalize": 72,
        }
        expected_failures = {
            "stale": "target-files output is missing",
            "touch": "target-files output is not a valid ZIP",
            "copy": "target-files output matches preserved pre-run artifact",
            "manifest": "Unable to create resolved manifest snapshot",
        }
        no_m = {"ccache", "envsetup", "breakfast", "prebuild"}
        resource_failures = {"free": 73, "df": 74, "ccache-resource": 75, "resource-write": 77, "metadata": 76}
        no_finalize = (set(expected_exit_codes) - {"finalize"}) | set(expected_failures) | set(resource_failures)
        preserved_failed_output = {"tee-failure", "touch", "copy", "manifest", "free", "df", "ccache-resource", "resource-write", "metadata"}
        for mode in (*expected_exit_codes, *expected_failures, *resource_failures):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory(
                dir=cache_root
            ) as directory:
                root = Path(directory)
                repo, workspace = self._target_files_runner_fixture(root, mode)
                environment = {
                    "PATH": f"{shell_path(root / 'bin')}:/usr/bin:/bin",
                    "TRACE": shell_path(root / "trace.txt"),
                    "FIXTURE_MODE": mode,
                }
                result = run_bash(
                    "-c",
                    " ".join(f"{key}='{value}'" for key, value in environment.items())
                    + f" bash '{shell_path(repo / 'scripts/ubuntu/build_target_files.sh')}' '{shell_path(workspace)}'",
                )
                self.assertNotEqual(0, result.returncode, result.stdout)
                if mode == "finalize":
                    self.assertEqual(expected_exit_codes[mode], result.returncode)
                elif mode in expected_exit_codes:
                    self.assertIn(
                        f"Target-files build exit code: {expected_exit_codes[mode]}",
                        result.stdout,
                    )
                elif mode in expected_failures:
                    self.assertIn(expected_failures[mode], result.stdout)
                trace = (root / "trace.txt").read_text(encoding="utf-8")
                if mode in no_m:
                    self.assertNotIn("m:", trace)
                if mode in no_finalize:
                    self.assertNotIn("finalize", trace)
                self.assertEqual([], list((repo / "logs").glob("*.build-provenance.json")))
                target = workspace / "out/target/product/fleur/obj/PACKAGING/target_files_intermediates/lineage_fleur-target_files.zip"
                if mode != "finalize":
                    with zipfile.ZipFile(target) as archive:
                        self.assertEqual(b"previous-boot", archive.read("IMAGES/boot.img"))
                if mode in preserved_failed_output:
                    self.assertEqual(
                        1,
                        len(list(target.parent.glob("lineage_fleur-target_files.zip.pre-final-failed-*"))),
                    )

        for mode in ("success", "tee-delay"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory(dir=cache_root) as directory:
                root = Path(directory)
                repo, workspace = self._target_files_runner_fixture(root, mode)
                result = run_bash(
                    "-c",
                    f"PATH='{shell_path(root / 'bin')}:/usr/bin:/bin' "
                    f"TRACE='{shell_path(root / 'trace.txt')}' FIXTURE_MODE={mode} "
                    f"bash '{shell_path(repo / 'scripts/ubuntu/build_target_files.sh')}' '{shell_path(workspace)}'",
                )
                self.assertEqual(0, result.returncode, result.stdout)
                trace = (root / "trace.txt").read_text(encoding="utf-8").splitlines()
                self.assertEqual(
                    ["ccache:-M 100G", "ccache:-z", "breakfast", "pre-build", "m:target-files-package otatools -j8", "manifest", "free", "df", "ccache:-s", "cat", "metadata", "finalize"],
                    trace,
                )
                target_dir = workspace / "out/target/product/fleur/obj/PACKAGING/target_files_intermediates"
                backups = list(target_dir.glob("lineage_fleur-target_files.zip.pre-run-*"))
                self.assertEqual(1, len(backups))
                with zipfile.ZipFile(backups[0]) as archive:
                    self.assertEqual(b"previous-boot", archive.read("IMAGES/boot.img"))
                self.assertEqual(1, len(list((repo / "logs").glob("*.build-provenance.json"))))
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
        self.assertIn("script --quiet --return --flush --command", result.stdout)
        self.assertIn("repo sync", result.stdout)
        self.assertIn("apply_patches.sh", result.stdout)
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
                "if [[ \"$1\" == init ]]; then\n"
                "  grep -q 'flowerbed-github' "
                ".repo/local_manifests/fleur-lineage-23.2.xml || exit 43\n"
                "fi\n"
                "if [[ \"$1\" == sync ]]; then\n"
                "  [[ -t 1 && -t 2 ]] || exit 44\n"
                "  exit 42\n"
                "fi\n",
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

    def test_apply_patches_selects_memtrack_module_defined_by_pinned_hardware(self):
        home = run_bash("-lc", "printf '%s' \"$HOME\"").stdout
        sandbox = f"{home}/.cache/flowerbed-tests/apply-patches-{uuid.uuid4().hex}"
        device_tree = f"{sandbox}/device/xiaomi/fleur"
        kernel_tree = f"{sandbox}/kernel/xiaomi/mt6781"
        try:
            setup = run_bash(
                "-c",
                f"mkdir -p '{device_tree}/sepolicy/vendor' '{device_tree}/sku' "
                f"'{kernel_tree}/drivers/misc/mediatek/base/power/include/mdpm_v2/mt6781' && "
                f"printf '%s\\n' '# Graphics' 'PRODUCT_PACKAGES += \\' "
                f"'    android.hardware.graphics.composer@2.3-service \\' "
                f"'    android.hardware.memtrack-service.mediatek-mali' '' "
                f"'# Health' 'PRODUCT_PACKAGES += \\' "
                f">'{device_tree}/device.mk' && "
                f"printf '%s\\n' 'vendor_public_prop(vendor_thermal_engine_prop)' "
                f"'vendor_restricted_prop(vendor_camera_prop)' "
                f"'vendor_internal_prop(vendor_camera_persist_prop)' "
                f"'vendor_internal_prop(vendor_dynamic_sensor_prop)' "
                f">'{device_tree}/sepolicy/vendor/property.te' && "
                f"printf '%s\\n' '# Graphics' "
                f"'genfscon sysfs /devices/platform/14000000.dispsys_config/drm/card0/card0-DSI-1/panel_event u:object_r:vendor_sysfs_panel:s0' "
                f"'genfscon sysfs /devices/platform/14000000.dispsys_config/drm/card0/card0-DSI-1/panel_info u:object_r:vendor_sysfs_panel:s0' "
                f"'genfscon sysfs /devices/platform/14000000.dispsys_config/idle_state u:object_r:vendor_sysfs_panel:s0' "
                f"'genfscon sysfs /devices/platform/13000000.mali/dvfs_period u:object_r:sysfs_gpu:s0' "
                f"'genfscon sysfs /devices/platform/13000000.mali/js_ctx_scheduling_mode u:object_r:sysfs_gpu:s0' "
                f"'genfscon sysfs /devices/platform/13000000.mali/js_scheduling_period u:object_r:sysfs_gpu:s0' "
                f"'' '# Health' "
                f">'{device_tree}/sepolicy/vendor/genfs_contexts' && "
                f"printf '%s\\n' '# Camera' "
                f"'persist.vendor.camera. u:object_r:vendor_camera_persist_prop:s0' "
                f"'vendor.camera. u:object_r:vendor_camera_prop:s0' "
                f"'vendor.debug. u:object_r:vendor_camera_prop:s0' "
                f"'' '# Dynamic sensor' "
                f"'vendor.dynamic_sensor. u:object_r:vendor_dynamic_sensor_prop:s0' "
                f"'' '# Fingerprint' "
                f"'persist.vendor.sys.fp. u:object_r:vendor_fp_prop:s0' "
                f"'' '# RIL' "
                f"'ro.vendor.oem. u:object_r:vendor_mtk_radio_prop:s0' "
                f"'ro.vendor.vt. u:object_r:vendor_mtk_radio_prop:s0' "
                f"'' '# Thermal' "
                f">'{device_tree}/sepolicy/vendor/property_contexts' && "
                f"printf '%s\\n' 'bluetooth.device.default_name=Redmi Note 11S' "
                f"'vendor.usb.product_string=Redmi Note 11S' 'ro.product.odm.brand=Redmi' "
                f"'ro.product.odm.device=fleur' 'ro.product.odm.model=fleur' "
                f"'ro.product.odm.name=fleur_global' >'{device_tree}/sku/build_fleur.prop' && "
                f"printf '%s\\n' 'bluetooth.device.default_name=Redmi Note 11S' "
                f"'vendor.usb.product_string=Redmi Note 11S' 'ro.product.odm.brand=Redmi' "
                f"'ro.product.odm.device=miel' 'ro.product.odm.model=miel' "
                f"'ro.product.odm.name=miel_global' >'{device_tree}/sku/build_miel.prop' && "
                f"printf '%s\\n' 'bluetooth.device.default_name=POCO M4 Pro' "
                f"'vendor.usb.product_string=POCO M4 Pro' 'ro.product.odm.brand=POCO' "
                f"'ro.product.odm.device=fleur' 'ro.product.odm.model=fleur' "
                f"'ro.product.odm.name=fleur_p_global' >'{device_tree}/sku/build_fleurp.prop' && "
                f"printf '%s\\n' 'bluetooth.device.default_name=POCO M4 Pro' "
                f"'vendor.usb.product_string=POCO M4 Pro' 'ro.product.odm.brand=POCO' "
                f"'ro.product.odm.device=miel' 'ro.product.odm.model=miel' "
                f"'ro.product.odm.name=miel_p_global' >'{device_tree}/sku/build_mielp.prop' && "
                f"printf '%b\\n' 'struct mdpm_scenario {{' "
                f"'\\tchar scenario_name[MAX_MDPM_NAME_LEN];' "
                f"'\\tstruct scenario_power_type_t *scenario_power;' "
                f"'\\tenum tx_rat_type tx_power_rat[MAX_DBM_FUNC_NUM];' "
                f"'\\tint (*tx_power_func)(u32 *dbm_mem, u32 *old_dbm_mem, unsigned int rat,' "
                f"'\\t\\tunsigned int power_type, struct md_power_status *md_power_s);' "
                f"'}};' '' '#ifdef MD_POWER_UT' "
                f">'{kernel_tree}/drivers/misc/mediatek/base/power/include/mdpm_v2/mt6781/mtk_mdpm_platform.h' && "
                f"git -C '{device_tree}' init -q && "
                f"git -C '{device_tree}' add device.mk sepolicy sku && "
                f"git -C '{device_tree}' -c user.name=Test "
                f"-c user.email=test@example.invalid commit -qm fixture && "
                f"git -C '{kernel_tree}' init -q && "
                f"git -C '{kernel_tree}' add drivers && "
                f"git -C '{kernel_tree}' -c user.name=Test "
                f"-c user.email=test@example.invalid commit -qm fixture",
            )
            self.assertEqual(0, setup.returncode, setup.stdout)

            result = run_script("scripts/ubuntu/apply_patches.sh", sandbox)
            self.assertEqual(0, result.returncode, result.stdout)
            device_mk = run_bash("-c", f"cat '{device_tree}/device.mk'")
            self.assertEqual(0, device_mk.returncode, device_mk.stdout)
            self.assertIn(
                "android.hardware.memtrack-service.mediatek\n",
                device_mk.stdout,
            )
            self.assertNotIn(
                "android.hardware.memtrack-service.mediatek-mali",
                device_mk.stdout,
            )
            property_te = run_bash(
                "-c", f"cat '{device_tree}/sepolicy/vendor/property.te'"
            )
            self.assertEqual(0, property_te.returncode, property_te.stdout)
            self.assertNotIn(
                "vendor_internal_prop(vendor_dynamic_sensor_prop)",
                property_te.stdout,
            )
            self.assertIn(
                "vendor_public_prop(vendor_thermal_engine_prop)",
                property_te.stdout,
            )
            genfs_contexts = run_bash(
                "-c", f"cat '{device_tree}/sepolicy/vendor/genfs_contexts'"
            )
            self.assertEqual(0, genfs_contexts.returncode, genfs_contexts.stdout)
            self.assertNotIn(
                "/devices/platform/13000000.mali/",
                genfs_contexts.stdout,
            )
            self.assertIn(
                "/devices/platform/14000000.dispsys_config/idle_state",
                genfs_contexts.stdout,
            )
            property_contexts = run_bash(
                "-c", f"cat '{device_tree}/sepolicy/vendor/property_contexts'"
            )
            self.assertEqual(0, property_contexts.returncode, property_contexts.stdout)
            self.assertNotIn("vendor.dynamic_sensor.", property_contexts.stdout)
            self.assertIn("persist.vendor.camera.", property_contexts.stdout)
            self.assertNotIn("ro.vendor.vt.", property_contexts.stdout)
            self.assertIn("ro.vendor.oem.", property_contexts.stdout)

            second = run_script("scripts/ubuntu/apply_patches.sh", sandbox)
            self.assertEqual(0, second.returncode, second.stdout)
            self.assertIn("already applied", second.stdout.lower())
        finally:
            self.assertTrue(sandbox.startswith(f"{home}/.cache/flowerbed-tests/"))
            cleanup = run_bash("-c", f"rm -rf -- '{sandbox}'")
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

    def test_build_verbose_passes_verbose_flag_to_ninja(self):
        result = run_script(
            "scripts/ubuntu/build.sh",
            "--dry-run",
            "--verbose",
            "/tmp/unused-build-workspace",
        )
        self.assertEqual(0, result.returncode, result.stdout)
        self.assertIn("export SOONG_UI_NINJA_ARGS=-v", result.stdout)
        self.assertIn("m bacon -j8", result.stdout)
        self.assertNotIn("showcommands", result.stdout)

    def test_build_sources_android_envsetup_without_nounset(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = Path(directory)
            fake_bin = fixture / "bin"
            fake_bin.mkdir()
            fake_ccache = fake_bin / "ccache"
            fake_ccache.write_text(
                "#!/usr/bin/env bash\n"
                "printf 'ccache:%s\\n' \"$*\"\n",
                encoding="utf-8",
                newline="\n",
            )
            envsetup = fixture / "envsetup.sh"
            envsetup.write_text(
                "#!/usr/bin/env bash\n"
                "if [[ -z \"$TOP\" ]]; then TOP=$PWD; fi\n"
                "breakfast() { printf 'breakfast:%s\\n' \"$*\"; }\n"
                "m() { printf 'm:%s\\n' \"$*\"; }\n",
                encoding="utf-8",
                newline="\n",
            )

            home = run_bash("-lc", "printf '%s' \"$HOME\"").stdout
            sandbox = f"{home}/.cache/flowerbed-tests/build-envsetup-{uuid.uuid4().hex}"
            repo = f"{sandbox}/repo"
            workspace = f"{sandbox}/android"
            try:
                setup = run_bash(
                    "-c",
                    f"mkdir -p '{repo}/scripts/ubuntu/lib' "
                    f"'{workspace}/build' '{workspace}/device/xiaomi/fleur' "
                    f"'{workspace}/vendor/xiaomi/fleur' '{workspace}/kernel/xiaomi/mt6781' && "
                    f"cp '{shell_path(ROOT / 'scripts/ubuntu/build.sh')}' "
                    f"'{repo}/scripts/ubuntu/build.sh' && "
                    f"cp '{shell_path(ROOT / 'scripts/ubuntu/lib/common.sh')}' "
                    f"'{repo}/scripts/ubuntu/lib/common.sh' && "
                    f"cp '{shell_path(envsetup)}' '{workspace}/build/envsetup.sh' && "
                    f"chmod 755 '{repo}/scripts/ubuntu/build.sh' "
                    f"'{repo}/scripts/ubuntu/lib/common.sh' "
                    f"'{workspace}/build/envsetup.sh' '{shell_path(fake_ccache)}'",
                )
                self.assertEqual(0, setup.returncode, setup.stdout)

                result = run_bash(
                    "-c",
                    f"PATH='{shell_path(fake_bin)}:/usr/bin:/bin' "
                    f"bash '{repo}/scripts/ubuntu/build.sh' --jobs 8 '{workspace}'",
                )
                self.assertEqual(0, result.returncode, result.stdout)
                self.assertIn("breakfast:fleur", result.stdout)
                self.assertIn("m:bacon -j8", result.stdout)
            finally:
                self.assertTrue(sandbox.startswith(f"{home}/.cache/flowerbed-tests/"))
                cleanup = run_bash("-c", f"rm -rf -- '{sandbox}'")
                self.assertEqual(0, cleanup.returncode, cleanup.stdout)

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

    def test_target_files_dry_run_is_side_effect_free_and_selects_fleur(self):
        workspace = f"/tmp/flowerbed-target-files-{uuid.uuid4().hex}"
        result = run_script(
            "scripts/ubuntu/build_target_files.sh", "--dry-run", workspace
        )
        self.assertEqual(0, result.returncode, result.stdout)
        self.assertIn("source build/envsetup.sh", result.stdout)
        self.assertIn("breakfast fleur", result.stdout)
        self.assertIn("m target-files-package otatools -j8", result.stdout)
        self.assertIn("build_provenance.py pre-build", result.stdout)
        self.assertIn("build_provenance.py finalize", result.stdout)
        existence = run_bash("-c", f"test ! -e '{workspace}'")
        self.assertEqual(0, existence.returncode, existence.stdout)

    def test_target_files_runner_never_cleans_and_requires_fresh_output(self):
        runner = (ROOT / "scripts/ubuntu/build_target_files.sh").read_text(
            encoding="utf-8"
        )
        for forbidden in ("m clean", "installclean", "rm -rf out", "ccache -C"):
            self.assertNotIn(forbidden, runner)
        self.assertIn("pre-build provenance output already exists", runner)
        self.assertIn("final build provenance output already exists", runner)
        self.assertIn("target-files output predates this build", runner)
        self.assertIn("target-files packaging proof is missing", runner)
        self.assertIn("--kernel-root", runner)
        self.assertIn("--kernel-policy", runner)
        self.assertIn("--application-script", runner)
        self.assertIn("repo manifest -r", runner)
        self.assertNotIn("repo -C", runner)
        self.assertIn('"metadata": str(path)', runner)

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
