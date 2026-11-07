import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPOSITORY_ROOT / "scripts"))
import release_assets


VERSION = "0.1.0"
REVISION = "a" * 40
PROTOCOL = 1
SCHEMA = 4
HOST_ARCH = "aarch64" if platform.machine().lower() in {"aarch64", "arm64"} else "x86_64"
HOST_TARGET = ("macos-" if platform.system() == "Darwin" else "linux-") + HOST_ARCH
HOST_TRIPLE = release_assets.TARGETS[HOST_TARGET]


def version_info(target):
    return {
        "name": "rex-projects",
        "version": VERSION,
        "target": target,
        "cli_protocol": PROTOCOL,
        "database_schema": SCHEMA,
        "source_revision": REVISION,
        "dirty": False,
    }


class ReleaseAssetsTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)

    def tearDown(self):
        self.temporary.cleanup()

    def make_bundle(self):
        version_root = self.root / VERSION
        for target, rust_target in release_assets.TARGETS.items():
            target_root = version_root / target
            target_root.mkdir(parents=True)
            binary = target_root / "rex-projects"
            binary.write_bytes(f"fixture-{target}".encode())
            binary.chmod(0o755)
            runtime_minimum = {"minimum_os": "macOS 11.0"} if target.startswith("macos-") else {"minimum_libc": "glibc >= 2.39"}
            manifest = release_assets.make_artifact_manifest(binary, version_info(rust_target), VERSION, target, runtime_minimum)
            (target_root / "artifact.json").write_text(json.dumps(manifest, indent=2) + "\n")
        return version_root

    def test_artifact_manifest_probes_fake_native_executable(self):
        binary = self.root / "rex-projects"
        info = json.dumps(version_info(HOST_TRIPLE))
        binary.write_text(
            "#!/bin/sh\n"
            'if [ "$1" = version ] && [ "$2" = --json ]; then\n'
            f"  printf '%s\\n' '{info}'\n"
            "else\n  exit 9\nfi\n"
        )
        binary.chmod(0o755)
        fake_bin = self.root / "bin"
        fake_bin.mkdir()
        command_name = "otool" if HOST_TARGET.startswith("macos-") else "getconf"
        command_output = "Load command 0\n      cmd LC_BUILD_VERSION\n    minos 11.0\n" if HOST_TARGET.startswith("macos-") else "glibc 2.39\n"
        fake_command = fake_bin / command_name
        fake_command.write_text(f"#!/bin/sh\nprintf '%s' '{command_output}'\n")
        fake_command.chmod(0o755)
        env = dict(os.environ)
        env["PATH"] = f"{fake_bin}:{env.get('PATH', '')}"
        output = self.root / "artifact.json"
        subprocess.run(
            [
                sys.executable,
                str(REPOSITORY_ROOT / "scripts/release_assets.py"),
                "artifact-manifest",
                "--binary",
                str(binary),
                "--version",
                VERSION,
                "--target",
                HOST_TARGET,
                "--output",
                str(output),
            ],
            cwd=REPOSITORY_ROOT,
            env=env,
            check=True,
            capture_output=True,
            text=True,
        )
        manifest = json.loads(output.read_text())
        self.assertEqual(manifest["sha256"], hashlib.sha256(binary.read_bytes()).hexdigest())
        self.assertEqual(manifest["source_revision"], REVISION)
        self.assertEqual(manifest["version_json"]["cli_protocol"], PROTOCOL)
        self.assertIn("minimum_os" if HOST_TARGET.startswith("macos-") else "minimum_libc", manifest)

    def test_complete_bundle_yields_all_four_exact_urls_and_digests(self):
        self.make_bundle()
        assets = release_assets.read_artifacts(self.root / VERSION, VERSION, PROTOCOL)
        pin = release_assets.lua_pin(VERSION, PROTOCOL, "https://github.com/civitaspo/rex-projects", assets)
        self.assertIn('version = "0.1.0"', pin)
        self.assertIn('protocol = 1', pin)
        for target, rust_target in release_assets.TARGETS.items():
            digest = hashlib.sha256(f"fixture-{target}".encode()).hexdigest()
            self.assertIn(f'https://github.com/civitaspo/rex-projects/releases/download/v0.1.0/rex-projects-{rust_target}', pin)
            self.assertIn(f'sha256 = "{digest}"', pin)
        self.assertEqual(pin, release_assets.lua_pin(VERSION, PROTOCOL, "https://github.com/civitaspo/rex-projects", assets))

    def test_flat_csm_release_download_bundle_is_verified(self):
        version_root = self.make_bundle()
        flat_root = self.root / "downloaded-release"
        flat_root.mkdir()
        for target, rust_target in release_assets.TARGETS.items():
            source = version_root / target
            binary_name = f"rex-projects-{rust_target}"
            binary = flat_root / binary_name
            shutil.copyfile(source / "rex-projects", binary)
            binary.chmod(0o755)
            shutil.copyfile(source / "artifact.json", flat_root / f"{binary_name}.artifact.json")
            (flat_root / f"{binary_name}.sha256").write_text(f"{hashlib.sha256(binary.read_bytes()).hexdigest()}  {binary_name}\n")
        asset_names = sorted(path.name for path in flat_root.iterdir())
        (flat_root / "SHA256SUMS").write_text(
            "".join(f"{hashlib.sha256((flat_root / name).read_bytes()).hexdigest()}  {name}\n" for name in asset_names)
        )
        assets = release_assets.read_artifacts(flat_root, VERSION, PROTOCOL)
        self.assertEqual(len(assets), 4)
        self.assertEqual(assets[0]["runtime_minimum"], "macOS 11.0")

    def test_missing_target_is_refused(self):
        version_root = self.make_bundle()
        (version_root / "linux-x86_64").rename(self.root / "omitted-target")
        with self.assertRaisesRegex(release_assets.ReleaseAssetError, "incomplete"):
            release_assets.read_artifacts(version_root, VERSION, PROTOCOL)

    def test_tampered_binary_is_refused(self):
        version_root = self.make_bundle()
        binary = version_root / "macos-aarch64/rex-projects"
        binary.write_bytes(binary.read_bytes() + b"tampered")
        with self.assertRaisesRegex(release_assets.ReleaseAssetError, "SHA-256"):
            release_assets.read_artifacts(version_root, VERSION, PROTOCOL)

    def test_empty_downloaded_binary_is_refused_even_with_matching_manifest(self):
        version_root = self.make_bundle()
        binary = version_root / "macos-aarch64/rex-projects"
        binary.write_bytes(b"")
        manifest_path = version_root / "macos-aarch64/artifact.json"
        manifest = json.loads(manifest_path.read_text())
        manifest["sha256"] = hashlib.sha256(b"").hexdigest()
        manifest_path.write_text(json.dumps(manifest))
        with self.assertRaisesRegex(release_assets.ReleaseAssetError, "executable is empty"):
            release_assets.read_artifacts(version_root, VERSION, PROTOCOL)

    def test_flat_release_download_rejects_tampered_aggregate_checksums(self):
        version_root = self.make_bundle()
        flat_root = self.root / "downloaded-release"
        flat_root.mkdir()
        for target, rust_target in release_assets.TARGETS.items():
            source = version_root / target
            binary_name = f"rex-projects-{rust_target}"
            binary = flat_root / binary_name
            shutil.copyfile(source / "rex-projects", binary)
            binary.chmod(0o755)
            shutil.copyfile(source / "artifact.json", flat_root / f"{binary_name}.artifact.json")
            (flat_root / f"{binary_name}.sha256").write_text(f"{'0' * 64}  {binary_name}\n")
        expected_names = sorted(path.name for path in flat_root.iterdir())
        (flat_root / "SHA256SUMS").write_text(
            "".join(f"{hashlib.sha256((flat_root / name).read_bytes()).hexdigest()}  {name}\n" for name in expected_names)
        )
        with self.assertRaisesRegex(release_assets.ReleaseAssetError, "checksum sidecar"):
            release_assets.read_artifacts(flat_root, VERSION, PROTOCOL)

    def test_protocol_or_source_revision_mismatch_is_refused(self):
        version_root = self.make_bundle()
        manifest_path = version_root / "linux-aarch64/artifact.json"
        manifest = json.loads(manifest_path.read_text())
        manifest["version_json"]["cli_protocol"] = 2
        manifest_path.write_text(json.dumps(manifest))
        with self.assertRaisesRegex(release_assets.ReleaseAssetError, "CLI protocol"):
            release_assets.read_artifacts(version_root, VERSION, PROTOCOL)

        manifest["version_json"]["cli_protocol"] = PROTOCOL
        manifest["source_revision"] = "b" * 40
        manifest["version_json"]["source_revision"] = "b" * 40
        manifest_path.write_text(json.dumps(manifest))
        with self.assertRaisesRegex(release_assets.ReleaseAssetError, "same source revision"):
            release_assets.read_artifacts(version_root, VERSION, PROTOCOL)

    def test_linux_libc_floor_below_supported_baseline_is_refused(self):
        version_root = self.make_bundle()
        manifest_path = version_root / "linux-aarch64/artifact.json"
        manifest = json.loads(manifest_path.read_text())
        manifest["minimum_libc"] = "glibc >= 2.38"
        manifest_path.write_text(json.dumps(manifest))
        with self.assertRaisesRegex(release_assets.ReleaseAssetError, "glibc 2.39"):
            release_assets.read_artifacts(version_root, VERSION, PROTOCOL)

    def test_artifact_probe_rejects_dirty_or_wrong_target_metadata(self):
        binary = self.root / "binary"
        binary.write_bytes(b"binary")
        binary.chmod(0o755)
        dirty = version_info("aarch64-apple-darwin")
        dirty["dirty"] = True
        with self.assertRaisesRegex(release_assets.ReleaseAssetError, "dirty=false"):
            release_assets.make_artifact_manifest(binary, dirty, VERSION, "macos-aarch64", {"minimum_os": "macOS 11.0"})

        wrong_target = version_info("x86_64-apple-darwin")
        with self.assertRaisesRegex(release_assets.ReleaseAssetError, "identity"):
            release_assets.make_artifact_manifest(binary, wrong_target, VERSION, "macos-aarch64", {"minimum_os": "macOS 11.0"})


if __name__ == "__main__":
    unittest.main()
