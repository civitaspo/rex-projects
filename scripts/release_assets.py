#!/usr/bin/env python3
"""Validate release build outputs and render the reviewed Lua runtime pin."""

from __future__ import annotations

import argparse
import difflib
import hashlib
import json
import os
import platform
import re
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


TARGETS = {
    "macos-aarch64": "aarch64-apple-darwin",
    "macos-x86_64": "x86_64-apple-darwin",
    "linux-aarch64": "aarch64-unknown-linux-gnu",
    "linux-x86_64": "x86_64-unknown-linux-gnu",
}
VERSION_RE = re.compile(r"^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$")
REVISION_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class ReleaseAssetError(Exception):
    """Invalid or incomplete release input."""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def inspect_runtime_minimum(binary: Path, target: str) -> dict[str, str]:
    host_os = platform.system()
    machine = platform.machine().lower()
    target_arch = "aarch64" if target.endswith("aarch64") else "x86_64"
    machine_aliases = {"aarch64": {"aarch64", "arm64"}, "x86_64": {"x86_64", "amd64"}}
    expected_os = "Darwin" if target.startswith("macos-") else "Linux"
    if host_os != expected_os or machine not in machine_aliases[target_arch]:
        raise ReleaseAssetError(f"release asset must be built and inspected on native {target} runner; current host is {host_os}/{machine}")

    if target.startswith("macos-"):
        try:
            output = subprocess.run(["otool", "-l", str(binary)], check=True, capture_output=True, text=True, timeout=10).stdout
        except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
            raise ReleaseAssetError(f"cannot inspect the macOS deployment target with otool: {error}") from error
        commands = output.split("Load command ")
        minimums: set[str] = set()
        for command in commands:
            if "cmd LC_BUILD_VERSION" in command:
                match = re.search(r"^\s*minos\s+(\d+(?:\.\d+){1,2})\s*$", command, re.MULTILINE)
                if match:
                    minimums.add(match.group(1))
            elif "cmd LC_VERSION_MIN_MACOSX" in command:
                match = re.search(r"^\s*version\s+(\d+(?:\.\d+){1,2})\s*$", command, re.MULTILINE)
                if match:
                    minimums.add(match.group(1))
        if len(minimums) != 1:
            raise ReleaseAssetError("otool did not report one unambiguous macOS minimum deployment version")
        return {"minimum_os": f"macOS {minimums.pop()}"}

    try:
        output = subprocess.run(["getconf", "GNU_LIBC_VERSION"], check=True, capture_output=True, text=True, timeout=10).stdout.strip()
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
        raise ReleaseAssetError(f"cannot inspect the Linux GNU libc baseline: {error}") from error
    match = re.fullmatch(r"glibc\s+(\d+)\.(\d+)", output)
    if not match:
        raise ReleaseAssetError("getconf did not identify the GNU libc version")
    major, minor = int(match.group(1)), int(match.group(2))
    if (major, minor) < (2, 39):
        raise ReleaseAssetError(f"Linux GNU release assets require a glibc 2.39-or-newer build host; found {output}")
    return {"minimum_libc": f"glibc >= {major}.{minor}"}


def package_metadata(repository_root: Path) -> tuple[str, str]:
    try:
        output = subprocess.run(
            ["cargo", "metadata", "--no-deps", "--format-version", "1"],
            cwd=repository_root,
            check=True,
            capture_output=True,
            text=True,
        )
        metadata = json.loads(output.stdout)
    except (OSError, subprocess.CalledProcessError, json.JSONDecodeError) as error:
        raise ReleaseAssetError(f"cannot read Cargo package metadata: {error}") from error

    packages = [package for package in metadata.get("packages", []) if package.get("name") == "rex-projects"]
    if len(packages) != 1:
        raise ReleaseAssetError("Cargo metadata must contain exactly one rex-projects package")
    package = packages[0]
    version = package.get("version")
    repository = package.get("repository")
    if not isinstance(version, str) or not VERSION_RE.fullmatch(version):
        raise ReleaseAssetError("Cargo package version is not a supported SemVer version")
    if not isinstance(repository, str):
        raise ReleaseAssetError("Cargo package must declare its HTTPS release repository")
    parsed = urlparse(repository)
    if parsed.scheme != "https" or parsed.netloc != "github.com" or not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", parsed.path.lstrip("/")):
        raise ReleaseAssetError("Cargo repository must be an HTTPS GitHub owner/repository URL")
    return version, repository.rstrip("/")


def validate_version_info(info: Any, version: str, rust_target: str) -> dict[str, Any]:
    if not isinstance(info, dict):
        raise ReleaseAssetError("version --json must return a JSON object")
    required = {"name", "version", "target", "cli_protocol", "database_schema", "source_revision", "dirty"}
    if set(info) != required:
        raise ReleaseAssetError(f"version --json fields differ from the CLI protocol: {sorted(info)}")
    if info["name"] != "rex-projects" or info["version"] != version or info["target"] != rust_target:
        raise ReleaseAssetError("version --json identity does not match the package and target")
    for field in ("cli_protocol", "database_schema"):
        if type(info[field]) is not int or info[field] < 1:
            raise ReleaseAssetError(f"version --json {field} must be a positive integer")
    if not isinstance(info["source_revision"], str) or not REVISION_RE.fullmatch(info["source_revision"]):
        raise ReleaseAssetError("version --json source_revision must be a full lowercase Git SHA")
    if info["dirty"] is not False:
        raise ReleaseAssetError("release build must report dirty=false")
    return info


def validate_runtime_minimum(target: str, runtime_key: str, value: Any) -> str:
    if not isinstance(value, str):
        raise ReleaseAssetError(f"{target} runtime minimum must be a string")
    if runtime_key == "minimum_os":
        if not re.fullmatch(r"macOS \d+\.\d+(?:\.\d+)?", value):
            raise ReleaseAssetError(f"{target} minimum_os must be measured from the executable load commands")
        return value
    match = re.fullmatch(r"glibc >= (\d+)\.(\d+)", value)
    if not match or (int(match.group(1)), int(match.group(2))) < (2, 39):
        raise ReleaseAssetError(f"{target} minimum_libc must be glibc 2.39 or newer")
    return value


def validate_release_binary(binary: Path) -> None:
    try:
        file_stat = binary.lstat()
    except OSError as error:
        raise ReleaseAssetError(f"cannot inspect release executable: {error}") from error
    if not stat.S_ISREG(file_stat.st_mode) or not file_stat.st_mode & 0o111:
        raise ReleaseAssetError("release executable must be a regular executable file, not a symlink")
    if file_stat.st_size == 0:
        raise ReleaseAssetError("release executable is empty")


def make_artifact_manifest(
    binary: Path,
    version_info: Any,
    version: str,
    target: str,
    runtime_minimum: dict[str, str],
) -> dict[str, Any]:
    rust_target = TARGETS.get(target)
    if rust_target is None:
        raise ReleaseAssetError(f"unsupported target: {target}")
    validate_release_binary(binary)
    info = validate_version_info(version_info, version, rust_target)
    expected_runtime_key = "minimum_os" if target.startswith("macos-") else "minimum_libc"
    if set(runtime_minimum) != {expected_runtime_key}:
        raise ReleaseAssetError(f"{target} requires measured {expected_runtime_key} evidence")
    validate_runtime_minimum(target, expected_runtime_key, runtime_minimum[expected_runtime_key])
    return {
        "version": version,
        "target": target,
        "rust_target": rust_target,
        **runtime_minimum,
        "source_revision": info["source_revision"],
        "dirty": info["dirty"],
        "version_json": info,
        "sha256": sha256_file(binary),
    }


def write_artifact_manifest(args: argparse.Namespace) -> None:
    version = args.version
    validate_release_binary(args.binary)
    binary = args.binary.absolute()
    digest_before_probe = sha256_file(binary)
    try:
        probe = subprocess.run(
            [str(binary), "version", "--json"],
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
        )
        version_info = json.loads(probe.stdout)
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired, json.JSONDecodeError) as error:
        raise ReleaseAssetError(f"release executable version probe failed: {error}") from error
    manifest = make_artifact_manifest(
        binary,
        version_info,
        version,
        args.target,
        inspect_runtime_minimum(binary, args.target),
    )
    if manifest["sha256"] != digest_before_probe:
        raise ReleaseAssetError("release executable changed while its build metadata was probed")
    args.output.write_text(json.dumps(manifest, indent=2) + "\n")


def read_artifacts(artifact_directory: Path, version: str, protocol: int) -> list[dict[str, str]]:
    entries = list(artifact_directory.iterdir())
    expected_targets = set(TARGETS)
    if {path.name for path in entries} == expected_targets:
        records = {
            target: (artifact_directory / target / "rex-projects", artifact_directory / target / "artifact.json")
            for target in TARGETS
        }
        for target in TARGETS:
            target_directory = artifact_directory / target
            if target_directory.is_symlink() or not target_directory.is_dir():
                raise ReleaseAssetError(f"{target} target directory must be a regular directory")
            target_files = {path.name for path in target_directory.iterdir()}
            if target_files != {"rex-projects", "artifact.json"}:
                raise ReleaseAssetError(f"{target} target directory must contain only rex-projects and artifact.json")
    else:
        expected_asset_names = {"SHA256SUMS"}
        records = {}
        for target, rust_target in TARGETS.items():
            binary_name = f"rex-projects-{rust_target}"
            manifest_name = f"{binary_name}.artifact.json"
            records[target] = (artifact_directory / binary_name, artifact_directory / manifest_name)
            expected_asset_names.update({binary_name, manifest_name, f"{binary_name}.sha256"})
        found_names = {path.name for path in entries}
        if found_names != expected_asset_names:
            missing = sorted(expected_asset_names - found_names)
            unexpected = sorted(found_names - expected_asset_names)
            raise ReleaseAssetError(f"flat release asset set is incomplete (missing={missing}, unexpected={unexpected})")
        flat_files = {path.name: path for path in entries}
        for name, path in flat_files.items():
            if path.is_symlink() or not path.is_file():
                raise ReleaseAssetError(f"release asset {name} must be a regular file")
        listed_assets = expected_asset_names - {"SHA256SUMS"}
        try:
            sums_text = flat_files["SHA256SUMS"].read_text()
        except (OSError, UnicodeDecodeError) as error:
            raise ReleaseAssetError(f"cannot read release SHA256SUMS: {error}") from error
        listed_sums: dict[str, str] = {}
        for line in sums_text.splitlines():
            match = re.fullmatch(r"([0-9a-f]{64})  ([A-Za-z0-9][A-Za-z0-9._+-]{0,254})", line)
            if not match or match.group(2) in listed_sums:
                raise ReleaseAssetError("release SHA256SUMS contains a malformed or duplicate entry")
            listed_sums[match.group(2)] = match.group(1)
        expected_sums = {name: sha256_file(flat_files[name]) for name in listed_assets}
        if listed_sums != expected_sums:
            raise ReleaseAssetError("release SHA256SUMS does not match the downloaded asset set")
        for target, rust_target in TARGETS.items():
            binary_name = f"rex-projects-{rust_target}"
            expected_sidecar = f"{sha256_file(flat_files[binary_name])}  {binary_name}\n"
            try:
                sidecar = flat_files[f"{binary_name}.sha256"].read_text()
            except (OSError, UnicodeDecodeError) as error:
                raise ReleaseAssetError(f"{target} binary checksum sidecar cannot be read: {error}") from error
            if sidecar != expected_sidecar:
                raise ReleaseAssetError(f"{target} binary checksum sidecar does not match its bytes")

    results: list[dict[str, str]] = []
    revisions: set[str] = set()
    schemas: set[int] = set()
    for target, rust_target in TARGETS.items():
        binary, manifest_path = records[target]
        if binary.is_symlink() or manifest_path.is_symlink() or not binary.is_file() or not manifest_path.is_file():
            raise ReleaseAssetError(f"{target} must contain regular binary and artifact metadata files")
        try:
            manifest = json.loads(manifest_path.read_text())
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ReleaseAssetError(f"cannot parse {manifest_path}: {error}") from error
        runtime_key = "minimum_os" if target.startswith("macos-") else "minimum_libc"
        required = {"version", "target", "rust_target", runtime_key, "source_revision", "dirty", "version_json", "sha256"}
        if not isinstance(manifest, dict) or set(manifest) != required:
            raise ReleaseAssetError(f"{target} artifact.json fields are invalid")
        if manifest["version"] != version or manifest["target"] != target or manifest["rust_target"] != rust_target:
            raise ReleaseAssetError(f"{target} artifact identity does not match Cargo metadata")
        validate_runtime_minimum(target, runtime_key, manifest[runtime_key])
        if manifest["dirty"] is not False or not isinstance(manifest["source_revision"], str) or not REVISION_RE.fullmatch(manifest["source_revision"]):
            raise ReleaseAssetError(f"{target} build metadata is not a clean, revisioned release build")
        version_json = validate_version_info(manifest["version_json"], version, rust_target)
        if version_json["cli_protocol"] != protocol:
            raise ReleaseAssetError(f"{target} CLI protocol does not match the requested pin protocol")
        if manifest["source_revision"] != version_json["source_revision"] or manifest["dirty"] != version_json["dirty"]:
            raise ReleaseAssetError(f"{target} artifact metadata disagrees with version_json build identity")
        if not isinstance(manifest["sha256"], str) or not SHA256_RE.fullmatch(manifest["sha256"]):
            raise ReleaseAssetError(f"{target} artifact SHA-256 is malformed")
        if not binary.stat().st_mode & 0o111:
            raise ReleaseAssetError(f"{target} release executable is not executable")
        if binary.stat().st_size == 0:
            raise ReleaseAssetError(f"{target} release executable is empty")
        digest = sha256_file(binary)
        if digest != manifest["sha256"]:
            raise ReleaseAssetError(f"{target} executable SHA-256 does not match artifact metadata")
        revisions.add(manifest["source_revision"])
        schemas.add(version_json["database_schema"])
        results.append({
            "target": target,
            "rust_target": rust_target,
            "runtime_key": runtime_key,
            "runtime_minimum": manifest[runtime_key],
            "sha256": digest,
        })

    if len(revisions) != 1:
        raise ReleaseAssetError("release assets were not built from the same source revision")
    if len(schemas) != 1:
        raise ReleaseAssetError("release assets report different database schema versions")
    return results


def lua_pin(version: str, protocol: int, repository: str, assets: list[dict[str, str]]) -> str:
    lines = [
        "return {",
        '  status = "released",',
        f'  version = "{version}",',
        f"  protocol = {protocol},",
        "  targets = {",
    ]
    release_base = f"{repository}/releases/download/v{version}"
    for asset in assets:
        url = f"{release_base}/rex-projects-{asset['rust_target']}"
        lines.extend(
            [
                f'    ["{asset["target"]}"] = {{',
                f'      rust_target = "{asset["rust_target"]}",',
                f'      url = "{url}",',
                f'      sha256 = "{asset["sha256"]}",',
                f'      {asset["runtime_key"]} = "{asset["runtime_minimum"]}",',
                "    },",
            ]
        )
    lines.extend(["  },", "}", ""])
    return "\n".join(lines)


def update_pin(args: argparse.Namespace) -> None:
    repository_root = args.repository_root.resolve()
    version, repository = package_metadata(repository_root)
    artifact_root = args.artifact_root.resolve()
    version_directory = artifact_root / version
    artifact_directory = version_directory if version_directory.is_dir() else artifact_root
    if not artifact_directory.is_dir():
        raise ReleaseAssetError(f"artifact directory does not exist: {artifact_directory}")
    assets = read_artifacts(artifact_directory, version, args.protocol)
    generated = lua_pin(version, args.protocol, repository, assets)
    pin_path = args.pin_path.resolve()
    if args.write:
        if not pin_path.parent.is_dir():
            raise ReleaseAssetError(f"Lua pin directory does not exist: {pin_path.parent}")
        temporary_path: Path | None = None
        try:
            with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=pin_path.parent, delete=False) as output:
                temporary_path = Path(output.name)
                output.write(generated)
                output.flush()
                os.fsync(output.fileno())
            os.chmod(temporary_path, 0o644)
            os.replace(temporary_path, pin_path)
        finally:
            if temporary_path and temporary_path.exists():
                temporary_path.unlink()
        print(f"wrote verified Lua runtime pin {pin_path}")
        return

    try:
        current = pin_path.read_text()
    except OSError as error:
        raise ReleaseAssetError(f"cannot read Lua runtime pin {pin_path}: {error}") from error
    if current == generated:
        print("Lua runtime pin matches all four verified artifact manifests")
        return
    sys.stdout.writelines(
        difflib.unified_diff(
            current.splitlines(keepends=True),
            generated.splitlines(keepends=True),
            fromfile=str(pin_path),
            tofile="generated runtime_version.lua",
        )
    )
    raise ReleaseAssetError("Lua runtime pin differs; review the diff and rerun with --write")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    manifest_parser = subparsers.add_parser("artifact-manifest", help="probe a native build and write artifact.json")
    manifest_parser.add_argument("--binary", type=Path, required=True)
    manifest_parser.add_argument("--version", required=True)
    manifest_parser.add_argument("--target", choices=TARGETS, required=True)
    manifest_parser.add_argument("--output", type=Path, required=True)
    manifest_parser.set_defaults(handler=write_artifact_manifest)

    pin_parser = subparsers.add_parser("pin", help="verify all target artifacts and check or write the Lua pin")
    pin_parser.add_argument("--repository-root", type=Path, default=Path(__file__).resolve().parents[1])
    pin_parser.add_argument("--artifact-root", type=Path, required=True, help="root containing <Cargo-version>/<target>/ artifacts")
    pin_parser.add_argument("--pin-path", type=Path, default=Path(__file__).resolve().parents[1] / "lua/rex_projects/runtime_version.lua")
    pin_parser.add_argument("--protocol", type=int, required=True, help="expected CLI protocol from the reviewed source")
    mode = pin_parser.add_mutually_exclusive_group()
    mode.add_argument("--check", action="store_true", help="compare generated output with the existing Lua pin (default)")
    mode.add_argument("--write", action="store_true", help="atomically replace the existing Lua pin after validation")
    pin_parser.set_defaults(handler=update_pin)

    args = parser.parse_args()
    try:
        args.handler(args)
    except (ReleaseAssetError, json.JSONDecodeError) as error:
        print(f"release assets: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
