#!/usr/bin/env bash
set -euo pipefail

normalized_target="${1:-}"
output_root="${2:-}"
if [[ -z "$normalized_target" || -z "$output_root" ]]; then
	printf 'usage: %s <normalized-target> <output-root>\n' "$0" >&2
	exit 2
fi

case "$normalized_target" in
	macos-aarch64) rust_target="aarch64-apple-darwin" ;;
	macos-x86_64) rust_target="x86_64-apple-darwin" ;;
	linux-aarch64) rust_target="aarch64-unknown-linux-gnu" ;;
	linux-x86_64) rust_target="x86_64-unknown-linux-gnu" ;;
	*)
		printf 'unsupported release target: %s\n' "$normalized_target" >&2
		exit 2
		;;
esac

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repository_root"

version="$(cargo metadata --no-deps --format-version 1 | python3 -c '
import json
import sys

metadata = json.load(sys.stdin)
package = next(package for package in metadata["packages"] if package["name"] == "rex-projects")
print(package["version"])
')"
export RUSTFLAGS="${RUSTFLAGS:-} --remap-path-prefix=$repository_root=/rex-projects"
cargo build --locked --release --target "$rust_target"

artifact_directory="$output_root/$version/$normalized_target"
mkdir -p "$artifact_directory"
cp "target/$rust_target/release/rex-projects" "$artifact_directory/rex-projects"
chmod 755 "$artifact_directory/rex-projects"

reported_version="$("$artifact_directory/rex-projects" --version)"
expected_version="rex-projects $version"
if [[ "$reported_version" != "$expected_version" ]]; then
	printf 'binary version mismatch: expected "%s", got "%s"\n' "$expected_version" "$reported_version" >&2
	exit 1
fi
python3 "$repository_root/scripts/release_assets.py" artifact-manifest \
	--binary "$artifact_directory/rex-projects" \
	--version "$version" \
	--target "$normalized_target" \
	--output "$artifact_directory/artifact.json"
printf '%s\n' "$artifact_directory/rex-projects" "$artifact_directory/artifact.json"
