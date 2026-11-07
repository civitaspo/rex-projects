# Release assets

Build one versioned executable and digest manifest with:

```sh
scripts/build-release-asset.sh macos-aarch64 /tmp/rex-projects-assets
```

The target argument must be one of `macos-aarch64`, `macos-x86_64`, `linux-aarch64`, or
`linux-x86_64`. The matching Rust target must be installed and the host must have a compatible
linker. Run each target on a native compatible runner. The script reads the package version from
Cargo metadata, builds the locked release profile, verifies `--version` and `version --json`, then
writes the executable and its `artifact.json` beneath `<output-root>/<version>/<target>/`. The
manifest includes the normalized and Rust targets, the measured runtime floor, source revision,
clean build flag, parsed `version --json` response, and SHA-256 computed from the executable bytes.
The CLI protocol and database schema stay inside `version_json` so release metadata remains generic.

After a release has published every required target asset, download that exact version and
validate/render the Lua pin:

```sh
gh release download v0.1.0 --dir /tmp/rex-projects-assets
python3 scripts/release_assets.py pin \
  --artifact-root /tmp/rex-projects-assets \
  --protocol 1 \
  --check
```

The command reads the version from `Cargo.toml` through `cargo metadata`. It requires exactly the
four target directories for that version, validates each manifest against the expected target,
version, protocol, source revision, and database schema, and recomputes every binary digest. All
four builds must have the same source revision, CLI protocol, and database schema. The command
does not execute cross-target binaries; native build jobs run each binary's JSON version probe
before producing its manifest. It accepts the local per-target build layout or csm-ci's flat
release-download layout. For flat downloads it validates the complete closed asset set, every
binary `.sha256` sidecar, and the aggregate `SHA256SUMS`. A manifest is build evidence, not a
substitute for verifying the release builder and its attestation against the expected repository,
tag, and merge revision.

Each `artifact.json` also carries exactly one measured runtime floor: `minimum_os` for macOS,
read from the executable's `otool -l` deployment load command, or `minimum_libc` for Linux GNU,
read from the native build runner's `getconf GNU_LIBC_VERSION`. The pin generator copies this
evidence into the corresponding target entry together with its Rust target triple. Linux GNU
assets are supported only on glibc 2.39 or newer; the current target profile does not claim
compatibility with older Linux distributions. The value describes the conservative build-runner
floor and must be checked against the release builder evidence.

The default `--check` mode prints a diff and fails when `lua/rex_projects/runtime_version.lua` is
not the exact output. Once the versioned raw assets have been published and their URLs verified,
use `--write` to atomically update that file, review the resulting source diff, and submit it as a
separate change. The generated URLs use the Cargo repository's GitHub release URL and the raw
asset names `rex-projects-<Rust-target-triple>`. The generated pin embeds the exact version,
protocol, URL, and recomputed SHA-256; it never uses a latest-version lookup or a downloaded
checksum sidecar as its trust root. Do not run `--write` from a PR or release job before real
versioned assets exist.

The csm-ci `cargo-raw` extension for this project must support the four exact targets in
`scripts/release_assets.py`. Linux GNU builds must run on the supported Ubuntu 24.04 baseline,
validate executable format and GLIBC symbol requirements through 2.39, and retain the runner's
glibc 2.39 floor as evidence. Keep the four-target matrix; do not substitute a different Linux
ABI or pin a target that has not been built. The csm-ci-generated release callers stay managed by
csm-ci and must not be edited in this repository. The release builder must provide the trusted
merge revision to Cargo builds from source archives so `version --json` reports a full source
revision; the release job should validate `name`, `version`, `target`, `cli_protocol`, positive
`database_schema`, `source_revision`, and `dirty=false` for every native artifact.

`build.rs` accepts `CSM_CI_SOURCE_REVISION` and `CSM_CI_SOURCE_CLEAN` only as a pair. The revision
must be a lowercase 40-character Git SHA. The clean marker must be exactly `true` or `false`; a
false marker produces `dirty=true`, which the release asset builder rejects. A partial, malformed,
or non-UTF-8 pair fails the build instead of silently omitting source identity. When neither
variable is set, local builds continue to read revision and cleanliness from Git metadata.

For the pin handoff, make each per-target build manifest a versioned release asset named
`rex-projects-<Rust-target-triple>.artifact.json`. It contains the generic fields `version`,
normalized `target`, `rust_target`, exactly one of `minimum_os` or `minimum_libc`,
`source_revision`, `dirty`, `version_json`, and `sha256`. `version_json` is the parsed
`version --json` response for that target binary and contains the product-specific CLI protocol and
database schema. The pin tool validates those product fields, recomputes `sha256` from the exact
binary bytes, and rejects incomplete or inconsistent target sets. The publisher's attestation
remains the source-provenance proof; a JSON manifest alone cannot establish which commit built a
binary.

The csm-ci release process publishes one immutable asset set, including its generated checksum
and provenance attestations. The Lua pin is a later reviewed source change after those assets
exist. Do not publish a release until every target selected by the Lua pin has an artifact.

Minimum operating-system and libc versions remain release evidence: record them from the native
runner and executable inspection before publishing. A target label alone does not establish
runtime compatibility.
