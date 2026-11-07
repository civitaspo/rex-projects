# Release assets

The release build and upload are owned by csm-ci. This repository keeps only the
release-time pin verifier/updater in its development-only `xtask` package. Cargo's
root `Cargo.toml` remains the version authority.

To validate a locally collected four-target asset set and print the proposed Lua pin:

```sh
cargo xtask pin --artifact-root /tmp/rex-projects-assets --check
```

The artifact root may contain the flat csm release asset set, or a local fixture layout with
`<Cargo version>/<normalized target>/rex-projects` and `artifact.json`. The validator requires all
four targets and checks each executable against its metadata, target, Cargo version, CLI protocol,
source revision, runtime floor, and digest. It does not execute cross-target binaries.

After csm-ci has published a release, verify its exact Cargo-version tag, all asset attestations,
and checksums, then compare the proposed pin:

```sh
cargo xtask refresh-pin --check
# After reviewing the diff:
cargo xtask refresh-pin --write
```

`refresh` reads the package version and release repository from `Cargo.toml`, uses only the
matching stable `v<Cargo version>` release, obtains that tag's commit SHA from GitHub, and
downloads its assets. It verifies the csm-ci release attestation for every expected binary,
`.artifact.json`, `.sha256`, and `SHA256SUMS` asset. Verification pins the csm-ci signer workflow
and release predicate, rejects self-hosted runners, and checks the attested client repository,
merge SHA, and tag against this repository and the tag commit. GitHub CLI authentication and
`gh attestation verify` must be available; lookup or verification failures stop the update.

After attestation checks, `refresh` validates the closed four-target asset set, each parsed
`version --json` response, runtime evidence, sidecar checksums, aggregate `SHA256SUMS`, matching
source revisions, and the expected tag commit. It derives the accepted CLI protocol from the
current Lua runtime pin and writes the new pin only with `--write`. The local `pin` subcommand is
also available for fixture or downloaded assets; it defaults to the protocol in the current pin
and accepts `--expected-source-revision` when the caller has verified the release provenance.
Neither subcommand executes cross-target binaries. Native csm-ci build jobs run `version --json`
on each just-built binary and store its parsed output in the sidecar.

Each `artifact.json` also carries exactly one measured runtime floor: `minimum_os` for macOS is
the bare deployment target value from the executable's `otool -l` load command (for example,
`11.0`), and `minimum_libc` for Linux GNU is `glibc X.Y` from the native build runner's
`getconf GNU_LIBC_VERSION` (for example, `glibc 2.39`). The pin generator copies this evidence
into the corresponding target entry together with its Rust target triple. Linux GNU assets are
supported only on glibc 2.39 or newer; the current target profile does not claim compatibility
with older Linux distributions. The value describes the conservative build-runner floor and must
be checked against the release builder evidence.

The default mode prints a diff and fails when `lua/rex_projects/runtime_version.lua` is not the
exact output. `--write` atomically updates that file after the release tag, all asset
attestations, and all content digests pass. Review the source diff and submit it as a separate
signed change; the refresh command does not create or merge a PR. Generated URLs use the Cargo
repository's GitHub release URL and the raw asset names `rex-projects-<Rust-target-triple>`. The
generated pin embeds the exact version, protocol, URLs, and recomputed SHA-256. It never queries a
mutable latest version or treats a downloaded checksum sidecar as its trust root.

The csm-ci server-side release entry for this repository must use `build_type: cargo-raw`, binary
`rex-projects`, these four exact Rust targets,
`version_probe_args: [version, --json]`. This creates a target-specific metadata sidecar containing
the parsed CLI response. The csm-ci-generated release callers stay managed by csm-ci; do not edit
them in this repository. Linux GNU builds must run on the supported Ubuntu 24.04 baseline,
validate executable format and GLIBC symbol requirements through 2.39, and retain the runner's
glibc floor as evidence. Keep the four-target matrix and do not pin a target that has not been
built. The release builder provides the trusted merge revision to Cargo builds from source
archives; the sidecar consumer requires `name`, `version`, `target`, `cli_protocol`, positive
`database_schema`, `source_revision`, and `dirty=false` in `version_json`.

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
