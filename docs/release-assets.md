# Release assets

Build one versioned executable and digest manifest with:

```sh
scripts/build-release-asset.sh macos-aarch64 /tmp/rex-projects-assets
```

The target argument must be one of `macos-aarch64`, `macos-x86_64`, `linux-aarch64`, or
`linux-x86_64`. The matching Rust target must be installed and the host must have a compatible
linker. The script reads the package version from Cargo metadata, builds the locked release
profile, verifies the executable's `--version` output, and writes the executable with an
`artifact.json` SHA-256 manifest beneath `<output-root>/<version>/<target>/`.

The release workflow should run each target on a native compatible runner, retain the complete
target triple and runner/toolchain evidence, then publish these files as raw versioned assets. The
Lua release pin is a later reviewed change and embeds each artifact's independently reviewed
digest. Do not publish a release until every target selected by the Lua pin has an artifact.

Minimum operating-system and libc versions remain release evidence: record them from the native
runner and executable inspection before publishing. A target label alone does not establish
runtime compatibility.
