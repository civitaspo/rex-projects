# Knowledge publication and profile learning

## Knowledge format

Postmortems are published as immutable Markdown concepts that conform to Open
Knowledge Format (OKF) v0.2. The upstream normative specification is pinned to
[`SPEC.md` at commit `ad30107c31c06aec8a7d5636e0d1058118604e6f`](https://github.com/GoogleCloudPlatform/open-knowledge-format/blob/ad30107c31c06aec8a7d5636e0d1058118604e6f/SPEC.md).
This pin is intentional: the v0.2 specification may receive clarifications
without changing its version label. The article uses required `type` metadata,
source provenance, `generated` metadata, and `status: draft`; no `verified`
claim is emitted without a human confirmation.

Each TicketRun produces one Markdown concept below
`<knowledge-root>/projects/<project-id>/postmortems/`. The opaque TicketRun ID
is SHA-256 mapped into the filename. A manifest records project, TicketRun,
operation, format, output path, source digests, content digest, and byte count;
the machine controller persists this manifest with its durable publication
receipt. Publishing uses a fully synced sibling temporary file and an atomic
hard-link create-if-absent, followed by syncing the containing directory. This
avoids `rename` replacing an empty destination directory. A retry verifies the
existing bytes and returns the same receipt; conflicting content is an error.

Only curated source excerpts are accepted, with a configured aggregate byte
limit. Sources carry their digest, resource, and trust label. Untrusted source
material is explicitly marked as data rather than instructions. Callers must
exclude environment dumps, credentials, and other secret-bearing material
before constructing an input; the format layer does not claim general-purpose
secret detection.

## Candidate learning

Learning is a bounded snapshot model for the machine controller's SQLite store,
not a second persistence system. At most five active candidates per project and
twenty retained revisions per project are kept. Candidates expire by a
canonical UTC timestamp and can be superseded. Trial revisions allow at most
ten paired runs and require at least five distinct input digests for an
`improved` classification. Timeouts and failed runs count against the run cap
and leave evidence `inconclusive`; any measured regression prevents promotion.
These limits are operational bounds and do not establish statistical efficacy.

An inconclusive candidate can be promoted only with explicit human approval
bound to the exact candidate digest, full file-manifest digest, project, role,
profile slot, and configuration revision. The approval records a rationale and
timestamp while preserving the `inconclusive` evidence label. Promotion takes
an exclusive lock over the declarative config root, rechecks its source and
profile-tree revision before publishing, validates every relative file path,
stages the complete package outside `profiles/`, and atomically publishes the
new immutable directory. Existing managed profiles are never overwritten;
stale approvals produce no package files. Automatic Git commits or pushes are
outside this module.
