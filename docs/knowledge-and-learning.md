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
the article's `generated.by` identifies `rex-projects/<Cargo package version>`
as its producer. Source credibility is represented only by attributable facts
(resource, title, digest, and the caller's reviewed/untrusted provenance label),
not by a subjective confidence score. The machine controller persists this
manifest with its durable publication receipt. Publishing uses a fully synced sibling temporary file and an atomic
hard-link create-if-absent, followed by syncing the containing directory. This
avoids `rename` replacing an empty destination directory. A retry verifies the
existing bytes and returns the same receipt; conflicting content is an error.

Only curated source excerpts are accepted, with a configured aggregate byte
limit. Sources carry their digest, resource, and trust label. Untrusted source
material is explicitly marked as data rather than instructions. Callers must
exclude environment dumps, credentials, and other secret-bearing material
before constructing an input; the format layer does not claim general-purpose
secret detection. Titles, summaries, findings, and excerpts are bounded before
rendering; source excerpts are rendered as fenced quoted data with their
provenance so embedded Markdown cannot escape into article structure.

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
profile slot, and configuration revision. The approval object can only be
constructed inside the crate from a controller-validated durable human
response; caller-supplied approver text is not authority. Approval records a
rationale and timestamp while preserving the `inconclusive` evidence label.
Promotion takes an exclusive lock over the declarative config root, rechecks
its source and profile-tree revision before publishing, validates every
relative file path, stages the complete package outside `profiles/`, and
atomically publishes the new immutable directory with no-replace semantics.
The result is a publication receipt, not proof that the profile is active. The
controller must separately apply the exact role binding through its durable
configuration compare-and-swap path and verify the resulting snapshot before
marking a candidate promoted. Replaying an existing publication only confirms
that the immutable bytes exist; it cannot activate a profile or bypass a stale
configuration revision. Existing managed profiles are never overwritten.
Automatic Git commits or pushes are outside this module.
