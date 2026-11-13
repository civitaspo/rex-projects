# Supervisor learning context

The Supervisor receives an immutable learning batch containing published Findings and the latest published version of each Topic in the configured knowledge root. Topic creation and revision are accepted only when their source Findings belong to the same Project. A revision must name the exact Topic content digest included in that batch.

Published Topic files are immutable. The first version remains at `projects/<project>/topics/<key>.md`; each later version is written to a digest-suffixed sibling such as `projects/<project>/topics/<key>.r<content-digest>.md`. The SQLite publication ledger selects the latest successfully published version for future batches. Earlier batches and files remain unchanged, and conflicts or pending publications do not replace the last published version.

The ledger's current-version selection is scoped to the configured knowledge root. Changing that root does not relocate or migrate prior Topics; see the known limitation tracked by issue #137.
