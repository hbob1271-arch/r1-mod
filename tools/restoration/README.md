<!-- coderabbit-ai-generated:v1 -->

<!-- coderabbit-ai-generated-section:v1:5900c1ef69cde9073196bcd17dc296273956d9ec635891e945d9137a863ad1bc -->

<!-- coderabbit-ai-generated-section:v1:f0a2ad655ea42e6288391aa4554411dd93f2721dc7558cd66b4a7fac0f77ff23 -->

<!-- coderabbit-ai-generated-section:v1:431bcfe997afef137a44692b7339d56948209bf9a124867996ec58b21fdf4236 -->

<!-- coderabbit-ai-generated-section:v1:03380c9e2ccc429933e45fbec480eb64e64027d5c99ae044bf66972a8ebac8a7 -->

<!-- coderabbit-ai-generated-section:v1:d9e0c5d5a2e36d177f566203e54bd6718f3677041931d6fd464177a48c7b0beb -->

# Restoration inventory reconciliation

`reconcile.py` checks an existing file/hash manifest against optional file trees using Python3.10+ and the standard library. It never extracts archives or modifies inspected files. Use stable, quiescent input trees; this is not a filesystem sandbox against an adversary concurrently replacing ancestor directories. Windows runtime validation is still required.

Input schema: `{"files":{"relative/path":{"size":3,"sha256":"<64 hexadecimal characters>"}}}`. Unknown metadata is ignored. Paths must be forward-slash relative names, unique even ignoring case, without traversal, Windows special names, stream syntax or conflicting file/directory entries. All entries are retained. Existing symlink components and nonregular files are rejected; permission/scan errors are reported.

```sh
python tools/restoration/reconcile.py --manifest /data/inventory.json --original /data/original --archive-tree /data/archive-members --restoration /data/restoration --output /reports/reconciliation-001.json
python -m unittest discover -s tools/restoration/tests -v
```

Each tree is optional. Omitted trees produce `unavailable`, while absent files in supplied trees produce `missing`. `--archive-tree` means an already available lawful archive member tree; container extraction and archive hashes are outside this tool. Output must be a new file outside all inspected trees, and its parent directory must exist. Existing output reports are preserved. In case of a write failure, a partial new report can remain; retain it for diagnosis and use a new output name for a retry.

Exit0 means all expected files matched across all three supplied trees without scan errors; unlisted paths remain separately reported and require disposition. Exit1 means incomplete file verification, including omitted trees. Exit2 means invalid input or an operational failure. No exit status means the game is playable. Seven functional evidence fields remain unknown: parsed, identified, integrated, dependencies verified, game loaded, functionally tested and complete. Hash matching only establishes file integrity.

The task Outputs hold the provisional public2,445-entry baseline and current master tracker. Game-derived manifests, assets, profiles and private paths must not be committed. The baseline's authority must be reconciled with the owner's original installation before release acceptance.


## TSV ledger view

Add `--format tsv` to write one row for every baseline entry; JSON remains the default. Each row contains `manifest_sha256`, expected metadata, the three physical-tree checks, seven functional-stage statuses and explicit `game_completion`. Provenance column `generated_by` identifies generated TSV records. Use Python's `csv` module with delimiter `\t` and UTF-8 for readback. TSV exports no unlisted-path/error lists; the console prints their counts and the full JSON report preserves their details. A TSV integrity result cannot establish functional completion. Output still requires a fresh filename outside all input trees.


<!-- /coderabbit-ai-generated:v1 -->

## Declared v461 content coverage

Add `--content-inventory /reports/CODOL_V461_MAP_MODE_INVENTORY.json` with JSON output. This consumes the existing project export: exact targetVersion `3.19.26.22 / fastfile v461`, `maps` with unique `internalId` and nonempty `recordedPackages`, `specialModes` with `internalId` and `recordedAddons`, and `standardModes` slots. Package records use `relativePath`, `size`, `sha256`; addons also carry `mapId`. Optional extraction counts must agree with the records. Unsafe paths, duplicate keys/IDs/packages and invalid metadata are rejected. Output cannot overwrite this input.

`contentCoverage` joins declared package references to existing file checks without another filesystem read. Every reference is retained. Missing baseline references, conflicting size/hash metadata and unknown addon map IDs are explicit issues and prevent exit0. Absent trees stay unavailable; empty addon lists cannot pass recordedPackagesMatch. All declared package segments must match for per-tree package coverage. The inventory SHA256 binds the result to its exact source. JSON is required so TSV cannot silently discard coverage.

This verifies only recorded outer-package relationships. It does not extract archives, parse fastfiles or produce a decoded asset dependency graph, establish mode eligibility, identify official display names, or prove gameplay. Do not treat recordedPackagesMatch as map or mode completion. The public documentary baseline still requires owner validation. No original files are bundled in tests.


<!-- /coderabbit-ai-generated:v1 -->

The project map/mode inventory and the file ledger now share this reconciliation command.


<!-- /coderabbit-ai-generated:v1 -->

## Per-map and per-mode dependency validation

JSON with `--content-inventory` now adds `contentValidation.records`, sorted by kind/ID, for every map, special mode and standard-mode slot. Special-mode roots include each recorded addon's mapped base-package segments. This records container associations, not actual decoded asset dependency edges or mode eligibility. Standard-mode package mappings remain unavailable.

Optional per-package `dependencies` is an explicit list of baseline-relative paths. Omission/null means dependency export unavailable; an explicitly empty list declares no further dependencies. Only use actual parser/export evidence for these fields. Duplicate/unsafe references are rejected. Traversal is iterative, follows transitive declarations where available, detects cycles and contradictory declarations, and reports unknown exports and unlisted references. No dependency is inferred from a filename. All original output fields remain available.

The validation view distinguishes `verified` (size/SHA256 match), `mismatched` (wrong size), `corrupt` (same size, wrong SHA256), `missing`, `unavailable` and `unlisted`. Here corrupt means bytes disagree with the baseline; it is not a claim that an archive parser diagnosed structural corruption. Unsafe, unreadable and changed-during-read states remain distinct. Extra physical files remain in unlistedFiles. Existing raw integrity statuses and TSV contract are preserved.

`declaredDependenciesVerified` requires nonempty roots, no unresolved declarations/cycles/conflicts, and every included file verified in the tree. It is separate from allExpectedFilesMatch, which retains its physical-baseline scope. Neither proves original graph completeness, eligibility or gameplay. A map or mode remains runtime unverified until actual load/play/complete tests pass. Reports contain no generated timestamps and are byte deterministic for identical stable inputs.


<!-- /coderabbit-ai-generated:v1 -->