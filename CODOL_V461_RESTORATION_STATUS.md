<!-- coderabbit-ai-generated:v1 -->

# CODOL v461 restoration status

**Status: incomplete; game compatibility and playability are unverified.** The connected repository primarily targets a different QA build; it has not been established as the primary v461 restoration workspace.

## Implemented in this branch

- [Inventory reconciler](tools/restoration/reconcile.py) validates a supplied manifest and records per-map and per-mode package and declared dependency status. It does not extract game archives or establish gameplay support. [Usage and limitations](tools/restoration/README.md).
- [Restoration tests](tools/restoration/tests/) cover file hashes, missing data, unsafe paths, addon associations and unresolved dependencies.
- The local backend's match-key client checks the reply's full endpoint and bounds each retry. Lobby diagnostics no longer print session keys or decrypted payloads. The HTTPS test uses temporary certificates.

The latest tested snapshot passed 36 restoration tests and 78 backend tests. These checks used synthetic files and local connections. They did not load the game or verify an actual match, controllers, maps, modes or Zombies. Original game files, profiles, source archives, and user data were not modified.

## Evidence and remaining work

The available documentary inventory contains 89 map records and 13 mode slots; original installation and dependency exports remain unavailable. The full tracker, machine state, package manifests, checkpoint archives and test evidence are local task artifacts and are excluded from Git to follow this repository's game-data and privacy rules. See [the coding task and its Outputs](https://app.coderabbit.ai/code/tasks/d0b75af3-a1ac-4e52-8dc5-8246da96f02d) for the review records.

The next game implementation requires the primary v461 source workspace or source bundle, including the version detector, zone/weapon loader, asset registry/resolver, build and tests, plus a lawful decoded original weapon fixture with hashes. A Windows build and the original game environment are required for runtime acceptance. Mecha's actual results and manifest are also needed to reconcile its reported asset recovery.
