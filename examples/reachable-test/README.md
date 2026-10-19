# reachable-test

This is a tiny source-only project for trying the reachable dashboard. The
dependency packages do not need to be installed: reachable reads the source,
metadata, and offline `osv_records.json` without importing or executing this
project.

Expected findings:

- `LOCAL-REACHABLE-001`: `REACHABLE` via `__main__` -> `main` -> `demo_pkg.vulnerable`.
- `LOCAL-NOT-PROVEN-002`: `NOT_PROVEN_REACHABLE` because `unused-pkg` is declared but never imported.
- `LOCAL-UNKNOWN-003`: `UNKNOWN` with `DYNAMIC_CODE_BLOCKS_ANALYSIS` because `getattr` chooses the function at runtime.
