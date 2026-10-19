# Benchmark record

The benchmark is intentionally an empty, honest template until public project snapshots and their advisory inputs are vendored or reproducibly fetched. A benchmark result must not depend on a live network call during `make test`.

## Required run

For each of 5–8 public Python projects, record:

| Project / revision | Raw alerts | REACHABLE | NOT_PROVEN_REACHABLE | UNKNOWN | Structured | Curated | Inferred | None |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Pending checked-in snapshot | — | — | — | — | — | — | — | — |

The resolver percentages use the raw-alert denominator and must include the corpus revision, advisory snapshot date, Python version, and command.

## Hand verification

For five alerts per completed corpus, a reviewer should inspect the source line, import/alias chain, advisory symbol evidence, and the resulting status. Record true/false positives and false/false negatives separately, then report precision and recall against this small verified set. `UNKNOWN` is a valid outcome and must not be silently counted as safe.

## Reproducibility

Add snapshots under a future data-owned fixture location, document their license and revision, and keep network access out of the default test command. Until those inputs exist, the only checked-in ground truth is `tests/fixtures/demo_app/expected_results.json`.
