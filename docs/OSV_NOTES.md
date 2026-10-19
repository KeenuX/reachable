# OSV record notes

## Scope of these notes

The checked-in cache and fixtures are synthetic, OSV-shaped demo records; the repository does not yet contain a downloaded public PYSEC/GHSA corpus. Consequently, this document records the OSV schema fields the adapter must inspect and the observations that can be verified from those OSV-shaped records, without inventing a resolution percentage. When real records are added, the benchmark must report counts for each resolver layer and the sample size.

## Fields to preserve

An OSV record has a stable `id`, timestamps such as `published` and `modified`, human text in `summary` and `details`, links in `references`, and affected package/range data in `affected`. The useful package fields are:

| Field | Use |
| --- | --- |
| `id` | Stable advisory ID shown in the API and exports. |
| `affected[].package.name` | Package identity to match against project dependencies. |
| `affected[].package.ecosystem` | Ecosystem guard; v1 accepts PyPI/Python records. |
| `affected[].ranges` | Version events and introduced/fixed boundaries. |
| `affected[].versions` | Explicit affected versions when present. |
| `affected[].database_specific` | Database/vendor extensions; preserve them for symbol resolution. |
| `affected[].ecosystem_specific` | Ecosystem extensions; inspect for function/module names but do not assume a standard key. |
| `details`, `summary` | Fallback advisory prose, never proof of a call path. |
| `references` | Human review and report links. |

The core OSV schema does not standardize a universal vulnerable-function field. A PYSEC or GHSA record can therefore identify a package and version range while naming no callable symbol. GitHub-origin records often include aliases and database-specific metadata; those aliases are identifiers, not vulnerable functions. Any vendor extension such as `affected_functions`, `functions`, `modules`, or `symbols` must be treated as structured only when its shape is validated and the record source is retained.

## Layered symbol resolver

The analyzer should resolve symbols in this order and record the first successful layer:

1. **`osv_structured`** — validated function/module/symbol values in a known structured extension. Preserve the exact field path in diagnostic metadata.
2. **`curated_map`** — a checked-in map for a well-known package, with a source URL and a `curated` label. A map entry is product knowledge, not evidence that the current project calls the symbol.
3. **`inferred_from_text`** — conservative identifiers in backticks or equivalent clearly delimited advisory prose, such as `` `package.function()` ``. This layer caps confidence at `medium` and must never invent names from arbitrary prose.
4. **`none`** — no symbol was found. This forces `UNKNOWN` with `NO_SYMBOL_IN_ADVISORY`.

A package match alone cannot produce `REACHABLE`: it can support `NOT_PROVEN_REACHABLE` when the package is not imported, but a reachable claim needs an evidence chain ending in a resolved vulnerable symbol.

## Minimal record shapes used by offline fixtures

The fixture records remain valid OSV-shaped JSON while using an explicitly documented `database_specific.affected_functions` extension so resolver behavior is deterministic:

```json
{
  "schema_version": "1.6.0",
  "id": "GHSA-demo-reachable",
  "published": "2024-01-01T00:00:00Z",
  "modified": "2024-01-02T00:00:00Z",
  "summary": "Demo advisory",
  "details": "The affected function is `vulnerable_pkg.connect()`.",
  "affected": [{
    "package": {"ecosystem": "PyPI", "name": "vulnerable-pkg"},
    "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.0.0"}]}],
    "database_specific": {"affected_functions": ["vulnerable_pkg.connect"]}
  }],
  "references": [{"type": "ADVISORY", "url": "https://osv.dev/"}]
}
```

## Measurement rule

`docs/BENCHMARK.md` must report, for each corpus, raw alert count and how many alerts resolved at each of `osv_structured`, `curated_map`, `inferred_from_text`, and `none`. The denominator is alerts with a package/version match, not source files. Do not report a percentage until a corpus and its sample count are checked in.
