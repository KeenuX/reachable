# HTTP API contract

This document is the frontend/backend seam. The dashboard may use a mock with these same shapes before the FastAPI implementation lands. JSON keys are lower snake case. Unknown keys may be added; clients must ignore keys they do not use.

## Common rules

- The service is local-only by default and binds to `127.0.0.1`.
- Paths are accepted only after normalization and containment checks. The analyzer must not follow a path outside the requested project root.
- The analyzer never imports or executes source from the analyzed project.
- Any subprocess invocation uses an argument list; `shell=True` is forbidden.
- Error responses use `{"error": {"code": "...", "message": "..."}}`; messages must not include secrets or full environment dumps. Completed responses use `status: "completed"`.
- `status` is one of `REACHABLE`, `NOT_PROVEN_REACHABLE`, or `UNKNOWN`.
- `confidence` is one of `high`, `medium`, or `low`.
- `symbol_source` is one of `osv_structured`, `curated_map`, `inferred_from_text`, or `none`.

## `POST /api/analyze`

Starts or completes an analysis. The v1 implementation may process synchronously; a `202` response is also valid for an implementation that queues work.

Request:

```json
{
  "path": "./fixtures/demo_app",
  "include_tests": false
}
```

`path` is required and must be a local project directory. `include_tests` defaults to `false`. Demo mode may additionally accept `{"demo": true}` and must use repository fixtures without network access.

For an arbitrary project, `osv_records.json` at the project root is the
authoritative offline advisory inventory. The file may be an OSV record list,
an OSV response object with `vulnerabilities`, or a local wrapper object with
`records`. A saved `pip-audit --format=json` list is also accepted; package
version, fix versions, aliases, description, and URLs are normalized without
executing pip-audit or the target project. The bundled demo cache is used only by `/api/demo`; it must not add
demo alerts to an arbitrary project. If an arbitrary project has no local
inventory and no explicitly configured external cache, the completed result is
the no-advisory empty state described below. Local inventory loading never
performs network I/O.

Dependency declarations are read without importing the project:

- `requirements.txt` entries and PEP 508 names in
  `[project].dependencies` in `pyproject.toml` are direct dependencies. The
  package name is normalized for comparison while its exact pinned version is
  retained for `installed_version`.
- An imported package that is not present in either declaration is treated as
  transitive in v1, so its finding is `UNKNOWN` with
  `TRANSITIVE_DEPENDENCY`. This does not claim that an undeclared package is
  safe; it records that v1 does not inspect its parent package.
- `[project.scripts]` and
  `[project.entry-points."console_scripts"]` values of the form
  `module:function` create static entry points. A console-script entry point
  is represented by the module/function source location as the first evidence
  hop in a reachable chain.

A completed response has this shape:

```json
{
  "analysis_id": "demo-001",
  "status": "completed",
  "advisory_source": "project",
  "summary": {
    "total": 4,
    "reachable": 1,
    "not_proven_reachable": 1,
    "unknown": 2
  },
  "alerts": [
    {
      "advisory_id": "GHSA-example",
      "package": "example-package",
      "installed_version": "1.0.0",
      "severity": "high",
      "status": "REACHABLE",
      "reason_code": "CALL_CHAIN_FOUND",
      "confidence": "high",
      "symbol_source": "osv_structured",
      "why": "A route reaches the affected function.",
      "evidence": [
        {"file": "app.py", "line": 12, "symbol": "route"},
        {"file": "app.py", "line": 8, "symbol": "affected_function"}
      ],
      "references": ["https://osv.dev/vulnerability/GHSA-example"]
    }
  ]
}
```

Every alert exposes the advisory metadata needed by the dashboard: the exact
declared `installed_version` when a pinned project dependency is available,
the normalized lowercase `severity` (`critical`, `high`, `medium`, `low`, or
`unknown`), and all URL values from the advisory `references` array. Missing
metadata is represented by `null`, `unknown`, or `[]` as appropriate; it must
not be silently fabricated.

When queued, the response must include `analysis_id` and `status: "queued"` or `"running"`; clients then poll the results endpoint.

## `GET /api/results/{analysis_id}`

Returns the same completed result shape, or a progress response:

```json
{
  "analysis_id": "demo-001",
  "status": "running",
  "progress": {"completed": 2, "total": 4},
  "alerts": []
}
```

Unknown IDs return HTTP 404.

## `POST /api/analyze/upload`

Accepts a folder represented as repeated `multipart/form-data` parts named
`files`. Each part's filename is a repository-relative POSIX path, so a
browser directory upload can send names such as `pkg/__init__.py`. The
endpoint accepts source files, dependency declarations, and the local
`osv_records.json` inventory using the same rules as `/api/analyze`.

The endpoint analyzes the temporary project synchronously and returns the
completed result shape above with an `analysis_id`. In a browser, the visible
Choose folder control uses the directory-upload file picker and sends only the
selected source and metadata files to this endpoint; the server never executes
those files. The temporary directory is
removed before the response is returned, on both success and failure, and no
absolute temporary path is included in the result. A filename that is
absolute, contains `..` path traversal, or resolves outside the temporary
project root returns HTTP 400 with the common `invalid_request` error envelope;
no file may be written outside that root.

`POST /api/upload` may be exposed as a compatibility alias with the same
contract; `/api/analyze/upload` is canonical.

## `GET /api/export/{analysis_id}`

Returns a self-contained report. `format` is required and is either `markdown` or `html`; the response uses `text/markdown` or `text/html` respectively. HTML export must escape advisory text, paths, symbols, and source snippets before inserting them into markup.

Example:

```text
GET /api/export/demo-001?format=markdown
Accept: text/markdown
```

Implementations may also expose `GET /api/export?analysis_id=...&format=...` as a compatibility alias. The path form is canonical.

## Alert and evidence invariants

- `REACHABLE` requires at least two evidence entries when the entry point and vulnerable symbol are distinct, and every entry includes a repository-relative `file` and positive `line`.
- `REACHABLE` requires `reason_code: CALL_CHAIN_FOUND`.
- `symbol_source: none` forces `status: UNKNOWN`; it cannot produce a reachable claim.
- `symbol_source: inferred_from_text` caps confidence at `medium`.
- `TRANSITIVE_DEPENDENCY`, `DYNAMIC_CODE_BLOCKS_ANALYSIS`, and `PARSE_ERROR` are `UNKNOWN` reasons.
- Counts in `summary` equal the number of alert statuses, not the number of packages.
- `advisory_source` is `project`, `configured`, `bundled`, or `none`. A project with an empty local advisory inventory returns `status: "completed"`,
  `summary: {"total": 0, "reachable": 0, "not_proven_reachable": 0,
  "unknown": 0}`, and empty `alerts` (and compatibility `results`) arrays.

Allowed reason codes are `CALL_CHAIN_FOUND`, `PACKAGE_NOT_IMPORTED`, `SYMBOL_NOT_CALLED`, `NO_SYMBOL_IN_ADVISORY`, `DYNAMIC_CODE_BLOCKS_ANALYSIS`, `TRANSITIVE_DEPENDENCY`, and `PARSE_ERROR`.
