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

A completed response has this shape:

```json
{
  "analysis_id": "demo-001",
  "status": "completed",
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

Allowed reason codes are `CALL_CHAIN_FOUND`, `PACKAGE_NOT_IMPORTED`, `SYMBOL_NOT_CALLED`, `NO_SYMBOL_IN_ADVISORY`, `DYNAMIC_CODE_BLOCKS_ANALYSIS`, `TRANSITIVE_DEPENDENCY`, and `PARSE_ERROR`.
