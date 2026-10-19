# reachable

`reachable` is a local-first Python dependency-alert analyzer. It reads recorded OSV data and inspects Python source without importing or executing the project under analysis. Its result is deliberately conservative:

- `REACHABLE`: a complete static entry-point-to-vulnerable-symbol chain was found.
- `NOT_PROVEN_REACHABLE`: the available source does not prove a call path.
- `UNKNOWN`: dynamic behavior, a transitive dependency, a parse problem, or missing advisory symbol data prevents a stronger claim.

A result is never a declaration that a project is safe.

## Requirements

- Python 3.11 (the version is pinned in `.python-version`)
- `make` for the canonical test command
- Docker 24+ for the container workflow

The application is designed to work offline after its locked dependencies are available locally. It does not require credentials or an OSV network request in demo mode.

## Setup

From the repository root:

```sh
python3.11 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.lock
python -m pip install --no-deps -e .
cp .env.example .env
```

On Windows PowerShell, activate with `.venv\Scripts\Activate.ps1`; the package and test commands are otherwise the same. `.env` is ignored and contains no required secrets.

## Run the offline demo

```sh
. .venv/bin/activate
make run
```

The server is expected to bind to `127.0.0.1` and serve the dashboard at `http://127.0.0.1:8000`. Configuration defaults are documented in `.env.example`. The demo is a real server-side analysis of the bundled fixture and offline advisory records; the browser does not substitute synthetic results when the API is unavailable.

## Analyze another project

Use **Choose folder** in the dashboard to open your operating system's folder picker. The browser uploads supported Python source and project metadata to the local server; the server stores it in a temporary directory, analyzes it without importing or executing it, and removes it before returning the result. This is the portable workflow when the dashboard is running inside Docker.

For a same-machine checkout, you can also type its path into the path field or use the CLI:

```sh
reachable scan ./path/to/project
```

To provide offline advisories, include one of these in the selected project:

- `osv_records.json` or `osv.json` using an OSV-shaped record list, `{"records": [...]}`, or `{"vulnerabilities": [...]}`.
- `pip-audit.json` saved from `pip-audit --format=json`; it is read as data and does not cause reachable to execute pip-audit or the target project.

Alternatively set `REACHABLE_OSV_CACHE` to a local cached OSV JSON file. If no inventory is supplied, reachable returns a completed empty result and explains that no advisory inventory was provided; it never applies the demo cache to an unrelated project.

## Test

`make test` is the one canonical test command:

```sh
make test
```

The test suite covers the analyzer, API, end-to-end demo, exports, security invariants, packaging contracts, and static frontend checks.

## Build

Build a local wheel with the pinned runtime dependencies installed:

```sh
make build
```

Build and run the demo container:

```sh
docker build --tag reachable:dev .
docker run --rm --network host reachable:dev
```

The container keeps the service on loopback inside the container. On Linux, `--network host` makes that loopback address available on the host. Docker is optional; local Python setup is the primary workflow.

## Deploy

For a local deployment, use the image above and keep it reachable only from the local machine. A production deployment must add an authentication and network boundary appropriate to its environment; this project does not ship credentials or a hosted OSV service. Review the image and dependency lock before publishing it.

## How classification works

1. Dependency alerts are read from cached OSV-shaped JSON records.
2. Vulnerable symbols are resolved from structured advisory extensions, a curated map, or conservative backticked identifiers in advisory text.
3. Python files are parsed with `ast`; imports, aliases, attributes, basic instances, routes, and module-level entry points form a conservative call graph.
4. Dynamic dispatch is surfaced as uncertainty. Every reachable claim includes file-and-line evidence for each hop.

The public HTTP shapes are in [docs/API.md](docs/API.md), and OSV field observations and resolution rules are in [docs/OSV_NOTES.md](docs/OSV_NOTES.md). The published wheel includes the dashboard, offline OSV cache, symbol map, and demo fixture.

## Limitations

Static analysis cannot see all dynamic code. `NOT_PROVEN_REACHABLE` does not mean safe. Many advisories name no function or module, and transitive dependencies are `UNKNOWN` in v1. Reflection, generated code, runtime plugin loading, and environment-specific imports can reduce confidence. The benchmark is intentionally not fabricated before real project snapshots are added; see [docs/BENCHMARK.md](docs/BENCHMARK.md).

## Project checks

The canonical commands are:

```sh
make test
make build
reachable serve --demo
```

The source brief files are intentionally kept out of the public repository. Runtime assets are packaged into the wheel so the installed CLI remains functional outside the source checkout.
