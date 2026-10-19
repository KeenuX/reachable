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

The server is expected to bind to `127.0.0.1` and serve the dashboard at `http://127.0.0.1:8000`. Configuration defaults are documented in `.env.example`.

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
