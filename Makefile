PYTHON ?= $(if $(wildcard .venv/bin/python),.venv/bin/python,python3)

.PHONY: test install run build

test:
	$(PYTHON) -m pytest

install:
	$(PYTHON) -m pip install -r requirements.lock
	$(PYTHON) -m pip install --no-deps -e .

run:
	$(PYTHON) -m reachable serve --demo

build:
	$(PYTHON) -m pip wheel --no-deps --no-build-isolation --wheel-dir dist .
