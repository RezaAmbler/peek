# PEEK local development shortcuts.
# Tabs required for recipe lines (Makefile syntax).

.PHONY: help install test test-backend test-frontend test-watch build lint format format-check audit clean all

VENV := .venv
# Backend pins require Python >=3.10 (Docker runs 3.11); system python3 on macOS
# is 3.9 (EOL), so prefer a modern interpreter explicitly. Override with
# `make install PYTHON=python3.11` if needed.
PYTHON ?= $(shell command -v python3.12 || command -v python3.11 || command -v python3.10 || echo python3)
PY := $(VENV)/bin/python
PIP := $(VENV)/bin/pip
NPM := cd frontend && npm

help:  ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'

install:  ## Install backend and frontend deps in .venv and node_modules
	$(PYTHON) -m venv $(VENV)
	$(PY) -m pip install --upgrade pip setuptools wheel
	$(PY) -m pip install -r backend/requirements.txt -r requirements-dev.txt
	$(NPM) install

test: test-backend test-frontend  ## Run all tests

test-backend:  ## Run backend pytest
	$(PY) -m pytest

test-frontend:  ## Run frontend vitest
	$(NPM) test

test-watch:  ## Run frontend vitest in watch mode
	$(NPM) run test:watch

build:  ## Build frontend production bundle
	$(NPM) run build

lint:  ## Run frontend eslint
	$(NPM) run lint

format:  ## Auto-format frontend code with prettier
	$(NPM) run format

format-check:  ## Check frontend formatting without modifying files
	$(NPM) run format:check

audit:  ## Run pip-audit (Python) and npm audit (frontend)
	$(PY) -m pip_audit -r backend/requirements.txt || true
	$(NPM) audit || true

clean:  ## Remove .venv, node_modules, build artifacts
	rm -rf $(VENV)
	rm -rf frontend/node_modules frontend/dist
	rm -rf .pytest_cache backend/.pytest_cache
	find . -name '__pycache__' -type d -exec rm -rf {} + 2>/dev/null || true

all: test build  ## Run all tests + build
