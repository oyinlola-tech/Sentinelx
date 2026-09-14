# SentinelX developer commands. Run `make help` for the list.
SHELL := /bin/bash
.DEFAULT_GOAL := help

PYTHON ?= python3
VENV   ?= .venv
BIN    := $(VENV)/bin
DASH   := apps/dashboard
PCAP   ?= pcaps/fixtures/mixed_intrusion.pcap

.PHONY: help
help: ## Show this help
	@awk 'BEGIN {FS = ":.*##"} /^[a-zA-Z0-9_-]+:.*##/ {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

# --------------------------------------------------------------------- setup
$(BIN)/python:
	$(PYTHON) -m venv $(VENV)

.PHONY: install
install: $(BIN)/python ## Install backend (editable, with dev tools) and dashboard dependencies
	$(BIN)/pip install -e ".[dev]"
	cd $(DASH) && npm ci
	@test -f .env || (cp .env.example .env && echo "created .env from .env.example - review it")

# ----------------------------------------------------------------------- run
.PHONY: dev
dev: ## Run API (:8000) and dashboard (:3000) with reload; Ctrl-C stops both
	@trap 'kill 0' INT TERM; \
	$(BIN)/sentinelx start --reload & \
	(cd $(DASH) && SENTINELX_API_URL=http://127.0.0.1:8000 npm run dev) & \
	wait

.PHONY: api
api: ## Run only the API
	$(BIN)/sentinelx start --reload

.PHONY: dashboard
dashboard: ## Run only the dashboard dev server
	cd $(DASH) && SENTINELX_API_URL=http://127.0.0.1:8000 npm run dev

.PHONY: fixtures
fixtures: ## Write all synthetic scenario pcaps to pcaps/fixtures
	$(BIN)/sentinelx fixtures generate --output pcaps/fixtures

.PHONY: replay
replay: ## Replay a capture through the pipeline: make replay PCAP=path/to/file.pcap
	@test -f "$(PCAP)" || $(MAKE) fixtures
	$(BIN)/sentinelx replay "$(PCAP)"

.PHONY: seed
seed: ## Fill the development database with detections from synthetic scenarios
	$(BIN)/python scripts/seed_demo.py

# ---------------------------------------------------------------- quality
.PHONY: test
test: ## Run the test suite (SQLite; no external services)
	$(BIN)/pytest

.PHONY: test-integration
test-integration: ## Run tests against real PostgreSQL and Redis in throwaway containers
	docker run -d --rm --name sx-it-pg -e POSTGRES_USER=sentinelx -e POSTGRES_PASSWORD=sentinelx-test -e POSTGRES_DB=sentinelx_test -p 127.0.0.1:55432:5432 postgres:17-alpine >/dev/null
	docker run -d --rm --name sx-it-redis -p 127.0.0.1:56379:6379 redis:7-alpine >/dev/null
	@trap 'docker rm -f sx-it-pg sx-it-redis >/dev/null' EXIT; \
	for i in $$(seq 1 30); do docker exec sx-it-pg pg_isready -U sentinelx >/dev/null 2>&1 && break; sleep 1; done; \
	SENTINELX_TEST_POSTGRES_URL=postgresql://sentinelx:sentinelx-test@127.0.0.1:55432/sentinelx_test \
	SENTINELX_TEST_REDIS_URL=redis://127.0.0.1:56379/0 $(BIN)/pytest

.PHONY: coverage
coverage: ## Test with a coverage report
	$(BIN)/pytest --cov --cov-report=term-missing

.PHONY: lint
lint: ## Lint Python (ruff) and the dashboard (eslint)
	$(BIN)/ruff check packages apps tests scripts
	$(BIN)/ruff format --check packages apps tests scripts
	cd $(DASH) && npm run -s lint

.PHONY: typecheck
typecheck: ## Strict mypy and TypeScript checks
	$(BIN)/mypy
	cd $(DASH) && npm run -s typecheck

.PHONY: format
format: ## Auto-fix lint issues and format
	$(BIN)/ruff check --fix packages apps tests scripts
	$(BIN)/ruff format packages apps tests scripts

.PHONY: rules
rules: ## Validate every rule file and run its embedded tests
	$(BIN)/sentinelx rules validate
	$(BIN)/sentinelx rules test rules

.PHONY: openapi
openapi: ## Regenerate the dashboard's typed API contract
	$(BIN)/python scripts/export_openapi.py
	cd $(DASH) && npm run -s generate:api

.PHONY: check
check: lint typecheck test rules ## Everything CI runs, locally
	cd $(DASH) && npm run -s build

# ------------------------------------------------------------- benchmarks
.PHONY: benchmark
benchmark: ## Run the controlled detection experiments (writes benchmarks/results/)
	$(BIN)/python scripts/benchmark.py --runs 5

# ----------------------------------------------------------------- docker
.PHONY: docker-build
docker-build: ## Build the API and dashboard images
	docker compose build

.PHONY: docker-up
docker-up: ## Start PostgreSQL, Redis, API and dashboard
	@test -f .env || (echo "create .env first: cp .env.example .env" && exit 1)
	docker compose up -d --build
	@echo "API http://127.0.0.1:$${API_PORT:-8000}/api/docs   dashboard http://127.0.0.1:$${DASHBOARD_PORT:-3000}"

.PHONY: docker-down
docker-down: ## Stop the stack (data volumes are kept)
	docker compose down

.PHONY: docker-logs
docker-logs: ## Follow API logs (shows the one-time admin password on first start)
	docker compose logs -f api

# ------------------------------------------------------------------ misc
.PHONY: clean
clean: ## Remove caches and build output (keeps .venv and node_modules)
	rm -rf .pytest_cache .mypy_cache .ruff_cache htmlcov .coverage $(DASH)/.next
	find . -name __pycache__ -type d -not -path "./.venv/*" -not -path "*/node_modules/*" -exec rm -rf {} +
