# =============================================================================
# LLM Data Poisoning Detection PaaS — Makefile
# =============================================================================
# All targets assume the working directory is the project root.
# Docker Compose configuration lives in infrastructure/docker-compose.yml.
#
# Usage:
#   make dev          Start the full development stack
#   make test         Run the Python test suite via pytest
#   make lint         Run ruff linter
#   make type-check   Run mypy static type checker
#   make build        Build Docker images
#   make clean        Stop containers and remove volumes
#   make migrate      Apply Alembic migrations
#   make migration    Generate a new migration revision
# =============================================================================

# ---------------------------------------------------------------------------
# Variables — override on the command line, e.g. make test PYTEST_ARGS="-k mcp"
# ---------------------------------------------------------------------------

# Compose file location (relative to project root)
COMPOSE_FILE        := infrastructure/docker-compose.yml
COMPOSE             := docker compose -f $(COMPOSE_FILE)

# Python interpreter (prefer .venv if present)
PYTHON              := $(if $(wildcard backend/.venv/bin/python),backend/.venv/bin/python,python3)
PYTEST              := $(if $(wildcard backend/.venv/bin/pytest),backend/.venv/bin/pytest,pytest)
RUFF                := $(if $(wildcard backend/.venv/bin/ruff),backend/.venv/bin/ruff,ruff)
MYPY                := $(if $(wildcard backend/.venv/bin/mypy),backend/.venv/bin/mypy,mypy)
ALEMBIC             := $(if $(wildcard backend/.venv/bin/alembic),backend/.venv/bin/alembic,alembic)

# Test configuration
PYTEST_ARGS         ?=
COVERAGE_THRESHOLD  ?= 80
FILE                ?= backend/tests/

# Migration message (used by `make migration`)
MSG                 ?= auto

# Image tag for `make build`
IMAGE_TAG           ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo latest)
REGISTRY            ?= ghcr.io/ai-cowboys/poisoning-detection

# ---------------------------------------------------------------------------
# Default target
# ---------------------------------------------------------------------------
.DEFAULT_GOAL := help

.PHONY: help
help:
	@echo ""
	@echo "LLM Data Poisoning Detection PaaS"
	@echo "=================================="
	@echo ""
	@echo "Development:"
	@echo "  make dev              Start the full Docker stack (detached)"
	@echo "  make dev-fg           Start the full Docker stack (foreground)"
	@echo "  make stop             Stop all containers (preserve volumes)"
	@echo "  make clean            Stop containers and remove volumes"
	@echo "  make restart SVC=api  Restart a specific service"
	@echo "  make logs             Tail logs for all services"
	@echo "  make logs SVC=api     Tail logs for a specific service"
	@echo "  make ps               Show container status"
	@echo ""
	@echo "Shells:"
	@echo "  make shell-api        Open a shell in the API container"
	@echo "  make shell-frontend   Open a shell in the frontend container"
	@echo "  make psql             Connect to Postgres via psql"
	@echo "  make redis-cli        Connect to Redis via redis-cli"
	@echo "  make cypher-shell     Open Neo4j cypher-shell"
	@echo ""
	@echo "Backend:"
	@echo "  make install          Install Python dependencies into backend/.venv"
	@echo "  make test             Run full pytest suite"
	@echo "  make test-unit        Run unit tests only"
	@echo "  make test-integration Run integration tests only"
	@echo "  make test-coverage    Run tests with HTML coverage report"
	@echo "  make lint             Lint Python code with ruff"
	@echo "  make lint-fix         Lint and auto-fix Python code with ruff"
	@echo "  make type-check       Run mypy static type checker"
	@echo "  make format           Format Python code with ruff formatter"
	@echo ""
	@echo "Database:"
	@echo "  make migrate          Apply Alembic migrations (head)"
	@echo "  make migrate-down     Roll back one Alembic revision"
	@echo "  make migration MSG=.. Generate a new Alembic revision"
	@echo "  make db-reset         Drop and recreate the dev database (DESTRUCTIVE)"
	@echo ""
	@echo "Frontend:"
	@echo "  make npm-install      Install Node.js dependencies"
	@echo "  make frontend-lint    Lint Next.js code with eslint"
	@echo "  make frontend-type    Type-check Next.js with tsc"
	@echo ""
	@echo "Build & Release:"
	@echo "  make build            Build all Docker images"
	@echo "  make build-api        Build API image only"
	@echo "  make build-frontend   Build frontend image only"
	@echo "  make push             Push images to registry (requires login)"
	@echo ""
	@echo "Utilities:"
	@echo "  make neo4j-init       Run Neo4j initialization Cypher script"
	@echo "  make env-check        Validate required env vars are set"
	@echo ""

# ---------------------------------------------------------------------------
# Development stack
# ---------------------------------------------------------------------------

.PHONY: dev
dev: env-check
	$(COMPOSE) up -d --build
	@echo ""
	@echo "Stack is up."
	@echo "  API:      http://localhost:$${API_HOST_PORT:-8000}"
	@echo "  Frontend: http://localhost:$${FRONTEND_HOST_PORT:-3000}"
	@echo "  Neo4j:    http://localhost:$${NEO4J_HTTP_HOST_PORT:-7474}"
	@echo ""
	@echo "Run 'make logs' to tail container output."

.PHONY: dev-fg
dev-fg: env-check
	$(COMPOSE) up --build

.PHONY: stop
stop:
	$(COMPOSE) stop

.PHONY: clean
clean:
	$(COMPOSE) down -v --remove-orphans
	@echo "All containers and volumes removed."

.PHONY: restart
restart:
	$(COMPOSE) restart $(SVC)

.PHONY: logs
logs:
	$(COMPOSE) logs -f $(SVC)

.PHONY: ps
ps:
	$(COMPOSE) ps

# ---------------------------------------------------------------------------
# Container shells
# ---------------------------------------------------------------------------

.PHONY: shell-api
shell-api:
	$(COMPOSE) exec api /bin/bash

.PHONY: shell-frontend
shell-frontend:
	$(COMPOSE) exec frontend /bin/sh

.PHONY: psql
psql:
	$(COMPOSE) exec postgres \
	  psql -U "$${POSTGRES_USER:-paas_user}" -d "$${POSTGRES_DB:-poisoning_detection}"

.PHONY: redis-cli
redis-cli:
	$(COMPOSE) exec redis \
	  redis-cli -a "$${REDIS_PASSWORD}"

.PHONY: cypher-shell
cypher-shell:
	$(COMPOSE) exec neo4j \
	  cypher-shell -u "$${NEO4J_USER:-neo4j}" -p "$${NEO4J_PASSWORD}"

# ---------------------------------------------------------------------------
# Python setup
# ---------------------------------------------------------------------------

.PHONY: install
install:
	cd backend && \
	  python3 -m venv .venv && \
	  .venv/bin/pip install --upgrade pip && \
	  .venv/bin/pip install -r requirements.txt -r requirements-dev.txt
	@echo "Python environment installed at backend/.venv"

# ---------------------------------------------------------------------------
# Testing
# ---------------------------------------------------------------------------

.PHONY: test
test:
	$(PYTEST) $(FILE) \
	  --tb=short \
	  --strict-markers \
	  -q \
	  $(PYTEST_ARGS)

.PHONY: test-unit
test-unit:
	$(PYTEST) backend/tests/unit/ \
	  --tb=short \
	  --strict-markers \
	  -q \
	  $(PYTEST_ARGS)

.PHONY: test-integration
test-integration:
	$(PYTEST) backend/tests/integration/ \
	  --tb=short \
	  --strict-markers \
	  -q \
	  $(PYTEST_ARGS)

.PHONY: test-coverage
test-coverage:
	$(PYTEST) backend/tests/ \
	  --cov=backend \
	  --cov-report=html:coverage_html \
	  --cov-report=term-missing \
	  --cov-fail-under=$(COVERAGE_THRESHOLD) \
	  --tb=short \
	  -q \
	  $(PYTEST_ARGS)
	@echo "Coverage report: coverage_html/index.html"

# ---------------------------------------------------------------------------
# Linting and formatting
# ---------------------------------------------------------------------------

.PHONY: lint
lint:
	$(RUFF) check backend/

.PHONY: lint-fix
lint-fix:
	$(RUFF) check --fix backend/

.PHONY: format
format:
	$(RUFF) format backend/

.PHONY: type-check
type-check:
	$(MYPY) backend/ \
	  --ignore-missing-imports \
	  --strict \
	  --exclude backend/tests/

# Run lint + type-check together (useful for CI pre-commit)
.PHONY: check
check: lint type-check

# ---------------------------------------------------------------------------
# Database migrations (Alembic)
# ---------------------------------------------------------------------------

.PHONY: migrate
migrate:
	cd backend && $(ALEMBIC) upgrade head

.PHONY: migrate-down
migrate-down:
	cd backend && $(ALEMBIC) downgrade -1

.PHONY: migration
migration:
	cd backend && $(ALEMBIC) revision --autogenerate -m "$(MSG)"
	@echo "New migration created in backend/alembic/versions/"

.PHONY: db-reset
db-reset:
	@echo "WARNING: This will DROP and recreate the poisoning_detection database."
	@read -p "Type 'yes' to continue: " confirm && [ "$$confirm" = "yes" ]
	$(COMPOSE) exec postgres \
	  psql -U "$${POSTGRES_USER:-paas_user}" -c \
	  "DROP DATABASE IF EXISTS $${POSTGRES_DB:-poisoning_detection}; \
	   CREATE DATABASE $${POSTGRES_DB:-poisoning_detection};"
	$(MAKE) migrate
	@echo "Database reset complete."

# ---------------------------------------------------------------------------
# Frontend
# ---------------------------------------------------------------------------

.PHONY: npm-install
npm-install:
	cd frontend && npm ci

.PHONY: frontend-lint
frontend-lint:
	cd frontend && npm run lint

.PHONY: frontend-type
frontend-type:
	cd frontend && npm run type-check

.PHONY: frontend-build
frontend-build:
	cd frontend && npm run build

# ---------------------------------------------------------------------------
# Docker image builds
# ---------------------------------------------------------------------------

.PHONY: build
build: build-api build-frontend

.PHONY: build-api
build-api:
	docker build \
	  -f infrastructure/Dockerfile.backend \
	  --target runtime \
	  --build-arg PYTHON_VERSION=3.12 \
	  -t $(REGISTRY)/api:$(IMAGE_TAG) \
	  -t $(REGISTRY)/api:latest \
	  .
	@echo "Built $(REGISTRY)/api:$(IMAGE_TAG)"

.PHONY: build-frontend
build-frontend:
	docker build \
	  -f infrastructure/Dockerfile.frontend \
	  --target runner \
	  --build-arg NODE_VERSION=20 \
	  --build-arg NEXT_PUBLIC_API_URL=$${NEXT_PUBLIC_API_URL:-http://localhost:8000} \
	  -t $(REGISTRY)/frontend:$(IMAGE_TAG) \
	  -t $(REGISTRY)/frontend:latest \
	  .
	@echo "Built $(REGISTRY)/frontend:$(IMAGE_TAG)"

.PHONY: push
push:
	docker push $(REGISTRY)/api:$(IMAGE_TAG)
	docker push $(REGISTRY)/api:latest
	docker push $(REGISTRY)/frontend:$(IMAGE_TAG)
	docker push $(REGISTRY)/frontend:latest

# ---------------------------------------------------------------------------
# Neo4j initialization
# ---------------------------------------------------------------------------

.PHONY: neo4j-init
neo4j-init:
	@echo "Running Neo4j initialization script..."
	$(COMPOSE) exec neo4j \
	  cypher-shell \
	    -u "$${NEO4J_USER:-neo4j}" \
	    -p "$${NEO4J_PASSWORD}" \
	    --database "$${DB_NEO4J_DATABASE:-poisoning}" \
	    --file /var/lib/neo4j/import/init.cypher
	@echo "Neo4j initialization complete."

# ---------------------------------------------------------------------------
# Environment validation
# ---------------------------------------------------------------------------

.PHONY: env-check
env-check:
	@test -f infrastructure/.env || \
	  (echo "ERROR: infrastructure/.env not found. Run: cp infrastructure/.env.example infrastructure/.env" && exit 1)
	@grep -q "CHANGE_ME" infrastructure/.env && \
	  echo "WARNING: infrastructure/.env still contains CHANGE_ME placeholders. Update before production use." || true

# ---------------------------------------------------------------------------
# CI shortcut — runs the full quality gate in one command
# ---------------------------------------------------------------------------

.PHONY: ci
ci: lint type-check test
	@echo "CI gate passed."
