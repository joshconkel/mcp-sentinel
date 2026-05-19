.PHONY: help install install-dev restructure lint test test-cov scan-demo \
        rules-validate sources-check clean

PYTHON   := python3
PIP      := pip
FIXTURE  := tests/fixtures/MCPS-001-malicious.json
BENIGN   := tests/fixtures/benign-server.json

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*##' $(MAKEFILE_LIST) \
		| sort \
		| awk 'BEGIN {FS = ":.*## "}; {printf "  \033[36m%-22s\033[0m %s\n", $$1, $$2}'

# ── Setup ────────────────────────────────────────────────────────────────────

install: ## Install package (runtime only)
	$(PIP) install -e .

install-dev: ## Install package with dev dependencies
	$(PIP) install -e ".[dev]"

restructure: ## Move flat Python files into mcp_sentinel/ package (run once after clone)
	bash scripts/restructure.sh

# ── Quality ──────────────────────────────────────────────────────────────────

lint: ## Run ruff linter
	ruff check mcp_sentinel/ tests/

lint-fix: ## Run ruff with auto-fix
	ruff check --fix mcp_sentinel/ tests/

typecheck: ## Run mypy type checker
	mypy mcp_sentinel/

test: ## Run full test suite
	pytest tests/ -v --tb=short

test-cov: ## Run tests with coverage report
	pytest tests/ -v --tb=short \
		--cov=mcp_sentinel \
		--cov-report=term-missing \
		--cov-report=html:htmlcov

# ── Rules and sources ────────────────────────────────────────────────────────

rules-validate: ## Validate rules.yaml structure and source references
	mcp-sentinel rules validate

rules-list: ## List all active rules with source mappings
	mcp-sentinel rules list

sources-check: ## Check threat sources for staleness
	mcp-sentinel sources check

# ── Demo scans ───────────────────────────────────────────────────────────────

scan-malicious: ## Scan the MCPS-001 malicious fixture (expect findings)
	mcp-sentinel scan --schema $(FIXTURE) --fail-on NONE

scan-benign: ## Scan the benign fixture (expect zero findings)
	mcp-sentinel scan --schema $(BENIGN)

scan-html: ## Scan malicious fixture and produce an HTML report
	mcp-sentinel scan \
		--schema $(FIXTURE) \
		--report html \
		--out report.html \
		--fail-on NONE
	@echo "Report written to report.html"

scan-json: ## Scan malicious fixture and produce JSON output
	mcp-sentinel scan \
		--schema $(FIXTURE) \
		--report json \
		--out scan-results.json \
		--fail-on NONE
	@python3 -c "\
import json; d = json.load(open('scan-results.json')); \
print(f'Score: {d[\"score\"][\"overall\"]}/100 [{d[\"score\"][\"label\"]}]'); \
print(f'Findings: {len(d[\"findings\"])}')"

# ── Cleanup ──────────────────────────────────────────────────────────────────

clean: ## Remove build artifacts and cache directories
	rm -rf dist/ build/ *.egg-info htmlcov/ .coverage .pytest_cache/ .mypy_cache/ .ruff_cache/
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -name "*.pyc" -delete 2>/dev/null || true
	rm -f report.html scan-results.json
