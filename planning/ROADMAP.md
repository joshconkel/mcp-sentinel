# Roadmap: mcp-sentinel

This document tracks the planned build phases, milestone criteria, and future
directions for `mcp-sentinel`. Phases are sequential. Each phase ships something
independently useful before the next begins.

---

## Phase 1: Static Analysis MVP

**Goal:** A working CLI tool that scans an MCP server definition file and
produces a risk-scored report. Independently useful on day one.

**Status:** Active development — core complete, tuning in progress

### Milestone 1.1: Core Infrastructure ✅

- [x] Project scaffold (`cli.py`, `loaders/`, `checks/`, `reporter.py`)
- [x] `sources.yaml` loader with validation and staleness detection
- [x] `rules.yaml` loader with schema validation
- [x] `ServerDefinition` normalization from JSON and YAML input
- [x] `Finding` and `SourceMapping` data models
- [x] Terminal reporter with Rich (severity colors, summary table, risk score)

### Milestone 1.2: Phase 1 Checks ✅

- [x] MCPS-001: Tool Poisoning via Description Field (regex + unicode + length)
- [x] MCPS-002: Secret and Token Exposure (regex against known secret patterns)
- [x] MCPS-003: Overly Permissive Parameter Schemas (schema_analysis)
- [x] MCPS-004: Insecure Transport Configuration (value_check on server URL)
- [x] MCPS-005: Agentic Supply Chain: Unverified Tool Provenance (value_check on packages)

### Milestone 1.2+: Extended Rule Set ✅

- [x] Generic rule engine (`checks/generic.py`) driving MCPS-006 through MCPS-150 from YAML
- [x] 145 experimental rules spanning 80+ threat categories (prompt injection, supply chain, credential exposure, model integrity, data exfiltration, adversarial AI, and more)
- [x] Full field extraction system: `tool.description`, `tool.inputSchema`, `server.url`, `server.env.*`, `server.packages[]`, and more
- [x] `missing_fields` value checks on dicts (flat key lookup)
- [x] `matches_unpinned` version string checks (exposed from package version field)
- [x] Parameter default value exposure for placeholder-detection rules

### Milestone 1.3: Output and Integration ✅

- [x] JSON reporter (CI/CD output with exit code support)
- [x] HTML reporter (stakeholder report with Jinja2 template)
- [x] `--fail-on` flag (exit code 1 when findings at or above threshold)
- [x] `mcp-sentinel rules list` command (show active rules with source mappings)
- [x] `mcp-sentinel rules validate` command (validate rules.yaml and source references)
- [x] `mcp-sentinel sources check` command (flag stale source definitions, `--warn-after` days)

### Milestone 1.4: Quality and Packaging ✅

- [x] Benign fixture (`benign-server.json`): zero findings across all 150 rules
- [x] Malicious fixtures: one per rule (MCPS-001 through MCPS-150)
- [x] 350 unit and integration tests — one `TestMCPSNNN` class per rule
- [x] `pyproject.toml` with correct `setuptools.build_meta` build backend
- [x] GitHub Actions CI workflow (test, lint, type-check, demo scan, sources staleness check)
- [x] mypy `--strict` passing across all source files
- [x] ruff clean with documented per-file suppressions

### Remaining Phase 1 Work

- [ ] Promote experimental rules to `active` as false positive rates are validated
  - Rules need real-world fixture coverage beyond the current minimal test fixtures
  - Target: promote highest-confidence rules (MCPS-006 through MCPS-030 range) first
- [ ] `pip install mcp-sentinel` via PyPI (requires first release tag)
- [ ] Phase 1 README finalization and demo GIF

**Phase 1 ship criteria:** All five core checks passing, JSON and terminal output working, `mcp-sentinel sources check` and `mcp-sentinel rules validate` working, installable via pip, GitHub Actions integration example functional, and a working set of promoted active rules beyond the initial five.

---

## Phase 2: LLM-Assisted Semantic Analysis

**Goal:** Use an LLM as a second-pass analyzer to detect subtle tool poisoning
and manipulation that regex-based patterns cannot reliably catch. Extends Phase 1
checks without replacing them.

**Status:** Planned (follows Phase 1 ship)

### Milestone 2.1: Anthropic API Integration

- [ ] `checks/semantic.py` (new check type: `semantic`)
- [ ] Anthropic SDK integration with configurable model selection
- [ ] Prompt templates for tool description analysis (stored in `rules/prompts/`)
- [ ] Structured JSON output from the LLM parsed into `Finding` objects
- [ ] `--no-llm` flag to run Phase 1 checks only (offline / cost-sensitive environments)

### Milestone 2.2: Semantic Rules

- [ ] MCPS-S01: Semantic Tool Poisoning Detection
  - Flags descriptions that imply hidden behavior, capability self-grants,
    or instructions that contradict the stated tool name or purpose
- [ ] MCPS-S02: Semantic Scope Creep Detection
  - Flags tool descriptions that claim access far beyond what the tool name implies
    (e.g., a `format_date` tool description referencing filesystem or network access)

### Milestone 2.3: Calibration and Cost Controls

- [ ] Per-run token usage reporting
- [ ] Configurable LLM analysis scope (description-only, full schema, both)
- [ ] False positive feedback mechanism (local ignore list for known-safe tools)
- [ ] Phase 2 documentation updates

**Phase 2 ship criteria:** Semantic checks running against known-bad tool descriptions with measurable detection rate, token cost reporting working, and `--no-llm` flag allowing full Phase 1 function without API access.

---

## Phase 3: Dynamic Probing

**Goal:** Connect to a live MCP server and send crafted payloads to probe for
runtime vulnerabilities that static analysis cannot detect. Extends the existing
architecture additively (new loader, new check type, same finding/reporting pipeline).

**Status:** Planned (follows Phase 2 ship)

### Milestone 3.1: Live Server Connectivity

- [ ] `loaders/live.py` — connect to running MCP server via SSE / WebSocket
- [ ] Tool enumeration from live server (discover actual tools without a static definition file)
- [ ] Session management and authentication handling

### Milestone 3.2: Dynamic Checks

- [ ] MCPS-D01: Response Boundary Violation — crafted inputs that produce outputs containing injected content
- [ ] MCPS-D02: Privilege Escalation via Tool Chaining — tool sequences that acquire permissions beyond what individual tools allow
- [ ] MCPS-D03: Information Disclosure via Error Messages — error responses that expose internal state, stack traces, or credentials

### Milestone 3.3: Integration

- [ ] `--live-url` flag on `mcp-sentinel scan` (combines static + dynamic analysis)
- [ ] Dynamic findings clearly labeled in all report formats
- [ ] Rate limiting and scan scope controls (prevent DoS against the target server)

**Phase 3 ship criteria:** At least two dynamic checks running against a reference MCP server with known vulnerabilities, combined static + dynamic report working, and rate limiting preventing scan abuse.
