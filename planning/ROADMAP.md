# Roadmap: mcp-sentinel

This document tracks the planned build phases, milestone criteria, and future
directions for `mcp-sentinel`. Phases are sequential. Each phase ships something
independently useful before the next begins.

---

## Phase 1: Static Analysis MVP

**Goal:** A working CLI tool that scans an MCP server definition file and
produces a risk-scored report. Independently useful on day one.

**Status:** Active development

### Milestone 1.1: Core Infrastructure

- [ ] Project scaffold (`cli.py`, `loaders/`, `checks/`, `reporter.py`)
- [ ] `sources.yaml` loader with validation and staleness detection
- [ ] `rules.yaml` loader with schema validation (pydantic)
- [ ] `ServerDefinition` normalization from JSON and YAML input
- [ ] `Finding` and `SourceMapping` data models
- [ ] Terminal reporter with Rich (severity colors, summary table, risk score)

### Milestone 1.2: Phase 1 Checks

- [ ] MCPS-001: Tool Poisoning via Description Field (regex + unicode + length)
- [ ] MCPS-002: Secret and Token Exposure (regex against known secret patterns)
- [ ] MCPS-003: Overly Permissive Parameter Schemas (schema_analysis)
- [ ] MCPS-004: Insecure Transport Configuration (value_check on server URL)
- [ ] MCPS-005: Agentic Supply Chain: Unverified Tool Provenance (value_check on packages)

### Milestone 1.3: Output and Integration

- [ ] JSON reporter (CI/CD output with exit code support)
- [ ] HTML reporter (stakeholder report with Jinja2 template)
- [ ] `--fail-on` flag (exit code 1 when findings at or above threshold)
- [ ] `mcp-sentinel rules list` command (show active rules with source mappings)
- [ ] `mcp-sentinel sources check` command (flag stale source definitions)

### Milestone 1.4: Quality and Packaging

- [ ] Test fixtures: benign MCP server definitions, malicious variants for each check
- [ ] Unit tests for each check and the rule engine
- [ ] `pyproject.toml` (installable via `pip install mcp-sentinel`)
- [ ] GitHub Actions workflow example for CI/CD integration
- [ ] Phase 1 README with demo output and installation instructions

**Phase 1 ship criteria:** All five checks passing their test fixtures, JSON
and terminal output working, installable via pip, and a working GitHub Actions
integration example.

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
- [ ] Structured JSON output from the LLM parsed into Finding objects
- [ ] `--no-llm` flag to run Phase 1 checks only (for offline / cost-sensitive environments)

### Milestone 2.2: Semantic Rules

- [ ] MCPS-006: Semantic Tool Poisoning Detection
  - Flags descriptions that imply hidden behavior, capability self-grants,
    or instructions that contradict the stated tool name or purpose
- [ ] MCPS-007: Semantic Scope Creep Detection
  - Flags tool descriptions that claim access far beyond what the tool name implies
    (e.g., a "format_date" tool description referencing filesystem or network access)

### Milestone 2.3: Calibration and Cost Controls

- [ ] Per-run token usage reporting
- [ ] Configurable LLM analysis scope (description-only, full schema, both)
- [ ] False positive feedback mechanism (local ignore list for known-safe tools)
- [ ] Phase 2 documentation updates

**Phase 2 ship criteria:** Semantic checks running against a set of known-bad
tool descriptions with measurable detection rate, token cost reporting working,
and `--no-llm` flag allowing full Phase 1 function without API access.

---

## Phase 3: Dynamic Probing

**Goal:** Connect to a live MCP server and send crafted payloads to probe for
runtime vulnerabilities that static analysis cannot detect. Extends the existing
architecture additively (new loader, new check type, same finding/reporting pipeline).

**Status:** Planned (follows Phase 2 ship)

### Milestone 3.1: Live Server Connectivity

- [ ] `loaders/live.py` (SSE and WebSocket transport support)
- [ ] Tool discovery from live server (`list_tools` equivalent)
- [ ] Safe probe mode: read-only, no destructive tool calls
- [ ] Connection timeout and error handling

### Milestone 3.2: Dynamic Checks

- [ ] MCPS-008: Prompt Injection via Tool Results
  - Sends benign tool invocations and inspects results for embedded instructions
    (adversarial content in tool output that an agent would subsequently act on)
- [ ] MCPS-009: Caller Authentication Bypass
  - Probes whether tools can be invoked without authentication headers or tokens
- [ ] MCPS-010: Rate Limiting and Resource Exhaustion
  - Checks whether the server enforces rate limits on expensive tool invocations
- [ ] MCPS-011: Excessive Data Return
  - Flags tools that return significantly more data than a minimal response
    would require (information disclosure risk)

### Milestone 3.3: Integration and Safety Controls

- [ ] `--dry-run` flag (enumerate tools and planned probes without executing)
- [ ] Scope limiting: probe only named tools, not all discovered tools
- [ ] Audit log of every probe sent and response received
- [ ] Phase 3 documentation and responsible use guidance

**Phase 3 ship criteria:** Dynamic checks running against a reference MCP
server with known vulnerabilities, dry-run mode working, and audit logging
producing a complete record of probe activity.

---

## Future Directions (Post-Phase 3)

These are ideas worth tracking that do not yet have a phase assignment.

**Multi-server scanning**
Scan a directory of MCP server definitions in one pass and produce a
consolidated risk report across a fleet. Useful for platform teams managing
many internal MCP integrations.

**VSCode / IDE Extension**
Surface findings inline while a developer writes an MCP server definition.
Real-time feedback at the point of authorship is significantly cheaper than
catching issues in CI.

**SARIF Output**
Static Analysis Results Interchange Format (SARIF) output would allow
`mcp-sentinel` findings to appear natively in GitHub Advanced Security's
code scanning UI without any custom integration work.

**Registry Scanning**
Scan public MCP server registries for known-bad patterns and publish a
community block list. Analogous to what npm audit and OSV do for
conventional packages.

**Rule Contribution Pipeline**
A structured process for the community to submit new rules: a template,
a review checklist mapped to evidence requirements, and automated tests
against fixture files.

---

## Versioning

`mcp-sentinel` follows semantic versioning.

- Phase 1 ships as `0.1.x`
- Phase 2 ships as `0.2.x`
- Phase 3 ships as `0.3.x`
- `1.0.0` is declared when all three phases are stable and the rule schema
  is considered stable (breaking schema changes require a major version bump)

Rule definitions in `rules/rules.yaml` and `rules/sources.yaml` are versioned
independently of the package via the `version` field in each file header.
