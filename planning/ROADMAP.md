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
  - Structurally separate the analyzer's own instructions from the tool-description
    content being analyzed (explicit delimiters, an instruction to disregard any
    directives embedded in the analyzed text) — the description field being sent
    for analysis is exactly the injection vector MCPS-001 exists to catch, so the
    analyzer prompt needs the same hardening. See THREAT-MODEL.md section 6.
  - Gate semantic analysis behind MCPS-001's own pattern check as a pre-filter,
    not only as an independent parallel check
- [ ] **Decision needed:** data sent per tool — description-only, or description +
      full `inputSchema`? Not yet decided; affects both cost and exposure scope.
- [ ] Structured JSON output from the LLM parsed into `Finding` objects
  - Validate the response against an explicit schema before constructing `Finding`
    objects — a successful API call is not the same claim as trustworthy content
- [ ] `--llm` flag to opt in to semantic analysis, off by default even with the
      `phase2` extra installed (replaces the `--no-llm` framing this milestone
      previously used, which implied default-on — corrected after design review)
- [ ] Pre-call tool exclude list — excluded tools are never transmitted to the
      Anthropic API at all, distinct from the false-positive ignore list in
      Milestone 2.3 (which only suppresses findings *after* a tool was analyzed)
  - Warn when an exclude-list entry matches zero tools in a run, so a stale entry
    (e.g. after a tool rename) fails visibly instead of silently
  - Prefer a stable identifier over a mutable display name for matching, where one exists
- [ ] Audit log of which tools/fields were sent externally, when, and under which
      scan invocation — Stakeholder reports are consumed for compliance purposes,
      and an org may need to attest whether proprietary tool content ever left its control
- [ ] Explicit, enforced constraint that the analyzer has no tool-calling capability
      wired in — not left as an assumption implied by roadmap wording, so a later
      addition can't grant it action access without a deliberate design review
- [ ] Document this data flow prominently in user-facing docs (README, `--help`
      text), not only here; evaluate whether a local/self-hosted model path
      (mirroring the existing `--backend lmstudio` default in `scripts/ingest_atlas.py`)
      should be offered so the capability doesn't strictly require a third-party route

### Milestone 2.2: Semantic Rules

- [ ] MCPS-S01: Semantic Tool Poisoning Detection
  - Flags descriptions that imply hidden behavior, capability self-grants,
    or instructions that contradict the stated tool name or purpose
- [ ] MCPS-S02: Semantic Scope Creep Detection
  - Flags tool descriptions that claim access far beyond what the tool name implies
    (e.g., a `format_date` tool description referencing filesystem or network access)
- [ ] THREAT-MODEL.md section for MCPS-S01/MCPS-S02, per this repo's own convention
      that every new check gets a corresponding attack-scenario section — see the
      drafted section 6, which also covers the analyzer-targeted-injection scenario
      (an attacker targeting the semantic analyzer itself, not just a downstream agent)

### Milestone 2.3: Calibration and Cost Controls

- [ ] Per-run token usage reporting
- [ ] Per-run (or per-day) API-call budget with a clear failure mode when exceeded
      (skip remaining tools with a warning) — reporting alone doesn't cap runaway
      cost or rate on a large definition or a CI pipeline re-scanning on every commit
- [ ] Configurable LLM analysis scope (description-only, full schema, both)
- [ ] False positive feedback mechanism (local ignore list for known-safe tools —
      suppresses findings *after* a tool was analyzed; distinct from the pre-call
      exclude list in Milestone 2.1, which prevents transmission in the first place)
- [ ] Phase 2 documentation updates

**Phase 2 ship criteria:** Semantic checks running against known-bad tool descriptions with measurable detection rate; the Anthropic response schema-validated before constructing findings; the analyzer prompt hardened against injection from the content it analyzes; an audit log of external transmissions in place; a per-run API-call budget enforced (not just usage reporting); token cost reporting working; and the `--llm` flag defaulting off, with full Phase 1 function available with no API access required.

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
