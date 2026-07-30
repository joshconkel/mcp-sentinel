# Changelog

All notable changes to mcp-sentinel will be documented here.

This project follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Added

**Phase 2 planning & security review artifacts**
- `BUGFIX.md` — inventory of 9 security-relevant gaps identified in the current implementation via a DFD + STRIDE-questionnaire review, prioritized by severity, each tied to a specific finding, file location, and recommended fix
- `docs/security/abuse-case-library.yml` — new abuse/misuse pattern library seeded with 20 patterns drawn from OWASP API Security Top 10 2023, OWASP Top 10 2021, and OWASP Cornucopia; 4 patterns matched against the Phase 2 proposal (`times_matched` incremented), 3 new patterns proposed under `staged_patterns` pending human review before promotion
- Draft feature spec, abuse/misuse case review, and a consolidated STRIDE risk table produced for the proposed Phase 2 (LLM-Assisted Semantic Analysis) feature — informed the `planning/ROADMAP.md` and `planning/THREAT-MODEL.md` updates described under Changed, below

**Rule set expansion — 150 rules (MCPS-001 through MCPS-150)**
- 5 active rules: MCPS-001 through MCPS-005 (unchanged, fully validated)
- 145 experimental rules: MCPS-006 through MCPS-150, covering 80+ threat categories including prompt injection, tool poisoning, credential exposure, supply chain attacks, data exfiltration, model integrity, adversarial AI, deepfake facilitation, RAG poisoning, context manipulation, multi-agent security, and more
- All experimental rules are enabled by default and map to OWASP, MITRE ATLAS, and NIST AI RMF

**Generic rule engine (`checks/generic.py`)**
- New engine module that drives MCPS-006 through MCPS-150 entirely from `rules.yaml` pattern definitions — no Python code required to add rules in this range
- Field extraction for: `tool.description`, `tool.name`, `tool.annotations`, `tool.inputSchema`, `server.url`, `server.transport`, `server.config`, `server.env` / `server.env.*`, `server.packages[]`
- `server.env.*` field path accepted as alias for `server.env` — rules can use either notation
- `server.packages[]` exposes both the full package dict (for `missing_fields` checks) and the version string as a separate entry (for `matches_unpinned` checks)
- `tool.inputSchema` now also exposes each property's `"default"` value as a string with a field path of `tool.inputSchema.properties.{name}.default`, enabling placeholder-detection rules (e.g. MCPS-020) to fire on parameter defaults

**Test suite — 350 tests across 150 rules**
- One `TestMCPSNNN` class per rule, each containing at minimum a malicious-fixture and benign-fixture test
- Rules with richer semantics carry additional targeted assertions (severity level, finding field path, tool name presence, source mapping count)
- `TestSchemaLoader` and `TestEngineIntegration` cover the loader and full scan pipeline
- `benign-server.json` expanded with all security annotation keys required by experimental `missing_fields` rules, ensuring zero false positives across the full rule set

**Malicious test fixtures (MCPS-006 through MCPS-150)**
- Created and validated 145 malicious fixture files, one per experimental rule
- Each fixture is minimal — only the fields needed to trigger the target rule — to keep test failures informative

### Changed

**`planning/ROADMAP.md` — Phase 2 milestones expanded with concrete tasks**
- Milestone 2.1: added analyzer prompt-injection hardening (delimit untrusted content, disregard-embedded-directives instruction, gate behind MCPS-001 as a pre-filter), response schema validation before constructing `Finding` objects, a pre-call tool exclude list with a stale-entry warning requirement, an audit log of externally-transmitted tool content, and an explicit enforced constraint that the analyzer has no tool-calling capability wired in
- Renamed the planned `--no-llm` (opt-out framing, implying default-on) flag to `--llm` (opt-in) — semantic analysis is off by default even with the `phase2` extra installed
- Flagged the description-vs-schema data-scope question as an explicit open decision rather than leaving it unstated
- Milestone 2.2: added a cross-reference to the new `THREAT-MODEL.md` section 6
- Milestone 2.3: added a per-run/per-day API-call budget with a defined failure mode (reporting alone doesn't cap runaway cost); clarified that the Milestone 2.1 pre-call exclude list (prevents transmission) is distinct from the Milestone 2.3 false-positive ignore list (suppresses findings post-analysis)
- Phase 2 ship criteria updated to require all of the above, not just detection rate and cost reporting

**`planning/THREAT-MODEL.md` — new Section 6: Semantic Tool Poisoning & Scope Creep (MCPS-S01, MCPS-S02)**
- Added the previously-missing attack-scenario section for the two Phase 2 semantic rules, matching the existing per-check format used for MCPS-001 through MCPS-005
- Includes a dedicated subsection on analyzer-targeted prompt injection — the semantic analyzer itself is a target for a crafted tool description, not only a downstream agent — with its own OWASP LLM Top 10 (LLM01) reference alongside the existing MCP02/AML.T0051 references

**`checks/base.py` — regex skipped on dict values**
- `CheckRunner.run_pattern` now returns `None` without running regex when the target value is a `dict`
- Background: `str(dict)` in Python produces a representation containing all key names and values; several annotation key names (e.g. `adversarialFilter`, `executionContext`) accidentally matched security rule patterns, producing false positives on the benign fixture
- Regex checks remain valid on all string-valued fields; structured dict values are now exclusively handled by `value_check` (key presence) and `schema_analysis` (schema structure)

**`benign-server.json` — comprehensive security annotation fixture**
- Added all `missing_fields` annotation keys required by the 145 experimental rules as flat top-level keys in each tool's `inputSchema`
- Updated server URL to `https://mcp.example.com/mcp` — avoids both the internal-domain pattern (MCPS-012) and the public-endpoint URL pattern (MCPS-135)
- Updated tool descriptions to avoid triggering any experimental regex rule
- Added all package integrity fields (`integrity`, `checksum`, `hash`, `signature`, `sha256`) required by provenance rules

**CLI — `sources check` now a subcommand**
- `mcp-sentinel sources check` is now invoked as a subcommand of a `sources` Typer sub-app, consistent with the `rules list` / `rules validate` pattern
- Previously registered as `@app.command("sources")`, which caused `check` to be treated as an unexpected positional argument
- `sources_app = typer.Typer(...)` added alongside `rules_app`; `sources_check` decorated with `@sources_app.command("check")`

### Fixed

**`models.py` — `_dc_field` alias for `dataclasses.field`**
- `Finding.field: str` shadowed the `dataclasses.field` factory function inside the class body, causing mypy to report `"str" not callable` on line 139 where `field(default_factory=list)` is called for `source_mappings`
- Fix: module-level alias `_dc_field = field` created before the `Finding` class definition; `source_mappings` default uses `_dc_field(default_factory=list)`

**`secrets.py` — `targets` type annotation corrected**
- `targets: list[tuple[str, str, object]]` caused mypy to infer the unpacked `tool` variable as `object`, incompatible with `ToolDefinition | None` expected by `run_pattern`
- Fix: changed to `list[tuple[str, str, ToolDefinition | None]]`; added `ToolDefinition` to the import; removed now-stale `# type: ignore[arg-type]` suppression

**`cli.py` — type annotations and exception handling**
- `reporter_kwargs: dict` → `reporter_kwargs: dict[str, Any]`; added `Any` to `from typing import` line
- Four `raise typer.Exit(...)` inside `except` blocks now use `raise typer.Exit(...) from None` to satisfy B904 and suppress implicit exception chaining (the error has already been printed to the console)
- Long f-string at line 177 extracted to `src_short` variable; long f-string at line 270 split across two adjacent string literals

**`pyproject.toml` — build backend and ruff configuration**
- `build-backend` corrected from `"setuptools.backends.legacy:build"` (non-standard internal path) to `"setuptools.build_meta"` (the canonical setuptools PEP 517 backend)
- Added `[tool.ruff.lint.per-file-ignores]`:
  - `tests/*` → `["E501"]`: assertion messages in tests intentionally include full rule names for self-describing failures
  - `mcp_sentinel/cli.py` → `["B008"]`: Typer's design requires `typer.Option()` in function-parameter defaults; B008 is a false positive for this pattern
  - `mcp_sentinel/reporter.py` → `["E501"]`: HTML template strings embedded in Python cannot be wrapped at arbitrary column boundaries without injecting whitespace into rendered output

### Security

**Threat-modeling review of the current implementation**
- Ran a DFD + STRIDE-questionnaire pass against the existing Local Scan Runtime and Rule Maintenance Pipeline; identified 9 issues (1 Critical, 5 High, 3 Medium) — none fixed yet, full inventory with recommended fixes in `BUGFIX.md`
- Highest priority: `scripts/promote_staged.py` performs no runtime identity or authorization check on the only path that changes what mcp-sentinel will ever detect (`SECFIX-001`)
- Also confirmed several existing controls are working as intended and need no action: the 10MB input-size cap + `yaml.safe_load` usage, the ATLAS-ingest network timeouts, and the scan runtime's read-only blast radius

**Design-time abuse/misuse review of the proposed Phase 2 feature**
- Reviewed the Phase 2 (LLM-Assisted Semantic Analysis) proposal before any code was written; identified 8 findings, resolved into concrete tasks in `planning/ROADMAP.md` and a new attack-scenario section in `planning/THREAT-MODEL.md` rather than left as a standalone report (see Changed, above)
- Most notable: the semantic analyzer itself is a prompt-injection target — a crafted tool description could attempt to manipulate the *analyzer's* verdict, not just a downstream agent's behavior — addressed via prompt-hardening requirements in `ROADMAP.md` Milestone 2.1 and a dedicated subsection in the new `THREAT-MODEL.md` section

---

## Version History

No releases yet. Active development toward v0.1.0.

See [`ROADMAP.md`](planning/ROADMAP.md) for the Phase 1 definition of done that constitutes the v0.1.0 release criteria.

---

## Release Format

```
## [0.1.0] - YYYY-MM-DD

### Added        New features and capabilities
### Changed      Changes to existing behavior
### Fixed        Bug fixes
### Deprecated   Features to be removed in a future release
### Removed      Features removed in this release
### Security     Security fixes (with advisory reference where applicable)
```
