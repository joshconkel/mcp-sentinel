# Changelog

All notable changes to mcp-sentinel will be documented here.

This project follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased] — 2026-05-19

### Fixed

- **[BUG] `schema_analysis` patterns with `field_name_matches` never fired** (`mcp_sentinel/checks/base.py`)
  `CheckRunner.__init__` compiled all `regex` and `schema_analysis` patterns by reading
  `pattern.expression`. For `schema_analysis` patterns, `pattern.expression` is always `None` —
  their match regex lives in `pattern.condition["field_name_matches"]["regex"]`. As a result,
  `self._compiled[id(pattern)]` stored `None` for every `schema_analysis` pattern that used
  `field_name_matches`, and `_check_schema` bailed out immediately on `compiled is None` before
  evaluating any property names. The `additionalProperties` path in `_check_schema` was unaffected
  because it does not consult `_compiled`. Fixed by splitting the single
  `if pattern.type in {"regex", "schema_analysis"}` branch into two separate branches: the `regex`
  branch reads `pattern.expression` (unchanged); the new `schema_analysis` branch reads
  `condition["field_name_matches"]["regex"]` and its associated `flags` list.
  Affected rules that now fire correctly: MCPS-010, MCPS-015, MCPS-018, MCPS-019.

- **[BUG] MCPS-002 `test_connection_string_detected_in_env` test failure** (`mcp_sentinel/rules/rules.yaml`)
  The connection-string detection regex matched `postgres://` but not `postgresql://`. The test
  fixture used `postgresql://admin:s3cr3tpassw0rd@prod-db.internal:5432/customers`, which is the
  format produced by psycopg2, SQLAlchemy, and asyncpg in real environments. Fixed by changing the
  alternation from `postgres` to `postgres(?:ql)?`, which matches both the short alias and the full
  driver name while keeping all existing matches intact.

- **[LINT] 51 ruff errors resolved across 8 files**
  All errors introduced after the initial security-fix pass were corrected. Changes were applied
  file by file and verified with `ruff check mcp_sentinel/ tests/` reaching zero errors.
  - `UP035` — `Callable` moved from `typing` to `collections.abc` (`checks/__init__.py`)
  - `UP045` — Eight `Optional[Path]` annotations replaced with `Path | None` (`cli.py`)
  - `UP037` — Quoted return type annotations removed from `RiskScore` and `SourceDefinition`
    (`models.py`); unnecessary with `from __future__ import annotations` already present
  - `B904` — Four `raise typer.Exit(...)` inside `except` blocks updated to
    `raise ... from exc` or `raise ... from None` (`cli.py`)
  - `B008` — `typer.Option()` in function argument defaults added to `[tool.ruff.lint] ignore`;
    this is Typer's documented and required usage pattern (`pyproject.toml`)
  - `SIM102` — Two nested `if` statements collapsed to single `if ... and ...` (`checks/base.py`)
  - `SIM114` — Three identical `if/elif` branches assigning the same value collapsed to a single
    `if pattern.type in {"length", "regex", "unicode"}` (`checks/tool_poisoning.py`)
  - `F401` — Unused imports removed: `Severity` (`checks/base.py`), `INVISIBLE_CODEPOINTS`
    (`checks/tool_poisoning.py`), `sys` (`cli.py`), `os` (`loaders/schema.py`), `Table` and `box`
    (`reporter.py`), `RuleStatus`, `DetectionType`, `SourceMapping` (`tests/test_checks.py`)
  - `E501` — Two long lines in `cli.py` broken by extracting intermediate variables;
    `reporter.py` added to `[tool.ruff.lint.per-file-ignores]` for `E501` since the violations
    are inside embedded HTML template string literals that cannot be shortened
  - `I001` — All import ordering issues resolved by running `ruff check --fix`; the auto-fixer
    was required because isort's blank-line placement rules for `from __future__` blocks, stdlib
    sections, and first-party/third-party boundaries within function bodies are too subtle to
    reproduce reliably by hand

### Added

- **23 experimental rules** (`mcp_sentinel/rules/rules.yaml`)
  The rule set expanded from 5 active rules to 28 total rules (5 active, 23 experimental).
  All 28 rules map to all 5 registered threat intelligence sources. Experimental rules run and
  produce labeled findings but do not count toward `--fail-on` thresholds until promoted to
  `active` after fixture review.

  First expansion (MCPS-006 through MCPS-020) — pattern-driven technical checks derived from
  coverage gaps in the original five rules:
  - `MCPS-006` CRITICAL — Hidden Instructions in Tool Annotations
  - `MCPS-007` CRITICAL — LLM Jailbreak Trigger Language in Tool Definitions
  - `MCPS-008` CRITICAL — Credentials Embedded in Server URL
  - `MCPS-009` HIGH     — Dangerous Tool Name Indicating Direct System Access
  - `MCPS-010` HIGH     — Server-Side Request Forgery via Unrestricted URL Parameter
  - `MCPS-011` HIGH     — Unfiltered External Content Pass-Through
  - `MCPS-012` MEDIUM   — Internal Network Infrastructure Disclosure
  - `MCPS-013` HIGH     — Unrestricted Filesystem Access Pattern in Tool Description
  - `MCPS-014` MEDIUM   — Bulk or Unfiltered Data Return Pattern
  - `MCPS-015` HIGH     — Insecure Webhook or Callback URL Parameter
  - `MCPS-016` CRITICAL — Capability Self-Grant in Tool Definition
  - `MCPS-017` HIGH     — Tool Memory Write and Persistence Pattern
  - `MCPS-018` MEDIUM   — Numeric Parameter Without Range Constraints
  - `MCPS-019` CRITICAL — Executable Code or Script Parameter
  - `MCPS-020` HIGH     — Placeholder and Default Credential Values in Tool Parameters

  Second expansion (MCPS-021 through MCPS-028) — consolidated from 28 externally-generated draft
  rule files covering the remainder of OWASP MCP Top 10, OWASP Agentic Top 10, and OWASP LLM Top
  10. The 21 drafts that overlapped with existing rules were not added as duplicates; unique
  patterns and missing source mappings from those overlapping drafts were merged into the existing
  rules instead. Eight genuinely new entries were promoted:
  - `MCPS-021` HIGH     — Misconfigured Cross-Origin and CORS Policies (MCP09)
  - `MCPS-022` MEDIUM   — Insufficient Logging and Monitoring Indicators (MCP10)
  - `MCPS-023` HIGH     — Missing Human Oversight for High-Risk Operations (ASI03)
  - `MCPS-024` HIGH     — Cross-Agent Instruction Propagation Risk (ASI07)
  - `MCPS-025` HIGH     — Unauthenticated Cross-Agent Communication (ASI09)
  - `MCPS-026` HIGH     — Untrusted External Source References in Tool Definitions (LLM03)
  - `MCPS-027` HIGH     — Data and Model Poisoning Patterns in Tool Definitions (LLM04)
  - `MCPS-028` MEDIUM   — Misleading Security Claims in Tool Metadata (LLM09)

- **`mcp_sentinel/checks/generic.py`** — YAML-driven check dispatch module
  Handles all 23 experimental rules (MCPS-006 through MCPS-028) without requiring a dedicated
  Python module per rule. `_extract_values()` resolves dot-notation target field paths
  (`tool.description`, `tool.name`, `tool.annotations`, `tool.inputSchema`, `server.url`,
  `server.transport`, `server.config`, `server.env`) from a `ServerDefinition` at runtime.
  `_run_generic()` iterates the rule's declared targets, extracts matching values, and dispatches
  each pattern through `CheckRunner.run_pattern()`. Adding a new YAML-driven rule requires only an
  entry in `rules.yaml` and one line in `_GENERIC_RULE_IDS`. No new Python file is needed.

- **23 malicious test fixtures** (`tests/fixtures/MCPS-006-malicious.json` through
  `tests/fixtures/MCPS-028-malicious.json`)
  One fixture per experimental rule. Each is minimal — containing only the fields required to
  trigger the target rule — and was validated against all rule patterns before writing. The four
  `schema_analysis`-only fixtures (MCPS-010, MCPS-015, MCPS-018, MCPS-019) contain correct
  malicious schemas and will produce findings once the `base.py` compile fix above is deployed.
  All 23 fixtures produce zero findings against all other rules (verified by exhaustive
  cross-check).

- **Updated `tests/fixtures/benign-server.json`**
  Added `_comment` field documenting the file's role as the shared zero-finding baseline. Existing
  tool names, descriptions, and server configuration were unchanged and remain verified clean
  against all 28 rules.

- **`scripts/generate_rules.py`** — Batch LLM rule generation from OWASP source entries
  Generates `rules.yaml`-format draft rules for all entries in OWASP MCP Top 10, OWASP Agentic
  Top 10, and OWASP LLM Top 10 using a local or cloud LLM. Supports two backends: `lmstudio`
  (LMStudio OpenAI-compatible local API, no extra dependencies, tested with Qwen 3.6 27B) and
  `anthropic` (Anthropic API, requires `pip install -e ".[phase2]"` and `ANTHROPIC_API_KEY`).
  Built-in source entry registry contains all 30 OWASP entries with full descriptions so batch
  generation works offline. Outputs staged draft files to `mcp_sentinel/rules/staged/`; drafts
  carry `status: experimental` and must be reviewed before promotion.

- **`scripts/ingest_atlas.py`** — MITRE ATLAS STIX 2.1 bundle ingestion
  Downloads and caches the ATLAS STIX bundle from GitHub (`~/.cache/mcp-sentinel/atlas-stix.json`,
  7-day TTL). Parses the bundle into a queryable `ATLASBundle` index with full cross-reference
  resolution: techniques, tactics, mitigations, sub-techniques, and case studies are all indexed
  and resolved onto each `Technique` object. Relevance scoring (0-100) filters to LLM/agent/MCP-
  relevant techniques by default. Generates rule drafts using the same LMStudio/Anthropic backends
  as `generate_rules.py`, with ATLAS-specific prompt context including tactic phase, ATLAS
  mitigations, real-world case studies, and sub-technique names. CLI supports `--stats`, `--list`,
  `--technique`, `--tactic`, `--filter`, `--include-subtechniques`, `--no-cache`, and `--bundle`.

- **Updated `mcp_sentinel/rules/README.md`**
  Complete rewrite to cover all 28 rules. Added a Rule Inventory table and a Test Coverage
  section with one entry per rule documenting: fixture file name, the specific field and phrase
  that triggers detection, whether the fixture exists or must be created, a copy-ready JSON
  fixture suggestion for each experimental rule, and the pattern types involved.

### Changed

- **`mcp_sentinel/checks/__init__.py`** — `generic` module added to `_ensure_loaded()`
  The `_ensure_loaded()` function now imports `mcp_sentinel.checks.generic` alongside the five
  dedicated check modules, causing the `@register` calls in `generic.py` to fire at engine
  startup.

- **`mcp_sentinel/rules/rules.yaml`** — Three existing active rules enhanced with patterns and
  mappings extracted from the overlapping draft rule set:
  - `MCPS-002` Secret and Token Exposure: added SSN and credit card number regex patterns; added
    `owasp-agentic:ASI08` and `owasp-llm:LLM02` source mappings
  - `MCPS-003` Overly Permissive Parameter Schemas: added regex pattern detecting broad-access
    language in tool descriptions; added `owasp-mcp:MCP03` source mapping
  - `MCPS-009` Dangerous Tool Name Keywords: added pattern matching OS execution library
    references in tool names (`os.system`, `os.popen`, `subprocess`)

---

## [Unreleased] — 2026-05-16 (Security Hardening)

### Security

- **[CRITICAL] Fixed XSS via disabled Jinja2 autoescape in HTML reporter** (`mcp_sentinel/reporter.py`)
  The `HtmlReporter` previously constructed templates using `Template(HTML_TEMPLATE)`, which disables
  HTML autoescaping by default. Finding data including `f.match`, `f.tool_name`, `f.field`, `f.detail`,
  and `source_path` flowed directly from untrusted MCP server definitions into the rendered HTML without
  escaping. A crafted tool description containing `<script>` or other HTML payloads would execute in the
  browser when a stakeholder opened the report. Fixed by replacing `Template()` with
  `Environment(autoescape=True, loader=BaseLoader()).from_string()`, which escapes all `{{ }}`
  interpolations as HTML entities. Addresses Semgrep rule
  `python.jinja2.security.audit.autoescape-disabled` and CodeQL `py/xss`.

- **[CRITICAL] Fixed URL injection via unvalidated `entry_url` in HTML report href attributes** (`mcp_sentinel/reporter.py`)
  Source mapping URLs from `sources.yaml` were rendered as bare `href` values with no scheme validation.
  A `sources.yaml` entry with a `javascript:` or `data:` URI as its URL would execute arbitrary
  JavaScript in the browser when a user clicked a mapping tag in a generated report. Fixed with
  `_sanitize_url()`, which validates the parsed URL scheme against an explicit allowlist of
  `{https, http}`. URLs failing validation are replaced with `#`. `_FindingView` and `_MappingView`
  wrapper classes enforce sanitization at the Python/Jinja2 boundary so raw `SourceMapping` objects
  never reach the template context. All external links now include `rel="noopener noreferrer"`. A
  `Content-Security-Policy` meta tag (`default-src 'none'; style-src 'unsafe-inline'; script-src 'none'`)
  was added to the HTML template as a defence-in-depth layer.

- **[HIGH] Fixed ReDoS via YAML-loaded regex patterns executed without timeout** (`mcp_sentinel/checks/base.py`)
  `re.search(pattern.expression, value, flags)` was called at every pattern match. Because
  `pattern.expression` is loaded from `rules.yaml` and `--rules` accepts user-supplied rule files,
  patterns were effectively user-controlled. A crafted pattern with catastrophic backtracking (e.g.,
  `(a+)+b`) against attacker-controlled tool description text could cause the scan process to hang
  indefinitely. Fixed with two independent layers: (1) all regex patterns are compiled once at
  `CheckRunner.__init__()` via `_compile_pattern()`, which enforces a maximum pattern length of
  `_MAX_PATTERN_LEN = 1000` characters; (2) match execution is dispatched to a
  `ThreadPoolExecutor` worker via `_timed_search()`, applying a `_REGEX_TIMEOUT_SECS = 2.0` second
  deadline. A timed-out match is logged as WARNING and treated as a non-match. Addresses CodeQL
  `py/redos`.

- **[HIGH] Fixed arbitrary attribute access via `getattr(re, flag_name, 0)` in regex flag resolution** (`mcp_sentinel/checks/base.py`)
  Regex flags from rule YAML were resolved using `getattr(re, flag_name, 0)`. The default of `0`
  does not apply to all `re` module attributes: `getattr(re, 'purge', 0)` returns the `re.purge()`
  function object, not `0`, causing `flags |= <function>` to raise `TypeError` and silently crash
  the affected check. Fixed by replacing both `getattr(re, f, 0)` call sites with `_SAFE_RE_FLAGS`,
  an explicit `dict[str, re.RegexFlag]` mapping all valid flag names to their `re.RegexFlag` values.

- **[MEDIUM] Fixed thread-unsafe global mutable cache** (`mcp_sentinel/engine.py`)
  `_active_sources_cache` was read and overwritten with no synchronization. Fixed with a
  `threading.Lock` using a double-checked locking pattern.

- **[MEDIUM] Fixed missing file size limit allowing memory exhaustion via oversized schema input** (`mcp_sentinel/loaders/schema.py`)
  `path.read_text()` was called with no prior size check. Fixed by checking `path.stat().st_size`
  against `MAX_FILE_BYTES = 10 MB` before any read. Added `MAX_TOOLS = 500`.

### Changed

- `mcp_sentinel/reporter.py`: `datetime.utcnow()` replaced with `datetime.now(timezone.utc)`
- `mcp_sentinel/engine.py`: `print(..., file=sys.stderr)` replaced with `logger.warning(...)`
- `mcp_sentinel/engine.py`: Removed unused `import importlib.resources`
- `mcp_sentinel/models.py`: Added `SourceDefinition.from_dict()` classmethod
- `mcp_sentinel/loaders/schema.py`: `Path(path)` canonicalized via `.resolve()`

### Added

- `mcp_sentinel/reporter.py`: `_sanitize_url()`, `_FindingView`, `_MappingView`
- `mcp_sentinel/checks/base.py`: `_SAFE_RE_FLAGS`, `_build_re_flags()`, `_compile_pattern()`,
  `_timed_search()`, `_MAX_PATTERN_LEN`, `_REGEX_TIMEOUT_SECS`, `_regex_executor`
- `mcp_sentinel/engine.py`: `_cache_lock: threading.Lock`
- `mcp_sentinel/loaders/schema.py`: `MAX_FILE_BYTES`, `MAX_TOOLS`
- README files added to `mcp_sentinel/`, `mcp_sentinel/checks/`, `mcp_sentinel/rules/`,
  `tests/`, and `planning/`

---

## Earlier [Unreleased] Work — Initial Scaffold

### Added

- Initial project documentation: root `README.md`, `CONTRIBUTING.md`, `SECURITY.md`,
  `CODE_OF_CONDUCT.md`, `LICENSE` (MIT)
- Planning documents in `planning/`: `ARCHITECTURE.md`, `THREAT-MODEL.md`, `ROADMAP.md`
- Threat intelligence source registry (`mcp_sentinel/rules/sources.yaml`) with 5 active sources:
  OWASP MCP Top 10, OWASP Top 10 for Agentic Applications 2026, OWASP Top 10 for LLMs 2025,
  MITRE ATLAS, and NIST AI Risk Management Framework
- Initial rule set (`mcp_sentinel/rules/rules.yaml`) with 5 rules mapped to multiple frameworks:
  MCPS-001 (Tool Poisoning, CRITICAL), MCPS-002 (Secret Exposure, CRITICAL),
  MCPS-003 (Overly Permissive Parameters, HIGH), MCPS-004 (Insecure Transport, HIGH),
  MCPS-005 (Unverified Tool Provenance, HIGH)
- Detection engine (`mcp_sentinel/engine.py`), `@register` decorator pattern
  (`mcp_sentinel/checks/__init__.py`), five check modules (`tool_poisoning.py`, `secrets.py`,
  `parameters.py`, `transport.py`, `provenance.py`), `CheckRunner` base class with five pattern
  type handlers (`regex`, `length`, `unicode`, `value_check`, `schema_analysis`), per-pattern
  `severity_override` support
- Schema loader (`mcp_sentinel/loaders/schema.py`), Phase 3 stub (`mcp_sentinel/loaders/live.py`)
- Three output formatters: `TerminalReporter` (Rich), `JsonReporter`, `HtmlReporter`
- Typer CLI (`mcp_sentinel/cli.py`): `scan`, `rules list`, `rules validate`, `sources check`
- Core data models (`mcp_sentinel/models.py`): `ServerDefinition`, `ToolDefinition`,
  `PackageReference`, `Finding`, `SourceMapping`, `RiskScore`, `RuleDefinition`,
  `PatternDefinition`, `SourceDefinition`
- `RiskScore.from_findings()` with severity-weighted scoring capped at 100
- Test suite (`tests/test_checks.py`) with 25 assertions across 7 test classes
- Six test fixtures: `benign-server.json` and MCPS-001 through MCPS-005 malicious fixtures
- GitHub Actions workflow, `Makefile`, GitHub issue templates, `pyproject.toml`

---

## Version History

No releases yet. Active development toward v0.1.0.

See [`planning/ROADMAP.md`](planning/ROADMAP.md) for the Phase 1 milestone criteria that
constitute the v0.1.0 release.

---

## Release Format

```
## [0.1.0] - YYYY-MM-DD

### Added        New features and capabilities
### Changed      Changes to existing behavior
### Fixed        Bug fixes
### Deprecated   Features to be removed in a future release
### Removed      Features removed in this release
### Security     Security fixes (with CVE or advisory reference where applicable)
```
