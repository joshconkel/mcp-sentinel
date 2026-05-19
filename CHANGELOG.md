# Changelog

All notable changes to mcp-sentinel will be documented here.

This project follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

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
  the affected check. The pattern also provided no restriction on which module attributes could be
  accessed. Fixed by replacing both `getattr(re, f, 0)` call sites with `_SAFE_RE_FLAGS`, an
  explicit `dict[str, re.RegexFlag]` mapping all valid flag names (full and abbreviated) to their
  `re.RegexFlag` values. Unrecognised names are logged as warnings and skipped.

- **[MEDIUM] Fixed thread-unsafe global mutable cache** (`mcp_sentinel/engine.py`)
  `_active_sources_cache` was read in `_build_active_sources()` and overwritten in `scan()` with no
  synchronization, creating a race condition under concurrent access. Fixed with a `threading.Lock`
  using a double-checked locking pattern around all reads and writes.

- **[MEDIUM] Fixed missing file size limit allowing memory exhaustion via oversized schema input** (`mcp_sentinel/loaders/schema.py`)
  `path.read_text()` was called with no prior size check. A crafted multi-GB schema file would
  exhaust available memory before parsing began. Fixed by checking `path.stat().st_size` against
  `MAX_FILE_BYTES = 10 MB` before any read. Files exceeding the limit raise `LoadError` immediately.
  Added `MAX_TOOLS = 500` to bound scans against definitions with an unreasonable number of tools.

### Changed

- **`mcp_sentinel/reporter.py`**: Replaced both `datetime.utcnow()` call sites with
  `datetime.now(timezone.utc)`. `utcnow()` is deprecated in Python 3.12+ and produces a naive
  (timezone-unaware) datetime. The replacement produces a timezone-aware ISO 8601 timestamp.

- **`mcp_sentinel/engine.py`**: Replaced `print(f"[WARNING] ...", file=sys.stderr)` in the
  per-rule exception handler with `logger.warning(...)` via `logging.getLogger(__name__)`. Callers
  can now control verbosity with standard log configuration. Removed the `import sys` statement
  that was inside the exception handler loop.

- **`mcp_sentinel/engine.py`**: Removed unused `import importlib.resources` from module-level
  imports. The import was never referenced and produced a dead-import finding in static analysis.

- **`mcp_sentinel/models.py`**: Added `SourceDefinition.from_dict()` classmethod so the class
  is actively constructible from a raw `sources.yaml` entry dict. Removed the corresponding unused
  import of `SourceDefinition` from `engine.py`.

- **`mcp_sentinel/loaders/schema.py`**: `Path(path)` is now called as `Path(path).resolve()` to
  canonicalize the input path before existence and size checks. Error messages and
  `ServerDefinition.source_path` now reflect the actual filesystem path.

### Added

- **`mcp_sentinel/reporter.py`**: `_sanitize_url()` — validates URL scheme against `{https, http}`
  allowlist; used by both HTML and JSON reporters for consistency.

- **`mcp_sentinel/reporter.py`**: `_FindingView` and `_MappingView` — wrapper classes that present
  `Finding` and `SourceMapping` objects to the Jinja2 context with pre-sanitized `safe_url`
  attributes, creating a typed security boundary between the data model and the rendering layer.

- **`mcp_sentinel/checks/base.py`**: `_SAFE_RE_FLAGS` dict, `_build_re_flags()`, `_compile_pattern()`,
  and `_timed_search()` — centralized, safe alternatives to the previous inline `getattr` and
  `re.search` call sites.

- **`mcp_sentinel/checks/base.py`**: `_MAX_PATTERN_LEN = 1000` and `_REGEX_TIMEOUT_SECS = 2.0`
  module-level constants for centralized tuning of ReDoS protections.

- **`mcp_sentinel/checks/base.py`**: Module-level `_regex_executor` (`ThreadPoolExecutor`,
  `max_workers=1`) for timed regex execution. A module-level executor avoids per-call pool
  creation overhead across many pattern evaluations in a single scan.

- **`mcp_sentinel/engine.py`**: `_cache_lock: threading.Lock` protecting all access to
  `_active_sources_cache`.

- **`mcp_sentinel/loaders/schema.py`**: `MAX_FILE_BYTES` and `MAX_TOOLS` module-level constants
  for centralized tuning of input safety limits, both documented in the module docstring.

- **README files**: Added `README.md` to `mcp_sentinel/`, `mcp_sentinel/checks/`,
  `mcp_sentinel/rules/`, `tests/`, and `planning/` documenting internal architecture, check
  development workflow, YAML schema reference, test suite layout, and planning document index.

---

## Earlier [Unreleased] Work

### Added (initial scaffold)

- Initial project documentation: root `README.md`, `CONTRIBUTING.md`, `SECURITY.md`,
  `CODE_OF_CONDUCT.md`, `LICENSE` (MIT)
- Planning documents in `planning/`: `ARCHITECTURE.md`, `THREAT-MODEL.md`, `ROADMAP.md`
- Threat intelligence source registry (`mcp_sentinel/rules/sources.yaml`) with 5 active sources:
  OWASP MCP Top 10, OWASP Top 10 for Agentic Applications 2026, OWASP Top 10 for LLMs 2025,
  MITRE ATLAS, and NIST AI Risk Management Framework
- Initial rule set (`mcp_sentinel/rules/rules.yaml`) with 5 rules mapped to multiple frameworks:
  MCPS-001 (Tool Poisoning, CRITICAL, static), MCPS-002 (Secret Exposure, CRITICAL, static),
  MCPS-003 (Overly Permissive Parameters, HIGH, static), MCPS-004 (Insecure Transport, HIGH, static),
  MCPS-005 (Unverified Tool Provenance, HIGH, static)
- Multi-source rule mapping: each rule maps simultaneously to all registered sources with per-entry
  IDs, names, URLs, and optional notes; adding a new source requires one YAML entry only
- Detection engine (`mcp_sentinel/engine.py`): loads rules and sources from YAML, dispatches to
  registered check functions, aggregates findings into a `RiskScore`
- `@register` decorator pattern in `mcp_sentinel/checks/__init__.py` for decoupled check registration;
  adding a new check requires only the decorated function and one import line
- Five check modules: `tool_poisoning.py`, `secrets.py`, `parameters.py`, `transport.py`,
  `provenance.py`, each implementing `run(server_def, rule) -> list[Finding]`
- `CheckRunner` base class in `mcp_sentinel/checks/base.py` with five pattern type handlers:
  `regex`, `length`, `unicode`, `value_check`, `schema_analysis`
- Per-pattern `severity_override` support allowing a single rule to emit findings at different
  severity levels depending on match type (e.g., MCPS-001 reports long descriptions as MEDIUM
  but instruction-override regex matches as CRITICAL)
- Schema loader (`mcp_sentinel/loaders/schema.py`): normalizes JSON and YAML server definitions
  into `ServerDefinition`; accepts both `inputSchema` and `input_schema` field names for
  compatibility
- Phase 3 stub (`mcp_sentinel/loaders/live.py`): defines the `load(url)` interface for future
  live server probing without blocking Phase 1 progress
- Three output formatters in `mcp_sentinel/reporter.py`: `TerminalReporter` (Rich, severity-colored
  terminal output), `JsonReporter` (CI/CD-friendly with structured output), `HtmlReporter`
  (dark-theme stakeholder report with per-finding remediation)
- Typer CLI (`mcp_sentinel/cli.py`) with four commands: `scan`, `rules list`, `rules validate`,
  `sources check`; `--fail-on` severity threshold controls CI exit code; `--report` selects
  output format; `--out` writes to file
- Core data models (`mcp_sentinel/models.py`): `ServerDefinition`, `ToolDefinition`,
  `PackageReference`, `Finding`, `SourceMapping`, `RiskScore`, `RuleDefinition`,
  `PatternDefinition`, `SourceDefinition`
- `RiskScore.from_findings()` with severity-weighted scoring (CRITICAL=25, HIGH=10, MEDIUM=4,
  LOW=1) capped at 100 and labeled CLEAN / LOW / MEDIUM / HIGH / CRITICAL
- Test suite (`tests/test_checks.py`) with 25 assertions across 7 test classes covering each
  check module, the schema loader, and engine integration
- Six test fixtures: `benign-server.json` (zero-finding baseline) and one malicious fixture per
  rule (MCPS-001 through MCPS-005), each minimal and scoped to the target rule
- GitHub Actions workflow (`.github/workflows/mcp-scan.yml`): matrix test across Python 3.10,
  3.11, and 3.12; ruff lint; rules validation; demo scan with JSON artifact upload
- `Makefile` with targets covering install, test, lint, type-check, rules management, demo scans,
  and clean; `make help` shows all targets
- GitHub issue templates: `bug_report.yml`, `false_positive.yml` (security-tool-specific),
  `new_rule.yml`; pull request template with security-focused review checklist
- `pyproject.toml` with `[dev]` extras (pytest, ruff, mypy) and `[phase2]` extras (anthropic SDK);
  ruff and mypy configuration included

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
