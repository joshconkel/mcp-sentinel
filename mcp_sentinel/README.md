# mcp_sentinel/

The Python package that implements `mcp-sentinel`. This document explains the internal structure for contributors who want to understand how the components connect before reading individual module docstrings.

For end-user documentation, see the [root README](../README.md).

---

## Package Layout

```
mcp_sentinel/
├── __init__.py       Package version (__version__ = "0.1.0") and author
├── cli.py            Typer CLI entry point: scan, rules list/validate, sources check
├── engine.py         Rule engine: loads YAML, dispatches checks, aggregates findings
├── models.py         All dataclasses and enums shared across the package
├── reporter.py       Output formatters: TerminalReporter, JsonReporter, HtmlReporter
├── checks/           One module per check rule + base runner
├── loaders/          Input normalization: static files and (Phase 3) live servers
└── rules/            Versioned YAML: rule definitions and threat source registry
```

---

## Data Flow

```
CLI (cli.py)
  │
  ├─ load schema ──► loaders/schema.py ──► ServerDefinition
  │
  └─ engine.scan(server_def)
        │
        ├─ load_sources(rules/sources.yaml) ──► dict[source_id, SourceDefinition]
        ├─ load_rules(rules/rules.yaml)     ──► list[RuleDefinition]
        │
        └─ for each Rule:
              get_check(rule.id) ──► checks/<module>.run(server_def, rule)
                                          │
                                          └─ CheckRunner (checks/base.py)
                                               │
                                               └─ list[Finding]
        │
        └─ RiskScore.from_findings(all_findings)
              │
              └─ reporter.report(score)
                    ├─ TerminalReporter  (human-readable)
                    ├─ JsonReporter      (CI/CD pipelines)
                    └─ HtmlReporter      (stakeholder reports)
```

---

## Key Modules

### models.py

The single source of truth for shared types. No external dependencies. Contains:

- `Severity` — CRITICAL / HIGH / MEDIUM / LOW / INFO, each carrying a `.score` weight and `.color` for Rich terminal output
- `ServerDefinition` — normalized representation of any MCP server definition, produced by the loader layer
- `ToolDefinition` — a single tool exposed by a server
- `PackageReference` — a declared dependency in the server definition
- `Finding` — one security issue produced by a check; carries rule ID, severity, field, match, source mappings, and remediation
- `RiskScore` — aggregated output of the engine; computes overall score (capped at 100) and per-severity/per-tool counts
- `RuleDefinition` and `PatternDefinition` — the in-memory representation of rules loaded from YAML

### engine.py

Orchestrates the full scan:

1. Loads `rules/sources.yaml` into a dict keyed by source ID
2. Loads `rules/rules.yaml` into a list of `RuleDefinition` objects
3. Calls `checks._ensure_loaded()` so all `@register` decorators fire
4. For each rule, calls `get_check(rule.id)` to get the registered check function
5. Runs the check and collects `Finding` objects
6. Returns a `RiskScore`

Rules with `status: deprecated` are skipped. Rules with no registered check function are silently skipped (expected during development when a rule is added to YAML before its check module is written).

The engine also exposes `check_source_staleness()` for the `sources check` CLI command.

### cli.py

Typer application with four commands:

- `scan` — the primary command; accepts `--schema`, `--report` (terminal/json/html), `--out`, `--fail-on`, `--remediation`, `--rules`, `--sources`
- `rules list` — tabular display of active rules with severity and source mappings
- `rules validate` — validates `rules.yaml` structure and verifies all source references resolve
- `sources` — checks `sources.yaml` for entries whose `last_checked` date exceeds the staleness threshold

Exit codes: `0` = clean or no findings above threshold, `1` = findings at or above `--fail-on` severity, `2` = input error (file not found, bad argument).

### reporter.py

Three formatters all inheriting from `BaseFormatter`:

- `TerminalReporter` — Rich-formatted output with severity colors, a findings list, and a summary table with a bar chart. Designed to be readable in a CI log in under 30 seconds.
- `JsonReporter` — Structured JSON output for pipeline consumption. Includes metadata block (tool version, source path, timestamp), score block, and full findings array.
- `HtmlReporter` — Jinja2-rendered dark-theme HTML report with per-finding severity badges, source mapping links, and remediation blocks. Template is embedded as a string (no external template file required).

---

## Adding a New Check

See [checks/README.md](checks/README.md) for the full process.

## Updating Rules and Sources

See [rules/README.md](rules/README.md) for the YAML schema reference.

## Running Tests

See [../tests/README.md](../tests/README.md).
