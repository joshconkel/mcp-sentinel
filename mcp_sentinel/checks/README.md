# mcp_sentinel/checks/

The check layer: one Python module per dedicated check, a shared base runner, and a generic engine that drives all YAML-defined rules.

---

## How It Works

The check system uses a decorator-based registry. Each module registers a function under its rule ID at import time:

```python
# checks/tool_poisoning.py
from mcp_sentinel.checks import register

@register("MCPS-001")
def run(server_def: ServerDefinition, rule: RuleDefinition) -> list[Finding]:
    ...
```

The engine calls `get_check(rule.id)` to look up the registered function. If no dedicated function is registered for a rule ID, the engine falls through to the generic runner, which drives the rule from its `rules.yaml` patterns with no Python code required.

`_ensure_loaded()` is called by the engine before scanning begins. It imports all check modules so their `@register` decorators fire.

---

## Module Map

| Module | Rule(s) | What It Detects |
|---|---|---|
| `base.py` | (shared) | `CheckRunner` — pattern dispatch, finding construction, source mapping resolution |
| `generic.py` | MCPS-006 – MCPS-150 | YAML-driven generic engine for all experimental rules |
| `tool_poisoning.py` | MCPS-001 | Hidden override instructions in tool description fields |
| `secrets.py` | MCPS-002 | Credentials and API tokens embedded in tool definitions or env vars |
| `parameters.py` | MCPS-003 | Unrestricted string parameters on dangerous tool inputs |
| `transport.py` | MCPS-004 | Plaintext HTTP, insecure transport, missing WebSocket origins allowlist |
| `provenance.py` | MCPS-005 | Unpinned package versions and missing integrity hashes |

---

## base.py: The CheckRunner

All check modules (dedicated and generic) instantiate `CheckRunner(rule, active_sources)` and call `runner.run_pattern(pattern, value, field_path, tool)`. The runner dispatches to the appropriate handler based on `pattern.type` and constructs the `Finding` including resolved source mappings.

**Important:** `run_pattern` skips `regex` pattern checks when `value` is a `dict`. Regex is only meaningful on string values; running `re.search(pattern, str(dict))` against a JSON Schema object produces false positives from the Python dict representation. Structured dict values are handled by `value_check` (for key presence) and `schema_analysis` (for schema structure).

### Pattern Types

| Type | Handler | What It Does |
|---|---|---|
| `regex` | `_check_regex` | Compiled regex match against a string value. Supports `IGNORECASE`, `MULTILINE`, `DOTALL` flags. Skipped on dict values. |
| `length` | `_check_length` | Flags strings exceeding `threshold_chars`. Used to detect suspiciously long tool descriptions. |
| `unicode` | `_check_unicode` | Scans for invisible/zero-width codepoints (U+200B, U+200C, U+200D, U+FEFF, U+2060, etc.). |
| `value_check` | `_check_value` | Structured condition evaluation against a field value. Conditions: `missing_fields` (flat key lookup on dict), `matches_unpinned` (version string pattern match), `value_in` (string membership test). |
| `schema_analysis` | `_check_schema` | JSON Schema structure checks. Requires both `field_name_matches` and `missing_constraints` to be present — either alone is a no-op. |

Each pattern may carry an optional `severity_override` that replaces the rule-level severity for that specific match.

---

## generic.py: The Generic Rule Engine

`generic.py` drives all rules from MCPS-006 onward using patterns defined in `rules.yaml`. No Python code is required to add a rule in this range.

### Field Extraction

The generic engine resolves each rule's `targets[].field` path to actual values from the `ServerDefinition`, then runs the rule's detection patterns against each value. Supported field paths:

| Field Path | Value Type | What It Extracts |
|---|---|---|
| `tool.description` | `str` | Description string for each tool |
| `tool.name` | `str` | Name string for each tool |
| `tool.annotations` | `str` | Stringified annotations dict for each tool |
| `tool.inputSchema` | `dict` | Full input schema dict + each property's `"default"` value as a string (field path: `tool.inputSchema.properties.{name}.default`) |
| `tool.inputSchema.properties.*` | `str` | Each property's `"default"` and `"description"` values |
| `server.url` | `str` | Server URL string |
| `server.transport` | `str` | Transport type string |
| `server.config` | `dict` | Server config dict (string values checked individually) |
| `server.env` or `server.env.*` | `str` | Each environment variable value independently |
| `server.packages[]` | `dict` + `str` | Full package dict (for `missing_fields` checks) **and** the version string (for `matches_unpinned` checks) |

The `server.env.*` path (with wildcard suffix) is accepted as an alias for `server.env` — both route to the same env-value extraction loop. This allows rules to use the natural `server.env.*` notation without requiring an exact match on the field_path string.

### `missing_fields` Checks

The `value_check` condition `missing_fields: [key1, key2]` performs a **flat key lookup** on a dict — it checks whether the literal key string is present in the dict, not nested access. A key like `"annotations.destructiveHint"` checks for that exact string as a key, not for `dict["annotations"]["destructiveHint"]`.

This is intentional: the benign server fixture uses these literal flat keys in `tool.inputSchema` as security annotation markers:

```json
"inputSchema": {
  "type": "object",
  "properties": { ... },
  "annotations.destructiveHint": false,
  "auth_required": true,
  "guardrails.enabled": true
}
```

---

## Adding a New Dedicated Check (MCPS-001 style)

Use a dedicated check module when the detection requires conditional logic, cross-field comparisons, or nuance that YAML patterns cannot express.

### Step 1: Define the rule in rules.yaml

Add an entry to `mcp_sentinel/rules/rules.yaml`. Start with `status: experimental`.

### Step 2: Create the check module

```python
# mcp_sentinel/checks/my_check.py
from __future__ import annotations

from mcp_sentinel.checks import register
from mcp_sentinel.checks.base import CheckRunner
from mcp_sentinel.models import Finding, RuleDefinition, ServerDefinition


@register("MCPS-NNN")
def run(server_def: ServerDefinition, rule: RuleDefinition) -> list[Finding]:
    from mcp_sentinel.engine import _build_active_sources

    active_sources = _build_active_sources()
    runner = CheckRunner(rule, active_sources)
    findings: list[Finding] = []

    for tool in server_def.tools:
        for pattern in rule.patterns:
            finding = runner.run_pattern(
                pattern,
                tool.description,    # value to check
                "tool.description",  # field path for the finding
                tool,                # ToolDefinition (for finding.tool_name)
            )
            if finding:
                findings.append(finding)

    return findings
```

### Step 3: Register the module

Add your module to the import list in `_ensure_loaded()` in `checks/__init__.py`.

### Step 4: Add test fixtures and tests

Create `tests/fixtures/MCPS-NNN-malicious.json` and add a `TestMCPSNNN` class to `test_checks.py`. See [tests/README.md](../../tests/README.md) for the standard pattern.

---

## Adding a New YAML-Driven Rule (MCPS-006+ style)

For rules that can be expressed as regex, `missing_fields`, `matches_unpinned`, or `schema_analysis` patterns, no Python module is needed.

1. Add the rule to `rules.yaml` with a `targets` block and `detection.patterns`
2. Create `tests/fixtures/MCPS-NNN-malicious.json`
3. Verify the benign fixture does not trigger the rule
4. Add a `TestMCPSNNN` class to `test_checks.py`

The generic engine picks up the rule automatically. No changes to any Python file are required.

---

## Python-Level vs. YAML-Driven Detection

**YAML-driven** is preferred when the detection can be expressed as regex, length, or schema structure checks. It keeps detection logic co-located with the rule definition and makes rules auditable without reading Python.

**Python-level** is appropriate when detection requires conditional logic, cross-field comparisons, or nuance that pattern matching cannot express. Both approaches produce identical `Finding` objects and are transparent to the engine and reporter.
