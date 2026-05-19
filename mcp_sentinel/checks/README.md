# mcp_sentinel/checks/

The check layer: one Python module per security rule, plus the shared base runner.

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

The engine calls `get_check(rule.id)` to look up the registered function. If no function is registered for a rule ID, the rule is skipped silently. This means a rule can be defined in `rules.yaml` before its check module is written, which is the expected workflow when adding new rules.

`_ensure_loaded()` is called by the engine before scanning begins. It imports all check modules so their `@register` decorators fire. Adding a new check module requires adding it to the import list in `_ensure_loaded()`.

---

## Module Map

| Module | Rule ID | What It Detects |
|---|---|---|
| `base.py` | (shared) | CheckRunner and all pattern type handlers |
| `tool_poisoning.py` | MCPS-001 | Hidden instructions in tool description fields |
| `secrets.py` | MCPS-002 | Credentials and tokens embedded in tool definitions |
| `parameters.py` | MCPS-003 | Unrestricted string parameters on dangerous tool inputs |
| `transport.py` | MCPS-004 | Plaintext HTTP, insecure transport, missing WebSocket origins |
| `provenance.py` | MCPS-005 | Unpinned package versions and missing integrity hashes |

---

## base.py: The CheckRunner

All check modules instantiate `CheckRunner(rule, active_sources)` and call `runner.run_pattern(pattern, value, field, tool)`. The runner dispatches to the appropriate handler based on `pattern.type` and builds the `Finding` object including resolved source mappings.

Supported pattern types:

| Type | What It Does |
|---|---|
| `regex` | Compiled regex match against a string value. Supports `IGNORECASE`, `MULTILINE`, `DOTALL` flags. |
| `length` | Flags strings exceeding `threshold_chars`. Used to detect suspiciously long descriptions. |
| `unicode` | Scans for invisible/zero-width codepoints (U+200B, U+200C, U+200D, U+FEFF, U+2060, etc.). |
| `value_check` | Structured condition evaluation: `value_in`, `missing_fields`, `matches_unpinned`. |
| `schema_analysis` | JSON Schema structure checks: dangerous property names, missing constraints, `additionalProperties` policy. |

Each pattern may carry an optional `severity_override` that replaces the rule-level severity for that specific match. This allows a single rule to produce findings at different severities depending on what was matched (for example, MCPS-001 reports a 600-character description as MEDIUM but an instruction-override regex match as CRITICAL).

---

## Adding a New Check

### Step 1: Define the rule in rules.yaml

Add an entry to `mcp_sentinel/rules/rules.yaml` following the schema in [rules/README.md](../rules/README.md). Start with `status: experimental`. At minimum, include a rule ID, name, severity, at least one detection pattern, and at least one active source mapping.

### Step 2: Create the check module

Create `mcp_sentinel/checks/<your_module>.py`. The module must:

1. Import `register` from `mcp_sentinel.checks`
2. Decorate a `run` function with `@register("MCPS-NNN")`
3. The `run` function signature: `(server_def: ServerDefinition, rule: RuleDefinition) -> list[Finding]`

Minimal example:

```python
from __future__ import annotations

from mcp_sentinel.checks import register
from mcp_sentinel.checks.base import CheckRunner
from mcp_sentinel.models import Finding, RuleDefinition, ServerDefinition


@register("MCPS-006")
def run(server_def: ServerDefinition, rule: RuleDefinition) -> list[Finding]:
    from mcp_sentinel.engine import _build_active_sources

    active_sources = _build_active_sources()
    runner = CheckRunner(rule, active_sources)
    findings: list[Finding] = []

    for tool in server_def.tools:
        for pattern in rule.patterns:
            finding = runner.run_pattern(
                pattern,
                tool.description,   # the value to check
                "tool.description", # the field name for the finding
                tool,               # the ToolDefinition (for finding.tool_name)
            )
            if finding:
                findings.append(finding)

    return findings
```

### Step 3: Register the module

Add your module to the import list in `_ensure_loaded()` in `checks/__init__.py`:

```python
def _ensure_loaded() -> None:
    if _REGISTRY:
        return
    from mcp_sentinel.checks import (
        tool_poisoning,
        secrets,
        parameters,
        transport,
        provenance,
        your_module,   # add here
    )
```

### Step 4: Add test fixtures

Create two fixture files in `tests/fixtures/`:

- `MCPS-006-malicious.json` — a minimal MCP server definition that triggers the new rule
- If the benign fixture (`benign-server.json`) already covers the absence case, no second fixture is needed; otherwise create a targeted benign variant

### Step 5: Add tests

Add a test class to `tests/test_checks.py` following the pattern of existing classes. At minimum:

- One test confirming the malicious fixture produces a finding
- One test confirming the benign fixture produces no finding
- One test verifying the finding has source mappings

### Step 6: Promote to active

Once tests pass and the detection rate on known-bad fixtures is acceptable with no false positives on the benign fixture, change `status: experimental` to `status: active` in `rules.yaml`.

---

## Python-Level Detection vs. YAML Patterns

Check modules can use either YAML-driven patterns (via `CheckRunner.run_pattern`) or custom Python logic (direct inspection of `server_def` fields). Both approaches are valid:

**YAML-driven** is preferred when the detection can be expressed as regex, length, or schema structure checks. It keeps the rule definition and the detection logic co-located and makes the rule auditable without reading Python.

**Python-level** is appropriate when the detection requires conditional logic, cross-field comparisons, or nuance that pattern matching cannot express cleanly. `parameters.py` (MCPS-003) uses both: YAML schema patterns for the general case and a Python loop for the specific case of dangerous parameter names with no constraints.

Both approaches produce the same `Finding` objects and are transparent to the engine and reporter.
