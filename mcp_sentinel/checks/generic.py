"""
generic.py: YAML-driven check module for mcp-sentinel.

Handles rules MCPS-006 through MCPS-020 (and any future rules) whose
detection logic can be fully expressed through the rules.yaml pattern
schema. Resolves target field paths from ServerDefinition and dispatches
each rule's patterns through CheckRunner.

No rule-specific code lives here. Adding a new rule requires only:
  1. An entry in rules.yaml with targets and detection patterns
  2. A line in _GENERIC_RULE_IDS below
  3. A malicious fixture file in tests/fixtures/

Supported target field paths
-----------------------------
  tool.description         All tool description strings
  tool.name                All tool name strings
  tool.annotations         All tool annotation dicts (as string for text patterns)
  tool.inputSchema         All tool input schemas (as dict for schema_analysis)
  server.url               Server URL string
  server.transport         Transport declaration string
  server.config            Server config dict (for value_check/missing_fields)
  server.env               All environment variable values
"""

from __future__ import annotations

from typing import Any

from mcp_sentinel.checks import register
from mcp_sentinel.checks.base import CheckRunner
from mcp_sentinel.models import Finding, RuleDefinition, ServerDefinition

# ---------------------------------------------------------------------------
# Rule IDs handled by this generic module.
# Add new YAML-driven rule IDs here as they are defined in rules.yaml.
# ---------------------------------------------------------------------------

_GENERIC_RULE_IDS: list[str] = [
    "MCPS-006",   # Hidden Instructions in Tool Annotations
    "MCPS-007",   # LLM Jailbreak Trigger Language
    "MCPS-008",   # Credentials Embedded in Server URL
    "MCPS-009",   # Dangerous Tool Name Keywords
    "MCPS-010",   # SSRF via Unrestricted URL Parameter
    "MCPS-011",   # Unfiltered External Content Pass-Through
    "MCPS-012",   # Internal Network Infrastructure Disclosure
    "MCPS-013",   # Unrestricted Filesystem Access Pattern
    "MCPS-014",   # Bulk or Unfiltered Data Return Pattern
    "MCPS-015",   # Insecure Webhook or Callback URL Parameter
    "MCPS-016",   # Capability Self-Grant in Tool Definition
    "MCPS-017",   # Tool Memory Write and Persistence Pattern
    "MCPS-018",   # Numeric Parameter Without Range Constraints
    "MCPS-019",   # Executable Code or Script Parameter
    "MCPS-020",   # Placeholder and Default Credential Values
]


# ---------------------------------------------------------------------------
# Field extractor
# ---------------------------------------------------------------------------

def _extract_values(
    server_def: ServerDefinition,
    field_path: str,
) -> list[tuple[str, Any, Any]]:
    """
    Resolve a target field path to a list of (field_path, value, tool_or_None).

    Returns multiple results when the path refers to a per-tool field
    (e.g. "tool.description" returns one entry per tool in the definition).
    Returns an empty list if the field has no value.

    Args:
        server_def:  Normalized server definition.
        field_path:  Dot-notation field path from the rule's targets block.

    Returns:
        List of (resolved_field_path, value, ToolDefinition_or_None) tuples.
    """
    results: list[tuple[str, Any, Any]] = []

    # ── Tool-level fields ────────────────────────────────────────────────────

    if field_path == "tool.description":
        for tool in server_def.tools:
            if tool.description:
                results.append((field_path, tool.description, tool))

    elif field_path == "tool.name":
        for tool in server_def.tools:
            if tool.name:
                results.append((field_path, tool.name, tool))

    elif field_path == "tool.annotations":
        for tool in server_def.tools:
            if tool.annotations:
                # Convert to string for text-based patterns;
                # dict form is also available if needed for future pattern types.
                results.append((field_path, str(tool.annotations), tool))

    elif field_path == "tool.inputSchema":
        for tool in server_def.tools:
            if tool.input_schema:
                results.append((field_path, tool.input_schema, tool))

    # ── Server-level fields ──────────────────────────────────────────────────

    elif field_path == "server.url":
        if server_def.server_url:
            results.append((field_path, server_def.server_url, None))

    elif field_path == "server.transport":
        if server_def.transport:
            results.append((field_path, server_def.transport, None))

    elif field_path == "server.config":
        if server_def.config:
            results.append((field_path, server_def.config, None))

    elif field_path == "server.env":
        # Scan each environment variable value independently so findings
        # can reference the specific variable key.
        for key, val in server_def.env.items():
            if val:
                results.append((f"server.env.{key}", val, None))

    elif field_path == "server.packages[]":
        # Used by MCPS-005 (provenance); included here for completeness if
        # future generic rules target the packages list.
        for pkg in server_def.packages:
            pkg_dict = {
                "name":      pkg.name,
                "version":   pkg.version or "",
                "integrity": pkg.integrity,
            }
            results.append((f"server.packages[{pkg.name}]", pkg_dict, None))

    # ── Per-tool parameter defaults (from input schema) ──────────────────────

    elif field_path == "tool.inputSchema.properties.*":
        # Expands to each parameter's default value for secret scanning.
        for tool in server_def.tools:
            props = tool.input_schema.get("properties", {}) or {}
            for prop_name, prop_def in props.items():
                if not isinstance(prop_def, dict):
                    continue
                if "default" in prop_def:
                    results.append((
                        f"tool.inputSchema.properties.{prop_name}.default",
                        str(prop_def["default"]),
                        tool,
                    ))
                if "description" in prop_def:
                    results.append((
                        f"tool.inputSchema.properties.{prop_name}.description",
                        str(prop_def["description"]),
                        tool,
                    ))

    return results


# ---------------------------------------------------------------------------
# Generic check function
# ---------------------------------------------------------------------------

def _run_generic(server_def: ServerDefinition, rule: RuleDefinition) -> list[Finding]:
    """
    YAML-driven check dispatcher.

    For each target field declared in the rule, extracts all matching values
    from server_def and runs every detection pattern against each value.
    Produces one Finding per (target_field, tool, pattern) combination that
    matches.
    """
    from mcp_sentinel.engine import _build_active_sources  # avoid circular at module level

    active_sources = _build_active_sources()
    runner = CheckRunner(rule, active_sources)
    findings: list[Finding] = []

    # Resolve target fields from the rule definition.
    # Fall back to tool.description if no targets are declared.
    targets = [t.get("field", "") for t in rule.targets if t.get("field")]
    if not targets:
        targets = ["tool.description"]

    seen: set[tuple[str, str | None]] = set()  # (field_path, tool_name) dedup key

    for target_field in targets:
        field_values = _extract_values(server_def, target_field)

        for field_path, value, tool in field_values:
            for pattern in rule.patterns:
                finding = runner.run_pattern(pattern, value, field_path, tool)
                if finding is None:
                    continue

                # Deduplicate: one finding per (field, tool) per rule run.
                # Multiple patterns can match the same field — keep the first
                # (highest-severity patterns are ordered first in rules.yaml).
                dedup_key = (field_path, tool.name if tool else None)
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)

                findings.append(finding)

    return findings


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------
# Register the generic function for all rule IDs in _GENERIC_RULE_IDS.
# The function uses rule.targets and rule.patterns (loaded from rules.yaml)
# to determine behavior, so no per-rule Python logic is needed.

for _rule_id in _GENERIC_RULE_IDS:
    register(_rule_id)(_run_generic)
