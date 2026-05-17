"""
MCPS-003: Overly Permissive Parameter Schemas

MCP tools that accept unrestricted string parameters for shell commands,
file paths, SQL queries, or URLs create a direct channel from agent-controlled
input to privileged system operations.

Checks:
  - String parameters with dangerous semantic names lacking enum/pattern/maxLength
  - Input schemas missing additionalProperties: false
"""

from __future__ import annotations

import re

from mcp_sentinel.checks import register
from mcp_sentinel.checks.base import CheckRunner
from mcp_sentinel.models import Finding, RuleDefinition, ServerDefinition

# Names that suggest the parameter accepts privileged or dangerous input
DANGEROUS_NAMES = re.compile(
    r"(command|cmd|shell|exec|query|sql|path|file|url|endpoint|script|eval|code|payload|input)",
    re.IGNORECASE,
)

# Constraints that, if any are present, indicate the parameter is bounded
BOUNDING_CONSTRAINTS = {"enum", "pattern", "maxLength", "minLength", "const", "format"}


@register("MCPS-003")
def run(server_def: ServerDefinition, rule: RuleDefinition) -> list[Finding]:
    """
    Evaluate every tool's JSON Schema for permissive parameter definitions.
    """
    from mcp_sentinel.engine import _build_active_sources

    active_sources = _build_active_sources()
    runner = CheckRunner(rule, active_sources)
    findings: list[Finding] = []

    schema_patterns = [p for p in rule.patterns if p.type == "schema_analysis"]

    for tool in server_def.tools:
        schema = tool.input_schema
        if not schema or not isinstance(schema, dict):
            continue

        for pattern in schema_patterns:
            finding = runner.run_pattern(pattern, schema, "tool.inputSchema", tool)
            if finding:
                findings.append(finding)

        # Additional Python-level check: dangerous param names with no constraints
        # (more nuanced than a single YAML pattern can express cleanly)
        properties = schema.get("properties", {}) or {}
        for prop_name, prop_def in properties.items():
            if not isinstance(prop_def, dict):
                continue
            if prop_def.get("type") != "string":
                continue
            if not DANGEROUS_NAMES.search(prop_name):
                continue
            has_constraint = bool(BOUNDING_CONSTRAINTS & set(prop_def.keys()))
            if not has_constraint:
                findings.append(Finding(
                    rule_id=rule.id,
                    rule_name=rule.name,
                    severity=rule.severity,
                    field=f"tool.inputSchema.properties.{prop_name}",
                    tool_name=tool.name,
                    match=prop_name,
                    detail=(
                        f"String parameter '{prop_name}' has a dangerous semantic name "
                        f"and no constraining keywords (enum, pattern, maxLength, etc.)"
                    ),
                    source_mappings=runner._resolve_mappings(),
                    remediation=rule.remediation,
                    experimental=(rule.status.value == "experimental"),
                ))

    return findings
