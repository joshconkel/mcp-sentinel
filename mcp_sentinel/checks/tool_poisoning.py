"""
MCPS-001: Tool Poisoning via Description Field

MCP tool description fields are trusted as authoritative context by the LLM.
A malicious or compromised server may embed hidden instructions in these fields
to redirect agent behavior, override system prompts, or exfiltrate data.

See THREAT-MODEL.md for the full attack scenario.
"""

from __future__ import annotations

from mcp_sentinel.checks import register
from mcp_sentinel.checks.base import CheckRunner
from mcp_sentinel.models import Finding, RuleDefinition, ServerDefinition


@register("MCPS-001")
def run(server_def: ServerDefinition, rule: RuleDefinition) -> list[Finding]:
    """
    Scan all tool description fields for:
      - Instruction override / hidden behavior language (regex)
      - Invisible / zero-width Unicode characters
      - Suspiciously long descriptions (possible hidden payload)
    """
    from mcp_sentinel.engine import _build_active_sources  # avoid circular at module level

    active_sources = _build_active_sources()
    runner = CheckRunner(rule, active_sources)
    findings: list[Finding] = []

    for tool in server_def.tools:
        # Scan the description field against every pattern in the rule
        for pattern in rule.patterns:
            field_name = "tool.description"

            if pattern.type in {"length", "regex", "unicode"}:
                value_to_check = tool.description
            else:
                continue

            finding = runner.run_pattern(pattern, value_to_check, field_name, tool)
            if finding:
                findings.append(finding)

        # Also scan annotations blob as a string (hidden instructions can live there too)
        if tool.annotations:
            annotation_str = str(tool.annotations)
            for pattern in rule.patterns:
                if pattern.type != "regex":
                    continue
                finding = runner.run_pattern(pattern, annotation_str, "tool.annotations", tool)
                if finding:
                    findings.append(finding)

    return findings
