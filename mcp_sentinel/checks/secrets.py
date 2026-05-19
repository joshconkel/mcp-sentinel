"""
MCPS-002: Secret and Token Exposure in Tool Definitions

Credentials, API keys, and connection strings embedded in MCP server
definitions expose sensitive environments to unauthorized access and may
be reproduced by the LLM in its outputs or logs.

Scans: tool descriptions, parameter defaults, parameter descriptions,
       server env block, and server config block.
"""

from __future__ import annotations

from mcp_sentinel.checks import register
from mcp_sentinel.checks.base import CheckRunner
from mcp_sentinel.models import Finding, RuleDefinition, ServerDefinition


@register("MCPS-002")
def run(server_def: ServerDefinition, rule: RuleDefinition) -> list[Finding]:
    """
    Scan all string-valued fields in the server definition for secret patterns.
    Covers tool descriptions, parameter defaults, env vars, and server config.
    """
    from mcp_sentinel.engine import _build_active_sources

    active_sources = _build_active_sources()
    runner = CheckRunner(rule, active_sources)
    findings: list[Finding] = []

    # Build a flat list of (field_path, string_value, tool_or_None) to scan
    targets: list[tuple[str, str, object]] = []

    # Tool-level fields
    for tool in server_def.tools:
        targets.append(("tool.description", tool.description, tool))

        props = tool.input_schema.get("properties", {}) or {}
        for prop_name, prop_def in props.items():
            if not isinstance(prop_def, dict):
                continue
            # Parameter default values
            if "default" in prop_def:
                targets.append(
                    (f"tool.inputSchema.properties.{prop_name}.default",
                     str(prop_def["default"]), tool)
                )
            # Parameter descriptions
            if "description" in prop_def:
                targets.append(
                    (f"tool.inputSchema.properties.{prop_name}.description",
                     str(prop_def["description"]), tool)
                )

    # Server-level env block
    for env_key, env_val in server_def.env.items():
        targets.append((f"server.env.{env_key}", env_val, None))

    # Server config blob (anything not already normalized)
    for cfg_key, cfg_val in server_def.config.items():
        if isinstance(cfg_val, str):
            targets.append((f"server.config.{cfg_key}", cfg_val, None))

    # Run regex patterns against every collected target
    regex_patterns = [p for p in rule.patterns if p.type == "regex"]

    for field_path, value, tool in targets:
        for pattern in regex_patterns:
            finding = runner.run_pattern(pattern, value, field_path, tool)  # type: ignore[arg-type]
            if finding:
                findings.append(finding)
                break  # one finding per field is enough; avoid pattern-flood

    return findings
