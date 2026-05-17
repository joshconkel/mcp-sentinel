"""
MCPS-004: Insecure Transport Configuration

MCP servers communicating over plaintext HTTP expose all tool invocations,
parameters, and results to network interception. WebSocket servers without
origin validation are vulnerable to cross-site WebSocket hijacking.
"""

from __future__ import annotations

from mcp_sentinel.checks import register
from mcp_sentinel.checks.base import CheckRunner
from mcp_sentinel.models import Finding, RuleDefinition, ServerDefinition, Severity


@register("MCPS-004")
def run(server_def: ServerDefinition, rule: RuleDefinition) -> list[Finding]:
    """
    Check server URL scheme, transport declaration, and WebSocket origin policy.
    """
    from mcp_sentinel.engine import _build_active_sources

    active_sources = _build_active_sources()
    runner = CheckRunner(rule, active_sources)
    findings: list[Finding] = []

    # --- Check 1: plaintext HTTP URL ---
    url = server_def.server_url or ""
    if url.lower().startswith("http://") or url.lower().startswith("ws://"):
        findings.append(Finding(
            rule_id=rule.id,
            rule_name=rule.name,
            severity=rule.severity,
            field="server.url",
            tool_name=None,
            match=url,
            detail=f"Plaintext transport detected in server URL: {url}",
            source_mappings=runner._resolve_mappings(),
            remediation=rule.remediation,
            experimental=(rule.status.value == "experimental"),
        ))

    # --- Check 2: transport field explicitly set to insecure value ---
    transport = server_def.transport or ""
    if transport.lower() == "http":
        findings.append(Finding(
            rule_id=rule.id,
            rule_name=rule.name,
            severity=Severity.MEDIUM,        # Lower than URL check; may be local-only
            field="server.transport",
            tool_name=None,
            match=transport,
            detail="Transport explicitly declared as 'http' without TLS.",
            source_mappings=runner._resolve_mappings(),
            remediation=rule.remediation,
            experimental=(rule.status.value == "experimental"),
        ))

    # --- Check 3: WebSocket server missing origins allowlist ---
    # Flag only when transport suggests WebSocket is in use
    is_websocket = (
        transport.lower() in {"websocket", "ws", "wss"}
        or (url.lower().startswith("ws://") or url.lower().startswith("wss://"))
    )
    if is_websocket:
        origins = server_def.websocket_origins
        if origins is None:
            findings.append(Finding(
                rule_id=rule.id,
                rule_name=rule.name,
                severity=rule.severity,
                field="server.websocket.origins",
                tool_name=None,
                match=None,
                detail="WebSocket server has no origins allowlist configured. "
                       "Vulnerable to cross-site WebSocket hijacking.",
                source_mappings=runner._resolve_mappings(),
                remediation=rule.remediation,
                experimental=(rule.status.value == "experimental"),
            ))
        elif "*" in origins or "" in origins:
            findings.append(Finding(
                rule_id=rule.id,
                rule_name=rule.name,
                severity=rule.severity,
                field="server.websocket.origins",
                tool_name=None,
                match=str(origins),
                detail="WebSocket origins allowlist contains a wildcard or empty entry.",
                source_mappings=runner._resolve_mappings(),
                remediation=rule.remediation,
                experimental=(rule.status.value == "experimental"),
            ))

    return findings
