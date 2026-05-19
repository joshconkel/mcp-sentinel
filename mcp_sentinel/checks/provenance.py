"""
MCPS-005: Agentic Supply Chain: Unverified Tool Provenance

MCP ecosystems compose tools at runtime from external registries and packages.
Without version pinning and integrity verification, a compromised dependency
can silently alter agent behavior.
"""

from __future__ import annotations

import re

from mcp_sentinel.checks import register
from mcp_sentinel.checks.base import CheckRunner
from mcp_sentinel.models import Finding, RuleDefinition, ServerDefinition, Severity

# Matches version strings that are not pinned to an exact version
UNPINNED = re.compile(
    r"^(\*|latest|x|next|canary|\^[\d]|~[\d]|>=[\d]|>[\d]|[\d]+\.[xX\*])",
    re.IGNORECASE,
)


@register("MCPS-005")
def run(server_def: ServerDefinition, rule: RuleDefinition) -> list[Finding]:
    """
    Check all declared packages for unpinned versions and missing integrity hashes.
    """
    from mcp_sentinel.engine import _build_active_sources

    active_sources = _build_active_sources()
    runner = CheckRunner(rule, active_sources)
    findings: list[Finding] = []

    for pkg in server_def.packages:
        # --- Check 1: unpinned or missing version ---
        version = pkg.version or ""
        if not version or UNPINNED.match(version):
            findings.append(Finding(
                rule_id=rule.id,
                rule_name=rule.name,
                severity=rule.severity,
                field="server.packages[].version",
                tool_name=None,
                match=f"{pkg.name}@{version or '(no version)'}",
                detail=(
                    f"Package '{pkg.name}' has an unpinned version specifier: "
                    f"'{version or 'missing'}'. A compromised update could silently "
                    f"alter tool behavior."
                ),
                source_mappings=runner._resolve_mappings(),
                remediation=rule.remediation,
                experimental=(rule.status.value == "experimental"),
            ))

        # --- Check 2: missing integrity hash ---
        if not pkg.integrity:
            findings.append(Finding(
                rule_id=rule.id,
                rule_name=rule.name,
                severity=Severity.HIGH,
                field="server.packages[].integrity",
                tool_name=None,
                match=f"{pkg.name}@{pkg.version or '?'}",
                detail=(
                    f"Package '{pkg.name}' has no integrity hash. "
                    f"There is no way to verify the package contents have not been tampered with."
                ),
                source_mappings=runner._resolve_mappings(),
                remediation=rule.remediation,
                experimental=(rule.status.value == "experimental"),
            ))

    return findings
