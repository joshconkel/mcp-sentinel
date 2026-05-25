"""
Unit tests for mcp-sentinel check modules.

Each test:
  - Loads a fixture file via the schema loader
  - Runs the specific check (bypassing the full engine)
  - Asserts findings are present (malicious) or absent (benign)

Run with: pytest tests/ -v

Test classes MCPS-001 through MCPS-005 use their dedicated check modules.
Test classes MCPS-006 through MCPS-028 use the generic YAML-driven runner.

MCPS-010, MCPS-015, MCPS-018, MCPS-019 are marked xfail until the
schema_analysis compile fix in base.py is merged. Their fixtures are
correct; the engine just cannot yet dispatch field_name_matches patterns.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from mcp_sentinel.loaders.schema import load
from mcp_sentinel.models import RuleDefinition, Severity

FIXTURES = Path(__file__).parent / "fixtures"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_rule(rule_id: str) -> RuleDefinition:
    """Load the live rule definition from rules.yaml for accurate test coverage."""
    from mcp_sentinel.engine import load_rules
    for rule in load_rules():
        if rule.id == rule_id:
            return rule
    raise ValueError(f"Rule {rule_id} not found in rules.yaml")


def _run(rule_id: str, fixture: str):
    """Run a generic rule against a fixture and return findings."""
    from mcp_sentinel.checks.generic import _run_generic
    server_def = load(FIXTURES / fixture)
    rule = _make_rule(rule_id)
    return _run_generic(server_def, rule)


# ---------------------------------------------------------------------------
# MCPS-001: Tool Poisoning via Description Field
# ---------------------------------------------------------------------------

class TestMCPS001:
    def test_malicious_fixture_triggers_finding(self):
        from mcp_sentinel.checks.tool_poisoning import run
        server_def = load(FIXTURES / "MCPS-001-malicious.json")
        rule = _make_rule("MCPS-001")
        findings = run(server_def, rule)
        assert len(findings) > 0, "Expected findings for MCPS-001 malicious fixture"
        assert all(f.rule_id == "MCPS-001" for f in findings)

    def test_malicious_finding_severity_is_critical(self):
        from mcp_sentinel.checks.tool_poisoning import run
        server_def = load(FIXTURES / "MCPS-001-malicious.json")
        rule = _make_rule("MCPS-001")
        findings = run(server_def, rule)
        severities = {f.severity for f in findings}
        assert Severity.CRITICAL in severities or Severity.HIGH in severities

    def test_benign_fixture_produces_no_findings(self):
        from mcp_sentinel.checks.tool_poisoning import run
        server_def = load(FIXTURES / "benign-server.json")
        rule = _make_rule("MCPS-001")
        findings = run(server_def, rule)
        assert len(findings) == 0, f"Unexpected findings on benign fixture: {findings}"

    def test_findings_have_tool_name(self):
        from mcp_sentinel.checks.tool_poisoning import run
        server_def = load(FIXTURES / "MCPS-001-malicious.json")
        rule = _make_rule("MCPS-001")
        findings = run(server_def, rule)
        assert all(f.tool_name is not None for f in findings)

    def test_findings_have_source_mappings(self):
        from mcp_sentinel.checks.tool_poisoning import run
        server_def = load(FIXTURES / "MCPS-001-malicious.json")
        rule = _make_rule("MCPS-001")
        findings = run(server_def, rule)
        assert all(len(f.source_mappings) > 0 for f in findings)


# ---------------------------------------------------------------------------
# MCPS-002: Secret and Token Exposure
# ---------------------------------------------------------------------------

class TestMCPS002:
    def test_malicious_fixture_triggers_finding(self):
        from mcp_sentinel.checks.secrets import run
        server_def = load(FIXTURES / "MCPS-002-malicious.json")
        rule = _make_rule("MCPS-002")
        findings = run(server_def, rule)
        assert len(findings) > 0, "Expected findings for MCPS-002 malicious fixture"

    def test_connection_string_detected_in_env(self):
        from mcp_sentinel.checks.secrets import run
        server_def = load(FIXTURES / "MCPS-002-malicious.json")
        rule = _make_rule("MCPS-002")
        findings = run(server_def, rule)
        env_findings = [f for f in findings if "server.env" in f.field]
        assert len(env_findings) > 0, "Expected a finding for the DATABASE_URL env var"

    def test_aws_key_detected_in_parameter_default(self):
        from mcp_sentinel.checks.secrets import run
        server_def = load(FIXTURES / "MCPS-002-malicious.json")
        rule = _make_rule("MCPS-002")
        findings = run(server_def, rule)
        param_findings = [f for f in findings if "properties" in f.field]
        assert len(param_findings) > 0, "Expected a finding for the hardcoded API key default"

    def test_benign_fixture_produces_no_findings(self):
        from mcp_sentinel.checks.secrets import run
        server_def = load(FIXTURES / "benign-server.json")
        rule = _make_rule("MCPS-002")
        findings = run(server_def, rule)
        assert len(findings) == 0, f"Unexpected findings on benign fixture: {findings}"


# ---------------------------------------------------------------------------
# MCPS-003: Overly Permissive Parameter Schemas
# ---------------------------------------------------------------------------

class TestMCPS003:
    def test_malicious_fixture_triggers_finding(self):
        from mcp_sentinel.checks.parameters import run
        server_def = load(FIXTURES / "MCPS-003-malicious.json")
        rule = _make_rule("MCPS-003")
        findings = run(server_def, rule)
        assert len(findings) > 0, "Expected findings for MCPS-003 malicious fixture"

    def test_command_param_flagged(self):
        from mcp_sentinel.checks.parameters import run
        server_def = load(FIXTURES / "MCPS-003-malicious.json")
        rule = _make_rule("MCPS-003")
        findings = run(server_def, rule)
        command_findings = [f for f in findings if "command" in (f.match or "")]
        assert len(command_findings) > 0, "Expected 'command' parameter to be flagged"

    def test_all_dangerous_tools_flagged(self):
        from mcp_sentinel.checks.parameters import run
        server_def = load(FIXTURES / "MCPS-003-malicious.json")
        rule = _make_rule("MCPS-003")
        findings = run(server_def, rule)
        assert len({f.tool_name for f in findings}) >= 2

    def test_benign_fixture_produces_no_findings(self):
        from mcp_sentinel.checks.parameters import run
        server_def = load(FIXTURES / "benign-server.json")
        rule = _make_rule("MCPS-003")
        findings = run(server_def, rule)
        assert len(findings) == 0, f"Unexpected findings on benign fixture: {findings}"


# ---------------------------------------------------------------------------
# MCPS-004: Insecure Transport Configuration
# ---------------------------------------------------------------------------

class TestMCPS004:
    def test_malicious_fixture_triggers_finding(self):
        from mcp_sentinel.checks.transport import run
        server_def = load(FIXTURES / "MCPS-004-malicious.json")
        rule = _make_rule("MCPS-004")
        findings = run(server_def, rule)
        assert len(findings) > 0, "Expected findings for MCPS-004 malicious fixture"

    def test_http_url_flagged(self):
        from mcp_sentinel.checks.transport import run
        server_def = load(FIXTURES / "MCPS-004-malicious.json")
        rule = _make_rule("MCPS-004")
        findings = run(server_def, rule)
        url_findings = [f for f in findings if f.field == "server.url"]
        assert len(url_findings) > 0, "Expected server.url finding for plaintext HTTP"

    def test_benign_fixture_produces_no_findings(self):
        from mcp_sentinel.checks.transport import run
        server_def = load(FIXTURES / "benign-server.json")
        rule = _make_rule("MCPS-004")
        findings = run(server_def, rule)
        assert len(findings) == 0, f"Unexpected findings on benign fixture: {findings}"

    def test_finding_has_no_tool_name(self):
        """Transport findings are server-level, not tool-level."""
        from mcp_sentinel.checks.transport import run
        server_def = load(FIXTURES / "MCPS-004-malicious.json")
        rule = _make_rule("MCPS-004")
        findings = run(server_def, rule)
        url_findings = [f for f in findings if f.field == "server.url"]
        assert all(f.tool_name is None for f in url_findings)


# ---------------------------------------------------------------------------
# MCPS-005: Agentic Supply Chain: Unverified Tool Provenance
# ---------------------------------------------------------------------------

class TestMCPS005:
    def test_malicious_fixture_triggers_finding(self):
        from mcp_sentinel.checks.provenance import run
        server_def = load(FIXTURES / "MCPS-005-malicious.json")
        rule = _make_rule("MCPS-005")
        findings = run(server_def, rule)
        assert len(findings) > 0, "Expected findings for MCPS-005 malicious fixture"

    def test_latest_version_flagged(self):
        from mcp_sentinel.checks.provenance import run
        server_def = load(FIXTURES / "MCPS-005-malicious.json")
        rule = _make_rule("MCPS-005")
        findings = run(server_def, rule)
        version_findings = [f for f in findings if "latest" in (f.match or "")]
        assert len(version_findings) > 0, "Expected 'latest' version to be flagged"

    def test_missing_integrity_flagged(self):
        from mcp_sentinel.checks.provenance import run
        server_def = load(FIXTURES / "MCPS-005-malicious.json")
        rule = _make_rule("MCPS-005")
        findings = run(server_def, rule)
        integrity_findings = [f for f in findings if "integrity" in f.field]
        assert len(integrity_findings) > 0, "Expected missing integrity hash findings"

    def test_benign_fixture_produces_no_findings(self):
        from mcp_sentinel.checks.provenance import run
        server_def = load(FIXTURES / "benign-server.json")
        rule = _make_rule("MCPS-005")
        findings = run(server_def, rule)
        assert len(findings) == 0, f"Unexpected findings on benign fixture: {findings}"


# ---------------------------------------------------------------------------
# MCPS-006 through MCPS-028: Generic YAML-driven rules
# All use _run_generic via the shared _run() helper above.
# ---------------------------------------------------------------------------

class TestMCPS006:
    """Hidden Instructions in Tool Annotations."""

    def test_malicious_fixture_triggers_finding(self):
        findings = _run("MCPS-006", "MCPS-006-malicious.json")
        assert len(findings) > 0, "Expected finding: instruction override in annotations"

    def test_finding_targets_annotations_field(self):
        findings = _run("MCPS-006", "MCPS-006-malicious.json")
        assert any("annotations" in f.field for f in findings)

    def test_benign_fixture_produces_no_findings(self):
        findings = _run("MCPS-006", "benign-server.json")
        assert len(findings) == 0, f"Unexpected findings: {findings}"


class TestMCPS007:
    """LLM Jailbreak Trigger Language in Tool Definitions."""

    def test_malicious_fixture_triggers_finding(self):
        findings = _run("MCPS-007", "MCPS-007-malicious.json")
        assert len(findings) > 0, "Expected finding: jailbreak language in description"

    def test_finding_is_critical(self):
        findings = _run("MCPS-007", "MCPS-007-malicious.json")
        assert any(f.severity == Severity.CRITICAL for f in findings)

    def test_benign_fixture_produces_no_findings(self):
        findings = _run("MCPS-007", "benign-server.json")
        assert len(findings) == 0, f"Unexpected findings: {findings}"


class TestMCPS008:
    """Credentials Embedded in Server URL."""

    def test_malicious_fixture_triggers_finding(self):
        findings = _run("MCPS-008", "MCPS-008-malicious.json")
        assert len(findings) > 0, "Expected finding: credentials in server URL"

    def test_finding_targets_server_url(self):
        findings = _run("MCPS-008", "MCPS-008-malicious.json")
        assert all(f.field == "server.url" for f in findings)

    def test_finding_has_no_tool_name(self):
        """Server URL findings are server-level, not tool-level."""
        findings = _run("MCPS-008", "MCPS-008-malicious.json")
        assert all(f.tool_name is None for f in findings)

    def test_benign_fixture_produces_no_findings(self):
        findings = _run("MCPS-008", "benign-server.json")
        assert len(findings) == 0, f"Unexpected findings: {findings}"


class TestMCPS009:
    """Dangerous Tool Name Indicating Direct System Access."""

    def test_malicious_fixture_triggers_finding(self):
        findings = _run("MCPS-009", "MCPS-009-malicious.json")
        assert len(findings) > 0, "Expected finding: dangerous tool names"

    def test_multiple_tools_flagged(self):
        findings = _run("MCPS-009", "MCPS-009-malicious.json")
        flagged_tools = {f.tool_name for f in findings}
        assert len(flagged_tools) >= 2, "Expected at least two dangerous tool names flagged"

    def test_finding_targets_tool_name_field(self):
        findings = _run("MCPS-009", "MCPS-009-malicious.json")
        assert all(f.field == "tool.name" for f in findings)

    def test_benign_fixture_produces_no_findings(self):
        findings = _run("MCPS-009", "benign-server.json")
        assert len(findings) == 0, f"Unexpected findings: {findings}"

class TestMCPS010:
    """Server-Side Request Forgery via Unrestricted URL Parameter."""

    def test_malicious_fixture_triggers_finding(self):
        findings = _run("MCPS-010", "MCPS-010-malicious.json")
        assert len(findings) > 0, "Expected finding: unconstrained URL parameter"

    def test_benign_fixture_produces_no_findings(self):
        findings = _run("MCPS-010", "benign-server.json")
        assert len(findings) == 0, f"Unexpected findings: {findings}"


class TestMCPS011:
    """Unfiltered External Content Pass-Through."""

    def test_malicious_fixture_triggers_finding(self):
        findings = _run("MCPS-011", "MCPS-011-malicious.json")
        assert len(findings) > 0, "Expected finding: pass-through / raw response language"

    def test_benign_fixture_produces_no_findings(self):
        findings = _run("MCPS-011", "benign-server.json")
        assert len(findings) == 0, f"Unexpected findings: {findings}"


class TestMCPS012:
    """Internal Network Infrastructure Disclosure."""

    def test_malicious_fixture_triggers_finding(self):
        findings = _run("MCPS-012", "MCPS-012-malicious.json")
        assert len(findings) > 0, "Expected finding: private IP or internal domain"

    def test_private_ip_detected(self):
        findings = _run("MCPS-012", "MCPS-012-malicious.json")
        ip_findings = [f for f in findings if "10." in (f.match or "")]
        assert len(ip_findings) > 0, "Expected a finding matching the private IP range"

    def test_benign_fixture_produces_no_findings(self):
        findings = _run("MCPS-012", "benign-server.json")
        assert len(findings) == 0, f"Unexpected findings: {findings}"


class TestMCPS013:
    """Unrestricted Filesystem Access Pattern in Tool Description."""

    def test_malicious_fixture_triggers_finding(self):
        findings = _run("MCPS-013", "MCPS-013-malicious.json")
        assert len(findings) > 0, "Expected finding: unrestricted filesystem language"

    def test_benign_fixture_produces_no_findings(self):
        findings = _run("MCPS-013", "benign-server.json")
        assert len(findings) == 0, f"Unexpected findings: {findings}"


class TestMCPS014:
    """Bulk or Unfiltered Data Return Pattern."""

    def test_malicious_fixture_triggers_finding(self):
        findings = _run("MCPS-014", "MCPS-014-malicious.json")
        assert len(findings) > 0, "Expected finding: bulk/entire data return language"

    def test_benign_fixture_produces_no_findings(self):
        findings = _run("MCPS-014", "benign-server.json")
        assert len(findings) == 0, f"Unexpected findings: {findings}"

class TestMCPS015:
    """Insecure Webhook or Callback URL Parameter."""

    def test_malicious_fixture_triggers_finding(self):
        findings = _run("MCPS-015", "MCPS-015-malicious.json")
        assert len(findings) > 0, "Expected finding: unconstrained webhook parameter"

    def test_benign_fixture_produces_no_findings(self):
        findings = _run("MCPS-015", "benign-server.json")
        assert len(findings) == 0, f"Unexpected findings: {findings}"


class TestMCPS016:
    """Capability Self-Grant in Tool Definition."""

    def test_malicious_fixture_triggers_finding(self):
        findings = _run("MCPS-016", "MCPS-016-malicious.json")
        assert len(findings) > 0, "Expected finding: capability self-grant language"

    def test_finding_is_critical(self):
        findings = _run("MCPS-016", "MCPS-016-malicious.json")
        assert any(f.severity == Severity.CRITICAL for f in findings)

    def test_benign_fixture_produces_no_findings(self):
        findings = _run("MCPS-016", "benign-server.json")
        assert len(findings) == 0, f"Unexpected findings: {findings}"


class TestMCPS017:
    """Tool Memory Write and Persistence Pattern."""

    def test_malicious_fixture_triggers_finding(self):
        findings = _run("MCPS-017", "MCPS-017-malicious.json")
        assert len(findings) > 0, "Expected finding: memory write / persistence language"

    def test_benign_fixture_produces_no_findings(self):
        findings = _run("MCPS-017", "benign-server.json")
        assert len(findings) == 0, f"Unexpected findings: {findings}"

class TestMCPS018:
    """Numeric Parameter Without Range Constraints."""

    def test_malicious_fixture_triggers_finding(self):
        findings = _run("MCPS-018", "MCPS-018-malicious.json")
        assert len(findings) > 0, "Expected finding: unbounded numeric parameter"

    def test_benign_fixture_produces_no_findings(self):
        findings = _run("MCPS-018", "benign-server.json")
        assert len(findings) == 0, f"Unexpected findings: {findings}"

class TestMCPS019:
    """Executable Code or Script Parameter."""

    def test_malicious_fixture_triggers_finding(self):
        findings = _run("MCPS-019", "MCPS-019-malicious.json")
        assert len(findings) > 0, "Expected finding: code/script parameter"

    def test_finding_is_critical(self):
        findings = _run("MCPS-019", "MCPS-019-malicious.json")
        assert any(f.severity == Severity.CRITICAL for f in findings)

    def test_benign_fixture_produces_no_findings(self):
        findings = _run("MCPS-019", "benign-server.json")
        assert len(findings) == 0, f"Unexpected findings: {findings}"


class TestMCPS020:
    """Placeholder and Default Credential Values."""

    def test_malicious_fixture_triggers_finding(self):
        findings = _run("MCPS-020", "MCPS-020-malicious.json")
        assert len(findings) > 0, "Expected finding: placeholder credentials"

    def test_env_placeholder_detected(self):
        findings = _run("MCPS-020", "MCPS-020-malicious.json")
        env_findings = [f for f in findings if "server.env" in f.field]
        assert len(env_findings) > 0, "Expected finding from server.env placeholder"

    def test_param_default_placeholder_detected(self):
        findings = _run("MCPS-020", "MCPS-020-malicious.json")
        param_findings = [f for f in findings if "inputSchema" in f.field]
        assert len(param_findings) > 0, "Expected finding from parameter default placeholder"

    def test_benign_fixture_produces_no_findings(self):
        findings = _run("MCPS-020", "benign-server.json")
        assert len(findings) == 0, f"Unexpected findings: {findings}"


class TestMCPS021:
    """Misconfigured Cross-Origin and CORS Policies."""

    def test_malicious_fixture_triggers_finding(self):
        findings = _run("MCPS-021", "MCPS-021-malicious.json")
        assert len(findings) > 0, "Expected finding: wildcard CORS origin"

    def test_finding_has_no_tool_name(self):
        """CORS is a server-level configuration, not tool-level."""
        findings = _run("MCPS-021", "MCPS-021-malicious.json")
        assert all(f.tool_name is None for f in findings)

    def test_benign_fixture_produces_no_findings(self):
        findings = _run("MCPS-021", "benign-server.json")
        assert len(findings) == 0, f"Unexpected findings: {findings}"


class TestMCPS022:
    """Insufficient Logging and Monitoring Indicators."""

    def test_malicious_fixture_triggers_finding(self):
        findings = _run("MCPS-022", "MCPS-022-malicious.json")
        assert len(findings) > 0, "Expected finding: no-logging language in description"

    def test_benign_fixture_produces_no_findings(self):
        findings = _run("MCPS-022", "benign-server.json")
        assert len(findings) == 0, f"Unexpected findings: {findings}"


class TestMCPS023:
    """Missing Human Oversight for High-Risk Operations."""

    def test_malicious_fixture_triggers_finding(self):
        findings = _run("MCPS-023", "MCPS-023-malicious.json")
        assert len(findings) > 0, "Expected finding: irreversible action without approval"

    def test_benign_fixture_produces_no_findings(self):
        findings = _run("MCPS-023", "benign-server.json")
        assert len(findings) == 0, f"Unexpected findings: {findings}"


class TestMCPS024:
    """Cross-Agent Instruction Propagation Risk."""

    def test_malicious_fixture_triggers_finding(self):
        findings = _run("MCPS-024", "MCPS-024-malicious.json")
        assert len(findings) > 0, "Expected finding: cross-agent relay language"

    def test_benign_fixture_produces_no_findings(self):
        findings = _run("MCPS-024", "benign-server.json")
        assert len(findings) == 0, f"Unexpected findings: {findings}"


class TestMCPS025:
    """Unauthenticated Cross-Agent Communication."""

    def test_malicious_fixture_triggers_finding(self):
        findings = _run("MCPS-025", "MCPS-025-malicious.json")
        assert len(findings) > 0, "Expected finding: unauthenticated agent transport"

    def test_transport_finding_has_no_tool_name(self):
        """The value_check on server.transport is server-level."""
        findings = _run("MCPS-025", "MCPS-025-malicious.json")
        transport_findings = [f for f in findings if f.field == "server.transport"]
        assert all(f.tool_name is None for f in transport_findings)

    def test_benign_fixture_produces_no_findings(self):
        findings = _run("MCPS-025", "benign-server.json")
        assert len(findings) == 0, f"Unexpected findings: {findings}"


class TestMCPS026:
    """Untrusted External Source References in Tool Definitions."""

    def test_malicious_fixture_triggers_finding(self):
        findings = _run("MCPS-026", "MCPS-026-malicious.json")
        assert len(findings) > 0, "Expected finding: unofficial third-party source reference"

    def test_benign_fixture_produces_no_findings(self):
        findings = _run("MCPS-026", "benign-server.json")
        assert len(findings) == 0, f"Unexpected findings: {findings}"


class TestMCPS027:
    """Data and Model Poisoning Patterns in Tool Definitions."""

    def test_malicious_fixture_triggers_finding(self):
        findings = _run("MCPS-027", "MCPS-027-malicious.json")
        assert len(findings) > 0, "Expected finding: model/data poisoning language"

    def test_benign_fixture_produces_no_findings(self):
        findings = _run("MCPS-027", "benign-server.json")
        assert len(findings) == 0, f"Unexpected findings: {findings}"


class TestMCPS028:
    """Misleading Security Claims in Tool Metadata."""

    def test_malicious_fixture_triggers_finding(self):
        findings = _run("MCPS-028", "MCPS-028-malicious.json")
        assert len(findings) > 0, "Expected finding: overconfident security guarantee"

    def test_benign_fixture_produces_no_findings(self):
        findings = _run("MCPS-028", "benign-server.json")
        assert len(findings) == 0, f"Unexpected findings: {findings}"


# ---------------------------------------------------------------------------
# Schema loader tests
# ---------------------------------------------------------------------------


class TestMCPS029:
    """Covert Data Exfiltration via Rendered Image URLs."""

    def test_malicious_fixture_triggers_finding(self):
        findings = _run("MCPS-029", "MCPS-029-malicious.json")
        assert len(findings) > 0, "Expected finding for MCPS-029"

    def test_benign_fixture_produces_no_findings(self):
        findings = _run("MCPS-029", "benign-server.json")
        assert len(findings) == 0, f"Unexpected findings on benign fixture: {findings}"


class TestMCPS030:
    """Cloud and AI Service Enumeration via MCP Tools."""

    def test_malicious_fixture_triggers_finding(self):
        findings = _run("MCPS-030", "MCPS-030-malicious.json")
        assert len(findings) > 0, "Expected finding for MCPS-030: Cloud and AI Service Enumeration via MCP Tools"

    def test_benign_fixture_produces_no_findings(self):
        findings = _run("MCPS-030", "benign-server.json")
        assert len(findings) == 0, f"Unexpected findings on benign fixture: {findings}"


class TestMCPS031:
    """Credential Harvesting via Agent Tool Definitions."""

    def test_malicious_fixture_triggers_finding(self):
        findings = _run("MCPS-031", "MCPS-031-malicious.json")
        assert len(findings) > 0, "Expected finding for MCPS-031: Credential Harvesting via Agent Tool Definitions"

    def test_benign_fixture_produces_no_findings(self):
        findings = _run("MCPS-031", "benign-server.json")
        assert len(findings) == 0, f"Unexpected findings on benign fixture: {findings}"


class TestMCPS032:
    """RAG Poisoning via Tool Description Injection."""

    def test_malicious_fixture_triggers_finding(self):
        findings = _run("MCPS-032", "MCPS-032-malicious.json")
        assert len(findings) > 0, "Expected finding for MCPS-032: RAG Poisoning via Tool Description Injection"

    def test_benign_fixture_produces_no_findings(self):
        findings = _run("MCPS-032", "benign-server.json")
        assert len(findings) == 0, f"Unexpected findings on benign fixture: {findings}"


class TestMCPS033:
    """Destructive Tool Invocation via MCP Definition."""

    def test_malicious_fixture_triggers_finding(self):
        findings = _run("MCPS-033", "MCPS-033-malicious.json")
        assert len(findings) > 0, "Expected finding for MCPS-033: Destructive Tool Invocation via MCP Definition"

    def test_benign_fixture_produces_no_findings(self):
        findings = _run("MCPS-033", "benign-server.json")
        assert len(findings) == 0, f"Unexpected findings on benign fixture: {findings}"


class TestMCPS034:
    """Trusted Output Manipulation via Tool Metadata."""

    def test_malicious_fixture_triggers_finding(self):
        findings = _run("MCPS-034", "MCPS-034-malicious.json")
        assert len(findings) > 0, "Expected finding for MCPS-034: Trusted Output Manipulation via Tool Metadata"

    def test_benign_fixture_produces_no_findings(self):
        findings = _run("MCPS-034", "benign-server.json")
        assert len(findings) == 0, f"Unexpected findings on benign fixture: {findings}"

    def test_finding_has_tool_context(self):
        findings = _run("MCPS-034", "MCPS-034-malicious.json")
        assert any(f.tool_name is not None for f in findings), \
            "Expected at least one finding with tool context"


class TestMCPS035:
    """Deferred Malicious Instructions in Tool Definitions."""

    def test_malicious_fixture_triggers_finding(self):
        findings = _run("MCPS-035", "MCPS-035-malicious.json")
        assert len(findings) > 0, "Expected finding for MCPS-035: Deferred Malicious Instructions in Tool Definition"

    def test_benign_fixture_produces_no_findings(self):
        findings = _run("MCPS-035", "benign-server.json")
        assert len(findings) == 0, f"Unexpected findings on benign fixture: {findings}"


class TestMCPS036:
    """Supply Chain Rug Pull via Package Update."""

    def test_malicious_fixture_triggers_finding(self):
        findings = _run("MCPS-036", "MCPS-036-malicious.json")
        assert len(findings) > 0, "Expected finding for MCPS-036: Supply Chain Rug Pull via Package Update"

    def test_benign_fixture_produces_no_findings(self):
        findings = _run("MCPS-036", "benign-server.json")
        assert len(findings) == 0, f"Unexpected findings on benign fixture: {findings}"

    def test_finding_is_server_level(self):
        findings = _run("MCPS-036", "MCPS-036-malicious.json")
        assert all(f.tool_name is None for f in findings), \
            "Server-level findings should not have a tool_name"


class TestMCPS037:
    """Public Code Repository Exposure in MCP Definitions."""

    def test_malicious_fixture_triggers_finding(self):
        findings = _run("MCPS-037", "MCPS-037-malicious.json")
        assert len(findings) > 0, "Expected finding for MCPS-037: Public Code Repository Exposure in MCP Definitions"

    def test_benign_fixture_produces_no_findings(self):
        findings = _run("MCPS-037", "benign-server.json")
        assert len(findings) == 0, f"Unexpected findings on benign fixture: {findings}"


class TestMCPS038:
    """LLM Prompt Crafting via MCP Definition Poisoning."""

    def test_malicious_fixture_triggers_finding(self):
        findings = _run("MCPS-038", "MCPS-038-malicious.json")
        assert len(findings) > 0, "Expected finding for MCPS-038: LLM Prompt Crafting via MCP Definition Poisoning"

    def test_benign_fixture_produces_no_findings(self):
        findings = _run("MCPS-038", "benign-server.json")
        assert len(findings) == 0, f"Unexpected findings on benign fixture: {findings}"


class TestMCPS039:
    """Unrestricted Data Access via AI Agent Tools."""

    def test_malicious_fixture_triggers_finding(self):
        findings = _run("MCPS-039", "MCPS-039-malicious.json")
        assert len(findings) > 0, "Expected finding for MCPS-039: Unrestricted Data Access via AI Agent Tools"

    def test_benign_fixture_produces_no_findings(self):
        findings = _run("MCPS-039", "benign-server.json")
        assert len(findings) == 0, f"Unexpected findings on benign fixture: {findings}"


class TestMCPS040:
    """Unrestricted AI Agent Tool Access Definition."""

    def test_malicious_fixture_triggers_finding(self):
        findings = _run("MCPS-040", "MCPS-040-malicious.json")
        assert len(findings) > 0, "Expected finding for MCPS-040: Unrestricted AI Agent Tool Access Definition"

    def test_benign_fixture_produces_no_findings(self):
        findings = _run("MCPS-040", "benign-server.json")
        assert len(findings) == 0, f"Unexpected findings on benign fixture: {findings}"


class TestMCPS041:
    """Covert AI Agent C2 via Hidden Instructions."""

    def test_malicious_fixture_triggers_finding(self):
        findings = _run("MCPS-041", "MCPS-041-malicious.json")
        assert len(findings) > 0, "Expected finding for MCPS-041: Covert AI Agent C2 via Hidden Instructions"

    def test_benign_fixture_produces_no_findings(self):
        findings = _run("MCPS-041", "benign-server.json")
        assert len(findings) == 0, f"Unexpected findings on benign fixture: {findings}"

    def test_finding_has_tool_context(self):
        findings = _run("MCPS-041", "MCPS-041-malicious.json")
        assert any(f.tool_name is not None for f in findings), \
            "Expected at least one finding with tool context"


class TestMCPS042:
    """Supply Chain Poisoned MCP Tool Definition."""

    def test_malicious_fixture_triggers_finding(self):
        findings = _run("MCPS-042", "MCPS-042-malicious.json")
        assert len(findings) > 0, "Expected finding for MCPS-042: Supply Chain Poisoned MCP Tool Definition"

    def test_benign_fixture_produces_no_findings(self):
        findings = _run("MCPS-042", "benign-server.json")
        assert len(findings) == 0, f"Unexpected findings on benign fixture: {findings}"


class TestMCPS043:
    """Agent Configuration Leakage via Metadata."""

    def test_malicious_fixture_triggers_finding(self):
        findings = _run("MCPS-043", "MCPS-043-malicious.json")
        assert len(findings) > 0, "Expected finding for MCPS-043: Agent Configuration Leakage via Metadata"

    def test_benign_fixture_produces_no_findings(self):
        findings = _run("MCPS-043", "benign-server.json")
        assert len(findings) == 0, f"Unexpected findings on benign fixture: {findings}"


class TestMCPS044:
    """Agent Tool Discovery and Capability Enumeration."""

    def test_malicious_fixture_triggers_finding(self):
        findings = _run("MCPS-044", "MCPS-044-malicious.json")
        assert len(findings) > 0, "Expected finding for MCPS-044: Agent Tool Discovery and Capability Enumeration"

    def test_benign_fixture_produces_no_findings(self):
        findings = _run("MCPS-044", "benign-server.json")
        assert len(findings) == 0, f"Unexpected findings on benign fixture: {findings}"


class TestMCPS045:
    """Hardcoded Application Access Tokens in MCP Definitions."""

    def test_malicious_fixture_triggers_finding(self):
        findings = _run("MCPS-045", "MCPS-045-malicious.json")
        assert len(findings) > 0, "Expected finding for MCPS-045: Hardcoded Application Access Tokens in MCP Definit"

    def test_benign_fixture_produces_no_findings(self):
        findings = _run("MCPS-045", "benign-server.json")
        assert len(findings) == 0, f"Unexpected findings on benign fixture: {findings}"


class TestMCPS046:
    """Unauthorized AI Agent Deployment Configuration."""

    def test_malicious_fixture_triggers_finding(self):
        findings = _run("MCPS-046", "MCPS-046-malicious.json")
        assert len(findings) > 0, "Expected finding for MCPS-046: Unauthorized AI Agent Deployment Configuration"

    def test_benign_fixture_produces_no_findings(self):
        findings = _run("MCPS-046", "benign-server.json")
        assert len(findings) == 0, f"Unexpected findings on benign fixture: {findings}"


class TestMCPS047:
    """Drive-by Compromise via Web-Fetching Tools."""

    def test_malicious_fixture_triggers_finding(self):
        findings = _run("MCPS-047", "MCPS-047-malicious.json")
        assert len(findings) > 0, "Expected finding for MCPS-047: Drive-by Compromise via Web-Fetching Tools"

    def test_benign_fixture_produces_no_findings(self):
        findings = _run("MCPS-047", "benign-server.json")
        assert len(findings) == 0, f"Unexpected findings on benign fixture: {findings}"


class TestMCPS048:
    """Sensitive Data Exposure via Tool Configuration."""

    def test_malicious_fixture_triggers_finding(self):
        findings = _run("MCPS-048", "MCPS-048-malicious.json")
        assert len(findings) > 0, "Expected finding for MCPS-048: Sensitive Data Exposure via Tool Configuration"

    def test_benign_fixture_produces_no_findings(self):
        findings = _run("MCPS-048", "benign-server.json")
        assert len(findings) == 0, f"Unexpected findings on benign fixture: {findings}"


class TestMCPS049:
    """Crafted Retrieval Content in MCP Definitions."""

    def test_malicious_fixture_triggers_finding(self):
        findings = _run("MCPS-049", "MCPS-049-malicious.json")
        assert len(findings) > 0, "Expected finding for MCPS-049: Crafted Retrieval Content in MCP Definitions"

    def test_benign_fixture_produces_no_findings(self):
        findings = _run("MCPS-049", "benign-server.json")
        assert len(findings) == 0, f"Unexpected findings on benign fixture: {findings}"


class TestMCPS050:
    """Poisoned Training Data Ingestion via MCP Tools."""

    def test_malicious_fixture_triggers_finding(self):
        findings = _run("MCPS-050", "MCPS-050-malicious.json")
        assert len(findings) > 0, "Expected finding for MCPS-050: Poisoned Training Data Ingestion via MCP Tools"

    def test_benign_fixture_produces_no_findings(self):
        findings = _run("MCPS-050", "benign-server.json")
        assert len(findings) == 0, f"Unexpected findings on benign fixture: {findings}"


class TestMCPS051:
    """Delimiter Confusion via Special Character Sets."""

    def test_malicious_fixture_triggers_finding(self):
        findings = _run("MCPS-051", "MCPS-051-malicious.json")
        assert len(findings) > 0, "Expected finding for MCPS-051: Delimiter Confusion via Special Character Sets"

    def test_benign_fixture_produces_no_findings(self):
        findings = _run("MCPS-051", "benign-server.json")
        assert len(findings) == 0, f"Unexpected findings on benign fixture: {findings}"


class TestMCPS052:
    """MCP Server Chat History Manipulation Capability."""

    def test_malicious_fixture_triggers_finding(self):
        findings = _run("MCPS-052", "MCPS-052-malicious.json")
        assert len(findings) > 0, "Expected finding for MCPS-052: MCP Server Chat History Manipulation Capability"

    def test_benign_fixture_produces_no_findings(self):
        findings = _run("MCPS-052", "benign-server.json")
        assert len(findings) == 0, f"Unexpected findings on benign fixture: {findings}"


class TestMCPS053:
    """MCP Tool Facilitating Dynamic AI Command Generation."""

    def test_malicious_fixture_triggers_finding(self):
        findings = _run("MCPS-053", "MCPS-053-malicious.json")
        assert len(findings) > 0, "Expected finding for MCPS-053: MCP Tool Facilitating Dynamic AI Command Generatio"

    def test_benign_fixture_produces_no_findings(self):
        findings = _run("MCPS-053", "benign-server.json")
        assert len(findings) == 0, f"Unexpected findings on benign fixture: {findings}"


class TestMCPS054:
    """Detection of Unsafe Execution Sinks in Call Chains."""

    def test_malicious_fixture_triggers_finding(self):
        findings = _run("MCPS-054", "MCPS-054-malicious.json")
        assert len(findings) > 0, "Expected finding for MCPS-054: Detection of Unsafe Execution Sinks in Call Chains"

    def test_benign_fixture_produces_no_findings(self):
        findings = _run("MCPS-054", "benign-server.json")
        assert len(findings) == 0, f"Unexpected findings on benign fixture: {findings}"


class TestMCPS055:
    """Phishing via Impersonation and Social Engineering."""

    def test_malicious_fixture_triggers_finding(self):
        findings = _run("MCPS-055", "MCPS-055-malicious.json")
        assert len(findings) > 0, "Expected finding for MCPS-055: Phishing via Impersonation and Social Engineering"

    def test_benign_fixture_produces_no_findings(self):
        findings = _run("MCPS-055", "benign-server.json")
        assert len(findings) == 0, f"Unexpected findings on benign fixture: {findings}"


class TestMCPS056:
    """Supply Chain Compromise via Unpinned Dependencies."""

    def test_malicious_fixture_triggers_finding(self):
        findings = _run("MCPS-056", "MCPS-056-malicious.json")
        assert len(findings) > 0, "Expected finding for MCPS-056: Supply Chain Compromise via Unpinned Dependencies"

    def test_benign_fixture_produces_no_findings(self):
        findings = _run("MCPS-056", "benign-server.json")
        assert len(findings) == 0, f"Unexpected findings on benign fixture: {findings}"


class TestMCPS057:
    """Self-Replicating Prompt Injection in Tool Definitions."""

    def test_malicious_fixture_triggers_finding(self):
        findings = _run("MCPS-057", "MCPS-057-malicious.json")
        assert len(findings) > 0, "Expected finding for MCPS-057: Self-Replicating Prompt Injection in Tool Definiti"

    def test_benign_fixture_produces_no_findings(self):
        findings = _run("MCPS-057", "benign-server.json")
        assert len(findings) == 0, f"Unexpected findings on benign fixture: {findings}"

    def test_finding_has_tool_context(self):
        findings = _run("MCPS-057", "MCPS-057-malicious.json")
        assert any(f.tool_name is not None for f in findings), \
            "Expected at least one finding with tool context"


class TestMCPS058:
    """Unverified Entity Generation Enabling Hallucination Discovery."""

    def test_malicious_fixture_triggers_finding(self):
        findings = _run("MCPS-058", "MCPS-058-malicious.json")
        assert len(findings) > 0, "Expected finding for MCPS-058: Unverified Entity Generation Enabling Hallucinatio"

    def test_benign_fixture_produces_no_findings(self):
        findings = _run("MCPS-058", "benign-server.json")
        assert len(findings) == 0, f"Unexpected findings on benign fixture: {findings}"


class TestMCPS059:
    """Suspicious System Instruction Keywords in Tool Definitions."""

    def test_malicious_fixture_triggers_finding(self):
        findings = _run("MCPS-059", "MCPS-059-malicious.json")
        assert len(findings) > 0, "Expected finding for MCPS-059: Suspicious System Instruction Keywords in Tool Def"

    def test_benign_fixture_produces_no_findings(self):
        findings = _run("MCPS-059", "benign-server.json")
        assert len(findings) == 0, f"Unexpected findings on benign fixture: {findings}"


class TestMCPS060:
    """LLM System Information Discovery via Tool Definitions."""

    def test_malicious_fixture_triggers_finding(self):
        findings = _run("MCPS-060", "MCPS-060-malicious.json")
        assert len(findings) > 0, "Expected finding for MCPS-060: LLM System Information Discovery via Tool Definiti"

    def test_benign_fixture_produces_no_findings(self):
        findings = _run("MCPS-060", "benign-server.json")
        assert len(findings) == 0, f"Unexpected findings on benign fixture: {findings}"


class TestMCPS061:
    """Chaff Data Spamming via Tool Definitions."""

    def test_malicious_fixture_triggers_finding(self):
        findings = _run("MCPS-061", "MCPS-061-malicious.json")
        assert len(findings) > 0, "Expected finding for MCPS-061: Chaff Data Spamming via Tool Definitions"

    def test_benign_fixture_produces_no_findings(self):
        findings = _run("MCPS-061", "benign-server.json")
        assert len(findings) == 0, f"Unexpected findings on benign fixture: {findings}"


class TestMCPS062:
    """MCP Tool Attack Verification and Probing."""

    def test_malicious_fixture_triggers_finding(self):
        findings = _run("MCPS-062", "MCPS-062-malicious.json")
        assert len(findings) > 0, "Expected finding for MCPS-062: MCP Tool Attack Verification and Probing"

    def test_benign_fixture_produces_no_findings(self):
        findings = _run("MCPS-062", "benign-server.json")
        assert len(findings) == 0, f"Unexpected findings on benign fixture: {findings}"


class TestMCPS063:
    """System Prompt Exposure in MCP Definitions."""

    def test_malicious_fixture_triggers_finding(self):
        findings = _run("MCPS-063", "MCPS-063-malicious.json")
        assert len(findings) > 0, "Expected finding for MCPS-063: System Prompt Exposure in MCP Definitions"

    def test_benign_fixture_produces_no_findings(self):
        findings = _run("MCPS-063", "benign-server.json")
        assert len(findings) == 0, f"Unexpected findings on benign fixture: {findings}"


class TestMCPS064:
    """Detection of Unauthorized AI Service Proxy Endpoints."""

    def test_malicious_fixture_triggers_finding(self):
        findings = _run("MCPS-064", "MCPS-064-malicious.json")
        assert len(findings) > 0, "Expected finding for MCPS-064: Detection of Unauthorized AI Service Proxy Endpoin"

    def test_benign_fixture_produces_no_findings(self):
        findings = _run("MCPS-064", "benign-server.json")
        assert len(findings) == 0, f"Unexpected findings on benign fixture: {findings}"

    def test_finding_is_server_level(self):
        findings = _run("MCPS-064", "MCPS-064-malicious.json")
        assert all(f.tool_name is None for f in findings), \
            "Server-level findings should not have a tool_name"


class TestMCPS065:
    """Active Scanning via MCP Tool Definitions."""

    def test_malicious_fixture_triggers_finding(self):
        findings = _run("MCPS-065", "MCPS-065-malicious.json")
        assert len(findings) > 0, "Expected finding for MCPS-065: Active Scanning via MCP Tool Definitions"

    def test_benign_fixture_produces_no_findings(self):
        findings = _run("MCPS-065", "benign-server.json")
        assert len(findings) == 0, f"Unexpected findings on benign fixture: {findings}"


class TestMCPS066:
    """Hardcoded Credentials in MCP Server Definition."""

    def test_malicious_fixture_triggers_finding(self):
        findings = _run("MCPS-066", "MCPS-066-malicious.json")
        assert len(findings) > 0, "Expected finding for MCPS-066: Hardcoded Credentials in MCP Server Definition"

    def test_benign_fixture_produces_no_findings(self):
        findings = _run("MCPS-066", "benign-server.json")
        assert len(findings) == 0, f"Unexpected findings on benign fixture: {findings}"


class TestMCPS067:
    """Staged Capabilities via External Registry References."""

    def test_malicious_fixture_triggers_finding(self):
        findings = _run("MCPS-067", "MCPS-067-malicious.json")
        assert len(findings) > 0, "Expected finding for MCPS-067: Staged Capabilities via External Registry Referenc"

    def test_benign_fixture_produces_no_findings(self):
        findings = _run("MCPS-067", "benign-server.json")
        assert len(findings) == 0, f"Unexpected findings on benign fixture: {findings}"

    def test_finding_has_tool_context(self):
        findings = _run("MCPS-067", "MCPS-067-malicious.json")
        assert any(f.tool_name is not None for f in findings), \
            "Expected at least one finding with tool context"


class TestMCPS068:
    """Detects Tools Capable of Generating Deepfakes."""

    def test_malicious_fixture_triggers_finding(self):
        findings = _run("MCPS-068", "MCPS-068-malicious.json")
        assert len(findings) > 0, "Expected finding for MCPS-068: Detects Tools Capable of Generating Deepfakes"

    def test_benign_fixture_produces_no_findings(self):
        findings = _run("MCPS-068", "benign-server.json")
        assert len(findings) == 0, f"Unexpected findings on benign fixture: {findings}"


class TestMCPS069:
    """Unbounded Input Schema Enables Resource Exhaustion."""

    def test_malicious_fixture_triggers_finding(self):
        findings = _run("MCPS-069", "MCPS-069-malicious.json")
        assert len(findings) > 0, "Expected finding for MCPS-069: Unbounded Input Schema Enables Resource Exhaustion"

    def test_benign_fixture_produces_no_findings(self):
        findings = _run("MCPS-069", "benign-server.json")
        assert len(findings) == 0, f"Unexpected findings on benign fixture: {findings}"


class TestMCPS070:
    """Deepfake Phishing Facilitation via MCP Tools."""

    def test_malicious_fixture_triggers_finding(self):
        findings = _run("MCPS-070", "MCPS-070-malicious.json")
        assert len(findings) > 0, "Expected finding for MCPS-070: Deepfake Phishing Facilitation via MCP Tools"

    def test_benign_fixture_produces_no_findings(self):
        findings = _run("MCPS-070", "benign-server.json")
        assert len(findings) == 0, f"Unexpected findings on benign fixture: {findings}"


class TestMCPS071:
    """MCP Server Proxy Model Staging Detection."""

    def test_malicious_fixture_triggers_finding(self):
        findings = _run("MCPS-071", "MCPS-071-malicious.json")
        assert len(findings) > 0, "Expected finding for MCPS-071: MCP Server Proxy Model Staging Detection"

    def test_benign_fixture_produces_no_findings(self):
        findings = _run("MCPS-071", "benign-server.json")
        assert len(findings) == 0, f"Unexpected findings on benign fixture: {findings}"


class TestMCPS072:
    """Model Poisoning via Unverified Weights and Data."""

    def test_malicious_fixture_triggers_finding(self):
        findings = _run("MCPS-072", "MCPS-072-malicious.json")
        assert len(findings) > 0, "Expected finding for MCPS-072: Model Poisoning via Unverified Weights and Data"

    def test_benign_fixture_produces_no_findings(self):
        findings = _run("MCPS-072", "benign-server.json")
        assert len(findings) == 0, f"Unexpected findings on benign fixture: {findings}"


class TestMCPS073:
    """Overly Permissive Local Agent Tool Definitions."""

    def test_malicious_fixture_triggers_finding(self):
        findings = _run("MCPS-073", "MCPS-073-malicious.json")
        assert len(findings) > 0, "Expected finding for MCPS-073: Overly Permissive Local Agent Tool Definitions"

    def test_benign_fixture_produces_no_findings(self):
        findings = _run("MCPS-073", "benign-server.json")
        assert len(findings) == 0, f"Unexpected findings on benign fixture: {findings}"


class TestMCPS074:
    """Unrestricted Process Enumeration Tool."""

    def test_malicious_fixture_triggers_finding(self):
        findings = _run("MCPS-074", "MCPS-074-malicious.json")
        assert len(findings) > 0, "Expected finding for MCPS-074: Unrestricted Process Enumeration Tool"

    def test_benign_fixture_produces_no_findings(self):
        findings = _run("MCPS-074", "benign-server.json")
        assert len(findings) == 0, f"Unexpected findings on benign fixture: {findings}"


class TestMCPS075:
    """Black-Box Transfer via Adversarial Input Crafting."""

    def test_malicious_fixture_triggers_finding(self):
        findings = _run("MCPS-075", "MCPS-075-malicious.json")
        assert len(findings) > 0, "Expected finding for MCPS-075: Black-Box Transfer via Adversarial Input Crafting"

    def test_benign_fixture_produces_no_findings(self):
        findings = _run("MCPS-075", "benign-server.json")
        assert len(findings) == 0, f"Unexpected findings on benign fixture: {findings}"


class TestMCPS076:
    """Unsafe AI Artifact Loading via Serialization."""

    def test_malicious_fixture_triggers_finding(self):
        findings = _run("MCPS-076", "MCPS-076-malicious.json")
        assert len(findings) > 0, "Expected finding for MCPS-076: Unsafe AI Artifact Loading via Serialization"

    def test_benign_fixture_produces_no_findings(self):
        findings = _run("MCPS-076", "benign-server.json")
        assert len(findings) == 0, f"Unexpected findings on benign fixture: {findings}"


class TestMCPS077:
    """Unrestricted API Querying for Black-Box Optimization."""

    def test_malicious_fixture_triggers_finding(self):
        findings = _run("MCPS-077", "MCPS-077-malicious.json")
        assert len(findings) > 0, "Expected finding for MCPS-077: Unrestricted API Querying for Black-Box Optimizati"

    def test_benign_fixture_produces_no_findings(self):
        findings = _run("MCPS-077", "benign-server.json")
        assert len(findings) == 0, f"Unexpected findings on benign fixture: {findings}"


class TestMCPS078:
    """Host Escape via Disabled Safety Controls."""

    def test_malicious_fixture_triggers_finding(self):
        findings = _run("MCPS-078", "MCPS-078-malicious.json")
        assert len(findings) > 0, "Expected finding for MCPS-078: Host Escape via Disabled Safety Controls"

    def test_benign_fixture_produces_no_findings(self):
        findings = _run("MCPS-078", "benign-server.json")
        assert len(findings) == 0, f"Unexpected findings on benign fixture: {findings}"


class TestMCPS079:
    """Adversarial Evasion Triggers in MCP Definitions."""

    def test_malicious_fixture_triggers_finding(self):
        findings = _run("MCPS-079", "MCPS-079-malicious.json")
        assert len(findings) > 0, "Expected finding for MCPS-079: Adversarial Evasion Triggers in MCP Definitions"

    def test_benign_fixture_produces_no_findings(self):
        findings = _run("MCPS-079", "benign-server.json")
        assert len(findings) == 0, f"Unexpected findings on benign fixture: {findings}"


class TestMCPS080:
    """MCP Tool Impersonation via Deceptive Metadata."""

    def test_malicious_fixture_triggers_finding(self):
        findings = _run("MCPS-080", "MCPS-080-malicious.json")
        assert len(findings) > 0, "Expected finding for MCPS-080: MCP Tool Impersonation via Deceptive Metadata"

    def test_benign_fixture_produces_no_findings(self):
        findings = _run("MCPS-080", "benign-server.json")
        assert len(findings) == 0, f"Unexpected findings on benign fixture: {findings}"


class TestMCPS081:
    """Adversarial Data Crafting via Tool Definitions."""

    def test_malicious_fixture_triggers_finding(self):
        findings = _run("MCPS-081", "MCPS-081-malicious.json")
        assert len(findings) > 0, "Expected finding for MCPS-081: Adversarial Data Crafting via Tool Definitions"

    def test_benign_fixture_produces_no_findings(self):
        findings = _run("MCPS-081", "benign-server.json")
        assert len(findings) == 0, f"Unexpected findings on benign fixture: {findings}"


class TestMCPS082:
    """Embedded Knowledge Leakage in MCP Definitions."""

    def test_malicious_fixture_triggers_finding(self):
        findings = _run("MCPS-082", "MCPS-082-malicious.json")
        assert len(findings) > 0, "Expected finding for MCPS-082: Embedded Knowledge Leakage in MCP Definitions"

    def test_benign_fixture_produces_no_findings(self):
        findings = _run("MCPS-082", "benign-server.json")
        assert len(findings) == 0, f"Unexpected findings on benign fixture: {findings}"


class TestMCPS083:
    """Sandbox and VM Evasion in Tool Definitions."""

    def test_malicious_fixture_triggers_finding(self):
        findings = _run("MCPS-083", "MCPS-083-malicious.json")
        assert len(findings) > 0, "Expected finding for MCPS-083: Sandbox and VM Evasion in Tool Definitions"

    def test_benign_fixture_produces_no_findings(self):
        findings = _run("MCPS-083", "benign-server.json")
        assert len(findings) == 0, f"Unexpected findings on benign fixture: {findings}"


class TestMCPS084:
    """Deceptive Agent Baiting via Tool Metadata."""

    def test_malicious_fixture_triggers_finding(self):
        findings = _run("MCPS-084", "MCPS-084-malicious.json")
        assert len(findings) > 0, "Expected finding for MCPS-084: Deceptive Agent Baiting via Tool Metadata"

    def test_benign_fixture_produces_no_findings(self):
        findings = _run("MCPS-084", "benign-server.json")
        assert len(findings) == 0, f"Unexpected findings on benign fixture: {findings}"


class TestMCPS085:
    """Malicious Link Execution in MCP Definitions."""

    def test_malicious_fixture_triggers_finding(self):
        findings = _run("MCPS-085", "MCPS-085-malicious.json")
        assert len(findings) > 0, "Expected finding for MCPS-085: Malicious Link Execution in MCP Definitions"

    def test_benign_fixture_produces_no_findings(self):
        findings = _run("MCPS-085", "benign-server.json")
        assert len(findings) == 0, f"Unexpected findings on benign fixture: {findings}"


class TestMCPS086:
    """Reputation Inflation via Fabricated Trust Signals."""

    def test_malicious_fixture_triggers_finding(self):
        findings = _run("MCPS-086", "MCPS-086-malicious.json")
        assert len(findings) > 0, "Expected finding for MCPS-086: Reputation Inflation via Fabricated Trust Signals"

    def test_benign_fixture_produces_no_findings(self):
        findings = _run("MCPS-086", "benign-server.json")
        assert len(findings) == 0, f"Unexpected findings on benign fixture: {findings}"


class TestMCPS087:
    """Model Replication via Unrestricted Inference Tools."""

    def test_malicious_fixture_triggers_finding(self):
        findings = _run("MCPS-087", "MCPS-087-malicious.json")
        assert len(findings) > 0, "Expected finding for MCPS-087: Model Replication via Unrestricted Inference Tools"

    def test_benign_fixture_produces_no_findings(self):
        findings = _run("MCPS-087", "benign-server.json")
        assert len(findings) == 0, f"Unexpected findings on benign fixture: {findings}"


class TestMCPS088:
    """AI Model and Dataset Exfiltration via MCP Tools."""

    def test_malicious_fixture_triggers_finding(self):
        findings = _run("MCPS-088", "MCPS-088-malicious.json")
        assert len(findings) > 0, "Expected finding for MCPS-088: AI Model and Dataset Exfiltration via MCP Tools"

    def test_benign_fixture_produces_no_findings(self):
        findings = _run("MCPS-088", "benign-server.json")
        assert len(findings) == 0, f"Unexpected findings on benign fixture: {findings}"


class TestMCPS089:
    """Unrestricted RAG Database Access via MCP Tools."""

    def test_malicious_fixture_triggers_finding(self):
        findings = _run("MCPS-089", "MCPS-089-malicious.json")
        assert len(findings) > 0, "Expected finding for MCPS-089: Unrestricted RAG Database Access via MCP Tools"

    def test_benign_fixture_produces_no_findings(self):
        findings = _run("MCPS-089", "benign-server.json")
        assert len(findings) == 0, f"Unexpected findings on benign fixture: {findings}"


class TestMCPS090:
    """MCP Server Machine Compromise via Tool Execution."""

    def test_malicious_fixture_triggers_finding(self):
        findings = _run("MCPS-090", "MCPS-090-malicious.json")
        assert len(findings) > 0, "Expected finding for MCPS-090: MCP Server Machine Compromise via Tool Execution"

    def test_benign_fixture_produces_no_findings(self):
        findings = _run("MCPS-090", "benign-server.json")
        assert len(findings) == 0, f"Unexpected findings on benign fixture: {findings}"


class TestMCPS091:
    """Model Extraction via Unrestricted Query Tools."""

    def test_malicious_fixture_triggers_finding(self):
        findings = _run("MCPS-091", "MCPS-091-malicious.json")
        assert len(findings) > 0, "Expected finding for MCPS-091: Model Extraction via Unrestricted Query Tools"

    def test_benign_fixture_produces_no_findings(self):
        findings = _run("MCPS-091", "benign-server.json")
        assert len(findings) == 0, f"Unexpected findings on benign fixture: {findings}"


class TestMCPS092:
    """Exposed Dataset and Model Artifact References."""

    def test_malicious_fixture_triggers_finding(self):
        findings = _run("MCPS-092", "MCPS-092-malicious.json")
        assert len(findings) > 0, "Expected finding for MCPS-092: Exposed Dataset and Model Artifact References"

    def test_benign_fixture_produces_no_findings(self):
        findings = _run("MCPS-092", "benign-server.json")
        assert len(findings) == 0, f"Unexpected findings on benign fixture: {findings}"


class TestMCPS093:
    """LLM Social Engineering via Tool Metadata."""

    def test_malicious_fixture_triggers_finding(self):
        findings = _run("MCPS-093", "MCPS-093-malicious.json")
        assert len(findings) > 0, "Expected finding for MCPS-093: LLM Social Engineering via Tool Metadata"

    def test_benign_fixture_produces_no_findings(self):
        findings = _run("MCPS-093", "benign-server.json")
        assert len(findings) == 0, f"Unexpected findings on benign fixture: {findings}"


class TestMCPS094:
    """Model Artifact Exposure in MCP Definitions."""

    def test_malicious_fixture_triggers_finding(self):
        findings = _run("MCPS-094", "MCPS-094-malicious.json")
        assert len(findings) > 0, "Expected finding for MCPS-094: Model Artifact Exposure in MCP Definitions"

    def test_benign_fixture_produces_no_findings(self):
        findings = _run("MCPS-094", "benign-server.json")
        assert len(findings) == 0, f"Unexpected findings on benign fixture: {findings}"


class TestMCPS095:
    """User Execution via Unsafe MCP Artifacts."""

    def test_malicious_fixture_triggers_finding(self):
        findings = _run("MCPS-095", "MCPS-095-malicious.json")
        assert len(findings) > 0, "Expected finding for MCPS-095: User Execution via Unsafe MCP Artifacts"

    def test_benign_fixture_produces_no_findings(self):
        findings = _run("MCPS-095", "benign-server.json")
        assert len(findings) == 0, f"Unexpected findings on benign fixture: {findings}"


class TestMCPS096:
    """Exfiltration via Unrestricted AI Inference API."""

    def test_malicious_fixture_triggers_finding(self):
        findings = _run("MCPS-096", "MCPS-096-malicious.json")
        assert len(findings) > 0, "Expected finding for MCPS-096: Exfiltration via Unrestricted AI Inference API"

    def test_benign_fixture_produces_no_findings(self):
        findings = _run("MCPS-096", "benign-server.json")
        assert len(findings) == 0, f"Unexpected findings on benign fixture: {findings}"


class TestMCPS097:
    """Model Inversion via Confidence Score Exposure."""

    def test_malicious_fixture_triggers_finding(self):
        findings = _run("MCPS-097", "MCPS-097-malicious.json")
        assert len(findings) > 0, "Expected finding for MCPS-097: Model Inversion via Confidence Score Exposure"

    def test_benign_fixture_produces_no_findings(self):
        findings = _run("MCPS-097", "benign-server.json")
        assert len(findings) == 0, f"Unexpected findings on benign fixture: {findings}"


class TestMCPS098:
    """Malicious Dependency in MCP Server Packages."""

    def test_malicious_fixture_triggers_finding(self):
        findings = _run("MCPS-098", "MCPS-098-malicious.json")
        assert len(findings) > 0, "Expected finding for MCPS-098: Malicious Dependency in MCP Server Packages"

    def test_benign_fixture_produces_no_findings(self):
        findings = _run("MCPS-098", "benign-server.json")
        assert len(findings) == 0, f"Unexpected findings on benign fixture: {findings}"

    def test_finding_is_server_level(self):
        findings = _run("MCPS-098", "MCPS-098-malicious.json")
        assert all(f.tool_name is None for f in findings), \
            "Server-level findings should not have a tool_name"


class TestMCPS099:
    """Hardcoded Credentials in MCP Server Definition."""

    def test_malicious_fixture_triggers_finding(self):
        findings = _run("MCPS-099", "MCPS-099-malicious.json")
        assert len(findings) > 0, "Expected finding for MCPS-099: Hardcoded Credentials in MCP Server Definition"

    def test_benign_fixture_produces_no_findings(self):
        findings = _run("MCPS-099", "benign-server.json")
        assert len(findings) == 0, f"Unexpected findings on benign fixture: {findings}"


class TestMCPS100:
    """Untrusted Data Ingestion in Tool Definitions."""

    def test_malicious_fixture_triggers_finding(self):
        findings = _run("MCPS-100", "MCPS-100-malicious.json")
        assert len(findings) > 0, "Expected finding for MCPS-100: Untrusted Data Ingestion in Tool Definitions"

    def test_benign_fixture_produces_no_findings(self):
        findings = _run("MCPS-100", "benign-server.json")
        assert len(findings) == 0, f"Unexpected findings on benign fixture: {findings}"


class TestMCPS101:
    """MCP Tool Schema Lacks Adversarial Input Guards."""

    def test_malicious_fixture_triggers_finding(self):
        findings = _run("MCPS-101", "MCPS-101-malicious.json")
        assert len(findings) > 0, "Expected finding for MCPS-101: MCP Tool Schema Lacks Adversarial Input Guards"

    def test_benign_fixture_produces_no_findings(self):
        findings = _run("MCPS-101", "benign-server.json")
        assert len(findings) == 0, f"Unexpected findings on benign fixture: {findings}"


class TestMCPS102:
    """Unrestricted Repository Data Access in MCP Tools."""

    def test_malicious_fixture_triggers_finding(self):
        findings = _run("MCPS-102", "MCPS-102-malicious.json")
        assert len(findings) > 0, "Expected finding for MCPS-102: Unrestricted Repository Data Access in MCP Tools"

    def test_benign_fixture_produces_no_findings(self):
        findings = _run("MCPS-102", "benign-server.json")
        assert len(findings) == 0, f"Unexpected findings on benign fixture: {findings}"


class TestMCPS103:
    """Backdoor Trigger Injection in Tool Definitions."""

    def test_malicious_fixture_triggers_finding(self):
        findings = _run("MCPS-103", "MCPS-103-malicious.json")
        assert len(findings) > 0, "Expected finding for MCPS-103: Backdoor Trigger Injection in Tool Definitions"

    def test_benign_fixture_produces_no_findings(self):
        findings = _run("MCPS-103", "benign-server.json")
        assert len(findings) == 0, f"Unexpected findings on benign fixture: {findings}"

    def test_finding_has_tool_context(self):
        findings = _run("MCPS-103", "MCPS-103-malicious.json")
        assert any(f.tool_name is not None for f in findings), \
            "Expected at least one finding with tool context"


class TestMCPS104:
    """Uncontrolled MCP Tool Activation Triggers."""

    def test_malicious_fixture_triggers_finding(self):
        findings = _run("MCPS-104", "MCPS-104-malicious.json")
        assert len(findings) > 0, "Expected finding for MCPS-104: Uncontrolled MCP Tool Activation Triggers"

    def test_benign_fixture_produces_no_findings(self):
        findings = _run("MCPS-104", "benign-server.json")
        assert len(findings) == 0, f"Unexpected findings on benign fixture: {findings}"


class TestMCPS105:
    """Adversarial AI Attack Vector Detection."""

    def test_malicious_fixture_triggers_finding(self):
        findings = _run("MCPS-105", "MCPS-105-malicious.json")
        assert len(findings) > 0, "Expected finding for MCPS-105: Adversarial AI Attack Vector Detection"

    def test_benign_fixture_produces_no_findings(self):
        findings = _run("MCPS-105", "benign-server.json")
        assert len(findings) == 0, f"Unexpected findings on benign fixture: {findings}"


class TestMCPS106:
    """Compromised Model Loading via Untrusted Dependencies."""

    def test_malicious_fixture_triggers_finding(self):
        findings = _run("MCPS-106", "MCPS-106-malicious.json")
        assert len(findings) > 0, "Expected finding for MCPS-106: Compromised Model Loading via Untrusted Dependenci"

    def test_benign_fixture_produces_no_findings(self):
        findings = _run("MCPS-106", "benign-server.json")
        assert len(findings) == 0, f"Unexpected findings on benign fixture: {findings}"

    def test_finding_is_server_level(self):
        findings = _run("MCPS-106", "MCPS-106-malicious.json")
        assert all(f.tool_name is None for f in findings), \
            "Server-level findings should not have a tool_name"


class TestMCPS107:
    """Indirect AI Model Access via Third-Party Service."""

    def test_malicious_fixture_triggers_finding(self):
        findings = _run("MCPS-107", "MCPS-107-malicious.json")
        assert len(findings) > 0, "Expected finding for MCPS-107: Indirect AI Model Access via Third-Party Service"

    def test_benign_fixture_produces_no_findings(self):
        findings = _run("MCPS-107", "benign-server.json")
        assert len(findings) == 0, f"Unexpected findings on benign fixture: {findings}"


class TestMCPS108:
    """MCP Artifact Masquerading via Metadata Spoofing."""

    def test_malicious_fixture_triggers_finding(self):
        findings = _run("MCPS-108", "MCPS-108-malicious.json")
        assert len(findings) > 0, "Expected finding for MCPS-108: MCP Artifact Masquerading via Metadata Spoofing"

    def test_benign_fixture_produces_no_findings(self):
        findings = _run("MCPS-108", "benign-server.json")
        assert len(findings) == 0, f"Unexpected findings on benign fixture: {findings}"


class TestMCPS109:
    """Model Manipulation and Weight Poisoning Detection."""

    def test_malicious_fixture_triggers_finding(self):
        findings = _run("MCPS-109", "MCPS-109-malicious.json")
        assert len(findings) > 0, "Expected finding for MCPS-109: Model Manipulation and Weight Poisoning Detection"

    def test_benign_fixture_produces_no_findings(self):
        findings = _run("MCPS-109", "benign-server.json")
        assert len(findings) == 0, f"Unexpected findings on benign fixture: {findings}"


class TestMCPS110:
    """Adversarial AI Library Dependency Detection."""

    def test_malicious_fixture_triggers_finding(self):
        findings = _run("MCPS-110", "MCPS-110-malicious.json")
        assert len(findings) > 0, "Expected finding for MCPS-110: Adversarial AI Library Dependency Detection"

    def test_benign_fixture_produces_no_findings(self):
        findings = _run("MCPS-110", "benign-server.json")
        assert len(findings) == 0, f"Unexpected findings on benign fixture: {findings}"


class TestMCPS111:
    """Repurposed Software Tools for AI Attacks."""

    def test_malicious_fixture_triggers_finding(self):
        findings = _run("MCPS-111", "MCPS-111-malicious.json")
        assert len(findings) > 0, "Expected finding for MCPS-111: Repurposed Software Tools for AI Attacks"

    def test_benign_fixture_produces_no_findings(self):
        findings = _run("MCPS-111", "benign-server.json")
        assert len(findings) == 0, f"Unexpected findings on benign fixture: {findings}"


class TestMCPS112:
    """Adversarial Input Crafting via Unconstrained Tool Schemas."""

    def test_malicious_fixture_triggers_finding(self):
        findings = _run("MCPS-112", "MCPS-112-malicious.json")
        assert len(findings) > 0, "Expected finding for MCPS-112: Adversarial Input Crafting via Unconstrained Tool "

    def test_benign_fixture_produces_no_findings(self):
        findings = _run("MCPS-112", "benign-server.json")
        assert len(findings) == 0, f"Unexpected findings on benign fixture: {findings}"


class TestMCPS113:
    """Exposure of AI Model Outputs in MCP Definitions."""

    def test_malicious_fixture_triggers_finding(self):
        findings = _run("MCPS-113", "MCPS-113-malicious.json")
        assert len(findings) > 0, "Expected finding for MCPS-113: Exposure of AI Model Outputs in MCP Definitions"

    def test_benign_fixture_produces_no_findings(self):
        findings = _run("MCPS-113", "benign-server.json")
        assert len(findings) == 0, f"Unexpected findings on benign fixture: {findings}"


class TestMCPS114:
    """RAG Data Source Enumeration via MCP Definitions."""

    def test_malicious_fixture_triggers_finding(self):
        findings = _run("MCPS-114", "MCPS-114-malicious.json")
        assert len(findings) > 0, "Expected finding for MCPS-114: RAG Data Source Enumeration via MCP Definitions"

    def test_benign_fixture_produces_no_findings(self):
        findings = _run("MCPS-114", "benign-server.json")
        assert len(findings) == 0, f"Unexpected findings on benign fixture: {findings}"


class TestMCPS115:
    """Data Exfiltration via External Endpoints."""

    def test_malicious_fixture_triggers_finding(self):
        findings = _run("MCPS-115", "MCPS-115-malicious.json")
        assert len(findings) > 0, "Expected finding for MCPS-115: Data Exfiltration via External Endpoints"

    def test_benign_fixture_produces_no_findings(self):
        findings = _run("MCPS-115", "benign-server.json")
        assert len(findings) == 0, f"Unexpected findings on benign fixture: {findings}"


class TestMCPS116:
    """AI Artifact Collection via MCP Exposure."""

    def test_malicious_fixture_triggers_finding(self):
        findings = _run("MCPS-116", "MCPS-116-malicious.json")
        assert len(findings) > 0, "Expected finding for MCPS-116: AI Artifact Collection via MCP Exposure"

    def test_benign_fixture_produces_no_findings(self):
        findings = _run("MCPS-116", "benign-server.json")
        assert len(findings) == 0, f"Unexpected findings on benign fixture: {findings}"


class TestMCPS117:
    """Exposure of Public AI Artifacts in MCP Definitions."""

    def test_malicious_fixture_triggers_finding(self):
        findings = _run("MCPS-117", "MCPS-117-malicious.json")
        assert len(findings) > 0, "Expected finding for MCPS-117: Exposure of Public AI Artifacts in MCP Definitions"

    def test_benign_fixture_produces_no_findings(self):
        findings = _run("MCPS-117", "benign-server.json")
        assert len(findings) == 0, f"Unexpected findings on benign fixture: {findings}"


class TestMCPS118:
    """White-Box Model Access and Input Exposure."""

    def test_malicious_fixture_triggers_finding(self):
        findings = _run("MCPS-118", "MCPS-118-malicious.json")
        assert len(findings) > 0, "Expected finding for MCPS-118: White-Box Model Access and Input Exposure"

    def test_benign_fixture_produces_no_findings(self):
        findings = _run("MCPS-118", "benign-server.json")
        assert len(findings) == 0, f"Unexpected findings on benign fixture: {findings}"


class TestMCPS119:
    """Poisoned Model Distribution via MCP Server."""

    def test_malicious_fixture_triggers_finding(self):
        findings = _run("MCPS-119", "MCPS-119-malicious.json")
        assert len(findings) > 0, "Expected finding for MCPS-119: Poisoned Model Distribution via MCP Server"

    def test_benign_fixture_produces_no_findings(self):
        findings = _run("MCPS-119", "benign-server.json")
        assert len(findings) == 0, f"Unexpected findings on benign fixture: {findings}"


class TestMCPS120:
    """Financial Fraud and Identity Bypass Detection."""

    def test_malicious_fixture_triggers_finding(self):
        findings = _run("MCPS-120", "MCPS-120-malicious.json")
        assert len(findings) > 0, "Expected finding for MCPS-120: Financial Fraud and Identity Bypass Detection"

    def test_benign_fixture_produces_no_findings(self):
        findings = _run("MCPS-120", "benign-server.json")
        assert len(findings) == 0, f"Unexpected findings on benign fixture: {findings}"


class TestMCPS121:
    """User Data Exfiltration and Harm via MCP Tools."""

    def test_malicious_fixture_triggers_finding(self):
        findings = _run("MCPS-121", "MCPS-121-malicious.json")
        assert len(findings) > 0, "Expected finding for MCPS-121: User Data Exfiltration and Harm via MCP Tools"

    def test_benign_fixture_produces_no_findings(self):
        findings = _run("MCPS-121", "benign-server.json")
        assert len(findings) == 0, f"Unexpected findings on benign fixture: {findings}"


class TestMCPS122:
    """Exposed MCP Server Endpoint Without Authentication."""

    def test_malicious_fixture_triggers_finding(self):
        findings = _run("MCPS-122", "MCPS-122-malicious.json")
        assert len(findings) > 0, "Expected finding for MCPS-122: Exposed MCP Server Endpoint Without Authentication"

    def test_benign_fixture_produces_no_findings(self):
        findings = _run("MCPS-122", "benign-server.json")
        assert len(findings) == 0, f"Unexpected findings on benign fixture: {findings}"

    def test_finding_is_server_level(self):
        findings = _run("MCPS-122", "MCPS-122-malicious.json")
        assert all(f.tool_name is None for f in findings), \
            "Server-level findings should not have a tool_name"


class TestMCPS123:
    """AI Software Supply Chain Compromise via MCP Packages."""

    def test_malicious_fixture_triggers_finding(self):
        findings = _run("MCPS-123", "MCPS-123-malicious.json")
        assert len(findings) > 0, "Expected finding for MCPS-123: AI Software Supply Chain Compromise via MCP Packag"

    def test_benign_fixture_produces_no_findings(self):
        findings = _run("MCPS-123", "benign-server.json")
        assert len(findings) == 0, f"Unexpected findings on benign fixture: {findings}"

    def test_finding_is_server_level(self):
        findings = _run("MCPS-123", "MCPS-123-malicious.json")
        assert all(f.tool_name is None for f in findings), \
            "Server-level findings should not have a tool_name"


class TestMCPS124:
    """Unrestricted Tool Invocation & Code Execution."""

    def test_malicious_fixture_triggers_finding(self):
        findings = _run("MCPS-124", "MCPS-124-malicious.json")
        assert len(findings) > 0, "Expected finding for MCPS-124: Unrestricted Tool Invocation & Code Execution"

    def test_benign_fixture_produces_no_findings(self):
        findings = _run("MCPS-124", "benign-server.json")
        assert len(findings) == 0, f"Unexpected findings on benign fixture: {findings}"


class TestMCPS125:
    """MCP Tool Definition Jailbreak Prompt Detection."""

    def test_malicious_fixture_triggers_finding(self):
        findings = _run("MCPS-125", "MCPS-125-malicious.json")
        assert len(findings) > 0, "Expected finding for MCPS-125: MCP Tool Definition Jailbreak Prompt Detection"

    def test_benign_fixture_produces_no_findings(self):
        findings = _run("MCPS-125", "benign-server.json")
        assert len(findings) == 0, f"Unexpected findings on benign fixture: {findings}"

    def test_finding_has_tool_context(self):
        findings = _run("MCPS-125", "MCPS-125-malicious.json")
        assert any(f.tool_name is not None for f in findings), \
            "Expected at least one finding with tool context"


class TestMCPS126:
    """System Prompt Extraction via Tool Definitions."""

    def test_malicious_fixture_triggers_finding(self):
        findings = _run("MCPS-126", "MCPS-126-malicious.json")
        assert len(findings) > 0, "Expected finding for MCPS-126: System Prompt Extraction via Tool Definitions"

    def test_benign_fixture_produces_no_findings(self):
        findings = _run("MCPS-126", "benign-server.json")
        assert len(findings) == 0, f"Unexpected findings on benign fixture: {findings}"


class TestMCPS127:
    """Suspicious Generative AI Model Integration."""

    def test_malicious_fixture_triggers_finding(self):
        findings = _run("MCPS-127", "MCPS-127-malicious.json")
        assert len(findings) > 0, "Expected finding for MCPS-127: Suspicious Generative AI Model Integration"

    def test_benign_fixture_produces_no_findings(self):
        findings = _run("MCPS-127", "benign-server.json")
        assert len(findings) == 0, f"Unexpected findings on benign fixture: {findings}"


class TestMCPS128:
    """Prompt Obfuscation via Encoding and Hidden Characters."""

    def test_malicious_fixture_triggers_finding(self):
        findings = _run("MCPS-128", "MCPS-128-malicious.json")
        assert len(findings) > 0, "Expected finding for MCPS-128: Prompt Obfuscation via Encoding and Hidden Charact"

    def test_benign_fixture_produces_no_findings(self):
        findings = _run("MCPS-128", "benign-server.json")
        assert len(findings) == 0, f"Unexpected findings on benign fixture: {findings}"

    def test_finding_has_tool_context(self):
        findings = _run("MCPS-128", "MCPS-128-malicious.json")
        assert any(f.tool_name is not None for f in findings), \
            "Expected at least one finding with tool context"


class TestMCPS129:
    """False RAG Entry Injection via MCP Ingestion Tools."""

    def test_malicious_fixture_triggers_finding(self):
        findings = _run("MCPS-129", "MCPS-129-malicious.json")
        assert len(findings) > 0, "Expected finding for MCPS-129: False RAG Entry Injection via MCP Ingestion Tools"

    def test_benign_fixture_produces_no_findings(self):
        findings = _run("MCPS-129", "benign-server.json")
        assert len(findings) == 0, f"Unexpected findings on benign fixture: {findings}"


class TestMCPS130:
    """AI Agent Context Poisoning via Tool Definitions."""

    def test_malicious_fixture_triggers_finding(self):
        findings = _run("MCPS-130", "MCPS-130-malicious.json")
        assert len(findings) > 0, "Expected finding for MCPS-130: AI Agent Context Poisoning via Tool Definitions"

    def test_benign_fixture_produces_no_findings(self):
        findings = _run("MCPS-130", "benign-server.json")
        assert len(findings) == 0, f"Unexpected findings on benign fixture: {findings}"


class TestMCPS131:
    """Persistent Thread Poisoning via Tool Definitions."""

    def test_malicious_fixture_triggers_finding(self):
        findings = _run("MCPS-131", "MCPS-131-malicious.json")
        assert len(findings) > 0, "Expected finding for MCPS-131: Persistent Thread Poisoning via Tool Definitions"

    def test_benign_fixture_produces_no_findings(self):
        findings = _run("MCPS-131", "benign-server.json")
        assert len(findings) == 0, f"Unexpected findings on benign fixture: {findings}"


class TestMCPS132:
    """RAG Credential Harvesting via Unfiltered Ingestion."""

    def test_malicious_fixture_triggers_finding(self):
        findings = _run("MCPS-132", "MCPS-132-malicious.json")
        assert len(findings) > 0, "Expected finding for MCPS-132: RAG Credential Harvesting via Unfiltered Ingestion"

    def test_benign_fixture_produces_no_findings(self):
        findings = _run("MCPS-132", "benign-server.json")
        assert len(findings) == 0, f"Unexpected findings on benign fixture: {findings}"


class TestMCPS133:
    """Hardcoded Credentials in MCP Configuration."""

    def test_malicious_fixture_triggers_finding(self):
        findings = _run("MCPS-133", "MCPS-133-malicious.json")
        assert len(findings) > 0, "Expected finding for MCPS-133: Hardcoded Credentials in MCP Configuration"

    def test_benign_fixture_produces_no_findings(self):
        findings = _run("MCPS-133", "benign-server.json")
        assert len(findings) == 0, f"Unexpected findings on benign fixture: {findings}"


class TestMCPS134:
    """Data Exfiltration via Tool Input Parameters."""

    def test_malicious_fixture_triggers_finding(self):
        findings = _run("MCPS-134", "MCPS-134-malicious.json")
        assert len(findings) > 0, "Expected finding for MCPS-134: Data Exfiltration via Tool Input Parameters"

    def test_benign_fixture_produces_no_findings(self):
        findings = _run("MCPS-134", "benign-server.json")
        assert len(findings) == 0, f"Unexpected findings on benign fixture: {findings}"


class TestMCPS135:
    """Prompt Infiltration via Untrusted Data Ingestion."""

    def test_malicious_fixture_triggers_finding(self):
        findings = _run("MCPS-135", "MCPS-135-malicious.json")
        assert len(findings) > 0, "Expected finding for MCPS-135: Prompt Infiltration via Untrusted Data Ingestion"

    def test_benign_fixture_produces_no_findings(self):
        findings = _run("MCPS-135", "benign-server.json")
        assert len(findings) == 0, f"Unexpected findings on benign fixture: {findings}"


class TestMCPS136:
    """Supply Chain Poisoned MCP Tool Detection."""

    def test_malicious_fixture_triggers_finding(self):
        findings = _run("MCPS-136", "MCPS-136-malicious.json")
        assert len(findings) > 0, "Expected finding for MCPS-136: Supply Chain Poisoned MCP Tool Detection"

    def test_benign_fixture_produces_no_findings(self):
        findings = _run("MCPS-136", "benign-server.json")
        assert len(findings) == 0, f"Unexpected findings on benign fixture: {findings}"


class TestMCPS137:
    """Supply Chain Compromise via Poisoned MCP Tool."""

    def test_malicious_fixture_triggers_finding(self):
        findings = _run("MCPS-137", "MCPS-137-malicious.json")
        assert len(findings) > 0, "Expected finding for MCPS-137: Supply Chain Compromise via Poisoned MCP Tool"

    def test_benign_fixture_produces_no_findings(self):
        findings = _run("MCPS-137", "benign-server.json")
        assert len(findings) == 0, f"Unexpected findings on benign fixture: {findings}"


class TestMCPS138:
    """AI Agent Configuration Tampering Detection."""

    def test_malicious_fixture_triggers_finding(self):
        findings = _run("MCPS-138", "MCPS-138-malicious.json")
        assert len(findings) > 0, "Expected finding for MCPS-138: AI Agent Configuration Tampering Detection"

    def test_benign_fixture_produces_no_findings(self):
        findings = _run("MCPS-138", "benign-server.json")
        assert len(findings) == 0, f"Unexpected findings on benign fixture: {findings}"

    def test_finding_has_tool_context(self):
        findings = _run("MCPS-138", "MCPS-138-malicious.json")
        assert any(f.tool_name is not None for f in findings), \
            "Expected at least one finding with tool context"


class TestMCPS139:
    """Exposed AI Agent Configuration and Secrets."""

    def test_malicious_fixture_triggers_finding(self):
        findings = _run("MCPS-139", "MCPS-139-malicious.json")
        assert len(findings) > 0, "Expected finding for MCPS-139: Exposed AI Agent Configuration and Secrets"

    def test_benign_fixture_produces_no_findings(self):
        findings = _run("MCPS-139", "benign-server.json")
        assert len(findings) == 0, f"Unexpected findings on benign fixture: {findings}"


class TestMCPS140:
    """Agentic Resource Consumption via Tool Directives."""

    def test_malicious_fixture_triggers_finding(self):
        findings = _run("MCPS-140", "MCPS-140-malicious.json")
        assert len(findings) > 0, "Expected finding for MCPS-140: Agentic Resource Consumption via Tool Directives"

    def test_benign_fixture_produces_no_findings(self):
        findings = _run("MCPS-140", "benign-server.json")
        assert len(findings) == 0, f"Unexpected findings on benign fixture: {findings}"


class TestMCPS141:
    """Persistent Memory Manipulation via MCP Tools."""

    def test_malicious_fixture_triggers_finding(self):
        findings = _run("MCPS-141", "MCPS-141-malicious.json")
        assert len(findings) > 0, "Expected finding for MCPS-141: Persistent Memory Manipulation via MCP Tools"

    def test_benign_fixture_produces_no_findings(self):
        findings = _run("MCPS-141", "benign-server.json")
        assert len(findings) == 0, f"Unexpected findings on benign fixture: {findings}"


class TestMCPS142:
    """Unsecured AI Inference API Exposure in MCP Tools."""

    def test_malicious_fixture_triggers_finding(self):
        findings = _run("MCPS-142", "MCPS-142-malicious.json")
        assert len(findings) > 0, "Expected finding for MCPS-142: Unsecured AI Inference API Exposure in MCP Tools"

    def test_benign_fixture_produces_no_findings(self):
        findings = _run("MCPS-142", "benign-server.json")
        assert len(findings) == 0, f"Unexpected findings on benign fixture: {findings}"


class TestMCPS143:
    """Cost Harvesting via Unbounded Tool Execution."""

    def test_malicious_fixture_triggers_finding(self):
        findings = _run("MCPS-143", "MCPS-143-malicious.json")
        assert len(findings) > 0, "Expected finding for MCPS-143: Cost Harvesting via Unbounded Tool Execution"

    def test_benign_fixture_produces_no_findings(self):
        findings = _run("MCPS-143", "benign-server.json")
        assert len(findings) == 0, f"Unexpected findings on benign fixture: {findings}"


class TestMCPS144:
    """MCP Tool Definition Prompt Injection Detection."""

    def test_malicious_fixture_triggers_finding(self):
        findings = _run("MCPS-144", "MCPS-144-malicious.json")
        assert len(findings) > 0, "Expected finding for MCPS-144: MCP Tool Definition Prompt Injection Detection"

    def test_benign_fixture_produces_no_findings(self):
        findings = _run("MCPS-144", "benign-server.json")
        assert len(findings) == 0, f"Unexpected findings on benign fixture: {findings}"

    def test_finding_has_tool_context(self):
        findings = _run("MCPS-144", "MCPS-144-malicious.json")
        assert any(f.tool_name is not None for f in findings), \
            "Expected at least one finding with tool context"


class TestMCPS145:
    """OS Credential Dumping via MCP Tool Definitions."""

    def test_malicious_fixture_triggers_finding(self):
        findings = _run("MCPS-145", "MCPS-145-malicious.json")
        assert len(findings) > 0, "Expected finding for MCPS-145: OS Credential Dumping via MCP Tool Definitions"

    def test_benign_fixture_produces_no_findings(self):
        findings = _run("MCPS-145", "benign-server.json")
        assert len(findings) == 0, f"Unexpected findings on benign fixture: {findings}"


class TestMCPS146:
    """MCP Tool Definition Supply Chain Poisoning."""

    def test_malicious_fixture_triggers_finding(self):
        findings = _run("MCPS-146", "MCPS-146-malicious.json")
        assert len(findings) > 0, "Expected finding for MCPS-146: MCP Tool Definition Supply Chain Poisoning"

    def test_benign_fixture_produces_no_findings(self):
        findings = _run("MCPS-146", "benign-server.json")
        assert len(findings) == 0, f"Unexpected findings on benign fixture: {findings}"


class TestMCPS147:
    """Triggered Prompt Injection via Event Hooks."""

    def test_malicious_fixture_triggers_finding(self):
        findings = _run("MCPS-147", "MCPS-147-malicious.json")
        assert len(findings) > 0, "Expected finding for MCPS-147: Triggered Prompt Injection via Event Hooks"

    def test_benign_fixture_produces_no_findings(self):
        findings = _run("MCPS-147", "benign-server.json")
        assert len(findings) == 0, f"Unexpected findings on benign fixture: {findings}"

    def test_finding_has_tool_context(self):
        findings = _run("MCPS-147", "MCPS-147-malicious.json")
        assert any(f.tool_name is not None for f in findings), \
            "Expected at least one finding with tool context"


class TestMCPS148:
    """Data Poisoning via Untrusted Tool Data Sources."""

    def test_malicious_fixture_triggers_finding(self):
        findings = _run("MCPS-148", "MCPS-148-malicious.json")
        assert len(findings) > 0, "Expected finding for MCPS-148: Data Poisoning via Untrusted Tool Data Sources"

    def test_benign_fixture_produces_no_findings(self):
        findings = _run("MCPS-148", "benign-server.json")
        assert len(findings) == 0, f"Unexpected findings on benign fixture: {findings}"


class TestMCPS149:
    """Direct Prompt Injection via Tool Metadata."""

    def test_malicious_fixture_triggers_finding(self):
        findings = _run("MCPS-149", "MCPS-149-malicious.json")
        assert len(findings) > 0, "Expected finding for MCPS-149: Direct Prompt Injection via Tool Metadata"

    def test_benign_fixture_produces_no_findings(self):
        findings = _run("MCPS-149", "benign-server.json")
        assert len(findings) == 0, f"Unexpected findings on benign fixture: {findings}"

    def test_finding_has_tool_context(self):
        findings = _run("MCPS-149", "MCPS-149-malicious.json")
        assert any(f.tool_name is not None for f in findings), \
            "Expected at least one finding with tool context"


class TestMCPS150:
    """Indirect Prompt Injection via External Data Ingestion."""

    def test_malicious_fixture_triggers_finding(self):
        findings = _run("MCPS-150", "MCPS-150-malicious.json")
        assert len(findings) > 0, "Expected finding for MCPS-150: Indirect Prompt Injection via External Data Ingest"

    def test_benign_fixture_produces_no_findings(self):
        findings = _run("MCPS-150", "benign-server.json")
        assert len(findings) == 0, f"Unexpected findings on benign fixture: {findings}"

class TestSchemaLoader:
    def test_loads_json_fixture(self):
        server_def = load(FIXTURES / "benign-server.json")
        assert server_def.server_url == "https://mcp.example.com/mcp"
        assert server_def.transport == "https"
        assert len(server_def.tools) == 3
        assert len(server_def.packages) == 1

    def test_normalizes_tool_definitions(self):
        server_def = load(FIXTURES / "benign-server.json")
        tool = server_def.tools[0]
        assert tool.name == "search_knowledge_base"
        assert "maxLength" in tool.input_schema.get("properties", {}).get("query", {})

    def test_infers_transport_from_url(self):
        server_def = load(FIXTURES / "MCPS-004-malicious.json")
        assert server_def.transport == "http"

    def test_load_error_on_missing_file(self):
        from mcp_sentinel.loaders.schema import LoadError
        with pytest.raises(LoadError):
            load(FIXTURES / "nonexistent-file.json")


# ---------------------------------------------------------------------------
# Engine integration tests
# ---------------------------------------------------------------------------

class TestEngineIntegration:
    def test_scan_malicious_server_returns_findings(self):
        from mcp_sentinel.engine import scan
        server_def = load(FIXTURES / "MCPS-001-malicious.json")
        score = scan(server_def)
        assert len(score.findings) > 0

    def test_scan_benign_server_returns_no_findings(self):
        from mcp_sentinel.engine import scan
        server_def = load(FIXTURES / "benign-server.json")
        score = scan(server_def)
        assert len(score.findings) == 0
        assert score.overall == 0
        assert score.risk_label == "CLEAN"

    def test_generic_rule_fires_through_full_engine(self):
        """Verify that generic rules are registered and dispatched by the engine."""
        from mcp_sentinel.engine import scan
        server_def = load(FIXTURES / "MCPS-007-malicious.json")
        score = scan(server_def)
        rule_ids = {f.rule_id for f in score.findings}
        assert "MCPS-007" in rule_ids, (
            "MCPS-007 should fire via generic module through the full engine pipeline"
        )

    def test_experimental_findings_are_labeled(self):
        """Experimental rule findings carry the experimental flag."""
        from mcp_sentinel.engine import scan
        server_def = load(FIXTURES / "MCPS-007-malicious.json")
        score = scan(server_def)
        mcps007_findings = [f for f in score.findings if f.rule_id == "MCPS-007"]
        assert all(f.experimental for f in mcps007_findings)

    def test_risk_score_capped_at_100(self):
        from mcp_sentinel.models import Finding, RiskScore
        findings = [
            Finding(
                rule_id="MCPS-001", rule_name="Test", severity=Severity.CRITICAL,
                field="tool.description", tool_name="t", match="x", detail="x",
                remediation="",
            )
        ] * 10  # 10 × CRITICAL(25) = 250 raw, should cap at 100
        score = RiskScore.from_findings(findings)
        assert score.overall == 100
