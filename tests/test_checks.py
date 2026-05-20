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


@pytest.mark.xfail(
    reason="Requires base.py schema_analysis compile fix: "
           "CheckRunner.__init__ must read condition.field_name_matches.regex "
           "instead of pattern.expression for schema_analysis patterns.",
    strict=True,
)
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


@pytest.mark.xfail(
    reason="Requires base.py schema_analysis compile fix: "
           "CheckRunner.__init__ must read condition.field_name_matches.regex "
           "instead of pattern.expression for schema_analysis patterns.",
    strict=True,
)
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


@pytest.mark.xfail(
    reason="Requires base.py schema_analysis compile fix: "
           "CheckRunner.__init__ must read condition.field_name_matches.regex "
           "instead of pattern.expression for schema_analysis patterns.",
    strict=True,
)
class TestMCPS018:
    """Numeric Parameter Without Range Constraints."""

    def test_malicious_fixture_triggers_finding(self):
        findings = _run("MCPS-018", "MCPS-018-malicious.json")
        assert len(findings) > 0, "Expected finding: unbounded numeric parameter"

    def test_benign_fixture_produces_no_findings(self):
        findings = _run("MCPS-018", "benign-server.json")
        assert len(findings) == 0, f"Unexpected findings: {findings}"


@pytest.mark.xfail(
    reason="Requires base.py schema_analysis compile fix: "
           "CheckRunner.__init__ must read condition.field_name_matches.regex "
           "instead of pattern.expression for schema_analysis patterns.",
    strict=True,
)
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

class TestSchemaLoader:
    def test_loads_json_fixture(self):
        server_def = load(FIXTURES / "benign-server.json")
        assert server_def.server_url == "https://api.example.com/mcp"
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
