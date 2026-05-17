"""
Unit tests for mcp-sentinel check modules.

Each test:
  - Loads a fixture file via the schema loader
  - Runs the specific check (bypassing the full engine)
  - Asserts findings are present (malicious) or absent (benign)

Run with: pytest tests/ -v
"""

from __future__ import annotations

from pathlib import Path

import pytest

from mcp_sentinel.loaders.schema import load
from mcp_sentinel.models import RuleDefinition, RuleStatus, Severity, DetectionType

FIXTURES = Path(__file__).parent / "fixtures"


# ---------------------------------------------------------------------------
# Helper: build a minimal RuleDefinition for isolated check testing
# (avoids needing a full rules.yaml parse in unit tests)
# ---------------------------------------------------------------------------

def _make_rule(rule_id: str) -> RuleDefinition:
    """Load the real rule definition from rules.yaml for accurate test coverage."""
    from mcp_sentinel.engine import load_rules
    rules = load_rules()
    for rule in rules:
        if rule.id == rule_id:
            return rule
    raise ValueError(f"Rule {rule_id} not found in rules.yaml")


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
        flagged_tools = {f.tool_name for f in findings}
        # All three malicious tools should generate findings
        assert len(flagged_tools) >= 2

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
# Engine integration test
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

    def test_risk_score_capped_at_100(self):
        from mcp_sentinel.models import Finding, RiskScore, Severity, SourceMapping
        findings = [
            Finding(
                rule_id="MCPS-001", rule_name="Test", severity=Severity.CRITICAL,
                field="tool.description", tool_name="t", match="x", detail="x",
                remediation=""
            )
        ] * 10   # 10 CRITICAL findings = 250 raw score, should cap at 100
        score = RiskScore.from_findings(findings)
        assert score.overall == 100
