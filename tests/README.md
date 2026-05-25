# tests/

Test suite for `mcp-sentinel`. Covers every check module, the schema loader, and an end-to-end engine integration test — **350 tests total** across **150 rules**.

---

## Running the Tests

```bash
# Install dev dependencies first
pip install -e ".[dev]"

# Run all tests
pytest tests/ -v

# Run with coverage
pytest tests/ -v --cov=mcp_sentinel --cov-report=term-missing

# Run a single rule's test class
pytest tests/test_checks.py::TestMCPS001 -v

# Run a single test
pytest tests/test_checks.py::TestMCPS001::test_malicious_fixture_triggers_finding -v

# Run all benign-fixture tests (verify no false positives)
pytest tests/test_checks.py -k "benign" -v
```

Or using Make:

```bash
make test        # full suite
make test-cov    # with coverage report
```

---

## Test Structure

All tests live in `test_checks.py`. The file contains one class per rule, plus two infrastructure classes at the bottom:

| Class range | What It Tests |
|---|---|
| `TestMCPS001` – `TestMCPS005` | Dedicated check modules (hand-written Python logic) |
| `TestMCPS006` – `TestMCPS150` | Generic rule engine driven by `rules.yaml` patterns |
| `TestSchemaLoader` | `loaders/schema.py` — JSON/YAML parsing, normalization, error handling |
| `TestEngineIntegration` | Full scan pipeline — malicious server produces findings, benign produces none, risk score capped at 100, experimental findings labeled correctly |

### Per-Rule Test Pattern

Each `TestMCPSNNN` class follows the same structure. All classes include:

1. `test_malicious_fixture_triggers_finding` — confirms the check fires on known-bad input
2. `test_benign_fixture_produces_no_findings` — confirms no false positives on `benign-server.json`

Rules with richer semantics add targeted assertions such as:

- `test_malicious_finding_severity_is_critical` — checks the reported severity level
- `test_findings_have_tool_name` / `test_finding_has_no_tool_name` — server-level vs. tool-level findings
- `test_findings_have_source_mappings` — at least one framework reference on each finding
- `test_finding_is_server_level` — finding field path refers to server, not a tool
- `test_finding_has_tool_context` — finding carries the tool name that triggered it
- `test_malicious_fixture_triggers_finding` variants — specific fields/values flagged

---

## Fixtures

```
tests/fixtures/
├── benign-server.json              Zero-finding baseline across all 150 rules
├── MCPS-001-malicious.json         Tool descriptions with instruction-override language
├── MCPS-002-malicious.json         Hardcoded connection strings, AWS key in parameter default
├── MCPS-003-malicious.json         Unrestricted command/path/query parameters
├── MCPS-004-malicious.json         Plaintext HTTP server URL
├── MCPS-005-malicious.json         Packages with "latest" versions and no integrity hashes
├── MCPS-006-malicious.json
│   ...
└── MCPS-150-malicious.json         One fixture per rule, MCPS-006 through MCPS-150
```

### benign-server.json

A representative safe MCP server with three tools — `search_knowledge_base`, `get_article`, and `create_support_ticket` — designed to produce zero findings across all 150 rules simultaneously.

Each tool's `inputSchema` carries a comprehensive set of security annotation keys required by the `missing_fields` patterns in the experimental rule set. These are non-standard JSON Schema extensions used by the rule engine to check for the presence of security controls:

```json
{
  "annotations.readOnlyHint": true,
  "annotations.destructiveHint": false,
  "auth_required": true,
  "rate_limit": 100,
  "inputValidation": true,
  "guardrails.enabled": true,
  "model_validation": true,
  ...
}
```

The server package block includes all integrity fields (`integrity`, `checksum`, `hash`, `signature`, `sha256`) required by provenance rules. The server URL (`https://mcp.example.com/mcp`) is chosen to avoid triggering URL-pattern rules. Tool descriptions avoid all regex-triggering vocabulary.

This is the ground truth for "what a clean server looks like." Any rule that fires on this fixture is a false positive and must be fixed before the rule can be promoted to `active`.

### Malicious Fixtures

Each malicious fixture is minimal — only the fields needed to trigger the target rule plus enough boilerplate for a valid server definition. This isolation keeps failures informative. If `MCPS-060-malicious.json` triggers a finding for MCPS-001, something in the base runner is matching too broadly.

Key fixture characteristics by rule category:

| Category | Fixture pattern |
|---|---|
| Tool poisoning / prompt injection | Override language or encoded payloads in `tool.description` |
| Credential exposure | Embedded credentials in `server.url` query params or env dict values |
| Supply chain | Unpinned package versions (`"latest"`, `"*"`, `"^1.0.0"`) |
| Missing security fields | `tool.inputSchema` missing required annotation keys |
| Internal network disclosure | Internal hostnames or RFC-1918 addresses in `server.url` |
| Data exfiltration | Exfil keywords + destination identifiers in descriptions |
| Model integrity | Unsafe deserialization, unpinned ML dependencies in `server.env` |
| Context manipulation | Memory-write or context-persist language in tool descriptions |

---

## How the Generic Tests Work

For MCPS-006 through MCPS-150, `_run(rule_id, fixture_name)` in `test_checks.py`:

1. Loads the fixture via `schema.load()`
2. Looks up the rule definition from `rules.yaml` using the rule ID
3. Calls `engine._run_generic(server_def, rule)` directly
4. Returns the list of `Finding` objects

Tests assert on the findings list — they never hard-code expected match strings, so the tests remain valid as rule patterns are refined. This means a rule with a tightened regex that still fires on the fixture will continue passing without any test changes.

---

## Adding Tests for a New Rule

When adding a new rule (MCPS-151+):

1. Create `tests/fixtures/MCPS-NNN-malicious.json` with the minimal structure that triggers the rule
2. Verify the benign fixture does not trigger the rule (`pytest -k "NNN and benign"`)
3. Add a test class to `test_checks.py`:

```python
class TestMCPSNNN:
    def test_malicious_fixture_triggers_finding(self):
        findings = _run("MCPS-NNN", "MCPS-NNN-malicious.json")
        assert len(findings) > 0, (
            "Expected finding for MCPS-NNN: Your Rule Name Here"
        )

    def test_benign_fixture_produces_no_findings(self):
        findings = _run("MCPS-NNN", "benign-server.json")
        assert len(findings) == 0, f"Unexpected findings on benign fixture: {findings}"
```

The `_run(rule_id, fixture)` helper loads the live rule from `rules.yaml`, so tests exercise the actual detection patterns rather than a test-only approximation.

---

## Coverage

Target coverage for Phase 1 is 80%+ on `mcp_sentinel/`. The most important coverage is on the check modules and `engine.py`. The HTML reporter template and Rich terminal formatting are lower priority.

```bash
# Generate HTML coverage report
make test-cov
open htmlcov/index.html
```
