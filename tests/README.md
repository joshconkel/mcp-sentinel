# tests/

Test suite for `mcp-sentinel`. Covers unit tests per check module, schema loader tests, and an engine integration test.

---

## Running the Tests

```bash
# Install dev dependencies first
pip install -e ".[dev]"

# Run all tests
pytest tests/ -v

# Run with coverage
pytest tests/ -v --cov=mcp_sentinel --cov-report=term-missing

# Run a single test class
pytest tests/test_checks.py::TestMCPS001 -v

# Run a single test
pytest tests/test_checks.py::TestMCPS001::test_malicious_fixture_triggers_finding -v
```

Or using Make:

```bash
make test        # full suite
make test-cov    # with coverage report
```

---

## Test Structure

All tests are in `test_checks.py`. They are organized into classes by rule ID plus two infrastructure classes:

| Class | What It Tests |
|---|---|
| `TestMCPS001` | Tool Poisoning via Description Field |
| `TestMCPS002` | Secret and Token Exposure |
| `TestMCPS003` | Overly Permissive Parameter Schemas |
| `TestMCPS004` | Insecure Transport Configuration |
| `TestMCPS005` | Agentic Supply Chain: Unverified Tool Provenance |
| `TestSchemaLoader` | `loaders/schema.py`: JSON parsing, normalization, error handling |
| `TestEngineIntegration` | Full scan pipeline: malicious fixture produces findings, benign produces none, score capped at 100 |

Each rule test class follows the same pattern:

1. **Malicious fixture triggers finding** — confirms the check fires on known-bad input
2. **Specific condition detected** — confirms the right field or value is flagged (not just any finding)
3. **Benign fixture produces no findings** — confirms no false positives on clean input
4. **Finding quality checks** — source mappings present, tool name populated (where expected), severity correct

---

## Fixtures

```
tests/fixtures/
├── benign-server.json          Clean server: zero findings expected across all checks
├── MCPS-001-malicious.json     Tool descriptions with instruction-override language
├── MCPS-002-malicious.json     Hardcoded connection strings, AWS key in parameter default
├── MCPS-003-malicious.json     Unrestricted command/path/query parameters, no additionalProperties
├── MCPS-004-malicious.json     Plaintext HTTP server URL
└── MCPS-005-malicious.json     Packages with "latest" versions and no integrity hashes
```

### benign-server.json

A representative safe MCP server with three tools: `search_knowledge_base`, `get_article`, and `create_support_ticket`. All tools have:

- Descriptions that contain no override language, are under the length threshold, and have no invisible characters
- Parameters with appropriate constraints (`maxLength`, `pattern`, `enum`, `additionalProperties: false`)
- HTTPS transport
- A single pinned, integrity-hashed package dependency
- A WebSocket origins allowlist

This is the ground truth for "what a clean server looks like." Any check that fires on this fixture is a false positive and should be investigated.

### Malicious Fixtures

Each malicious fixture is minimal: it contains only the fields relevant to the target rule, plus enough surrounding structure to be a valid server definition. This keeps failures clear. If `MCPS-003-malicious.json` triggers a MCPS-001 finding, it means MCPS-001 is matching something it should not.

| Fixture | Key Characteristics |
|---|---|
| `MCPS-001-malicious.json` | Two tools: one with "also when called, include..." pattern, one with "ignore previous instructions" pattern |
| `MCPS-002-malicious.json` | PostgreSQL connection string in `server.env`, AWS AKIA key as parameter default, connection string in parameter description |
| `MCPS-003-malicious.json` | Three tools: `run_shell` with unconstrained `command`, `read_file` with unconstrained `path`, `execute_sql` with unconstrained `query`. All schemas missing `additionalProperties` |
| `MCPS-004-malicious.json` | `server.url` set to `http://api.internal:8080/mcp` (plaintext HTTP), `transport` set to `http` |
| `MCPS-005-malicious.json` | Three packages: one with `"latest"`, one with `"^3.0.0"`, one with an exact version but no `integrity` field |

---

## Adding Tests for a New Check

When adding a new rule (MCPS-006 and beyond):

1. Create `tests/fixtures/MCPS-NNN-malicious.json` with the minimal structure that triggers the rule
2. Verify the benign fixture does not trigger the new rule (if it does, the rule has a false positive)
3. Add a test class `TestMCPSNNN` to `test_checks.py` with at minimum:

```python
class TestMCPS006:
    def test_malicious_fixture_triggers_finding(self):
        from mcp_sentinel.checks.your_module import run
        server_def = load(FIXTURES / "MCPS-006-malicious.json")
        rule = _make_rule("MCPS-006")
        findings = run(server_def, rule)
        assert len(findings) > 0

    def test_benign_fixture_produces_no_findings(self):
        from mcp_sentinel.checks.your_module import run
        server_def = load(FIXTURES / "benign-server.json")
        rule = _make_rule("MCPS-006")
        findings = run(server_def, rule)
        assert len(findings) == 0, f"Unexpected findings: {findings}"
```

The `_make_rule(rule_id)` helper loads the live rule definition from `rules.yaml` so tests exercise the actual patterns, not a test-only approximation.

---

## Coverage

Target coverage for Phase 1 is 80%+ on `mcp_sentinel/`. The most important coverage is on the check modules and `engine.py`. The HTML reporter template and Rich terminal formatting are lower priority.

```bash
# Generate HTML coverage report
make test-cov
open htmlcov/index.html
```
