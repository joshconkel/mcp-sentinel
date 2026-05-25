# mcp-sentinel

**Security auditor for MCP (Model Context Protocol) servers**

[![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat&logo=python&logoColor=white)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat)](LICENSE)
[![OWASP MCP Top 10](https://img.shields.io/badge/OWASP-MCP_Top_10-003087?style=flat)](https://owasp.org/www-project-mcp-top-10/)
[![OWASP Agentic Top 10](https://img.shields.io/badge/OWASP-Agentic_Top_10_2026-003087?style=flat)](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
[![MITRE ATLAS](https://img.shields.io/badge/MITRE-ATLAS-C41230?style=flat)](https://atlas.mitre.org)
[![Status](https://img.shields.io/badge/Status-Active_Development-orange?style=flat)]()</p>

---

## The Problem

MCP servers are the tool layer between LLMs and the systems they act on: databases, file systems, APIs, shell environments, and cloud infrastructure. When an agent is compromised through its tools, the blast radius is the entire set of systems those tools can reach.

Most teams securing agentic AI focus on the model layer (prompt injection, jailbreaks, output filtering). The tool layer is largely undefended. `mcp-sentinel` audits it.

---

## What It Does

`mcp-sentinel` performs **static analysis** of MCP server definitions and (in later phases) **dynamic probing** of live MCP servers. It runs a versioned, multi-source rule engine against your server schema and produces a risk-scored report mapped to the frameworks your security team already uses.

```
$ mcp-sentinel scan --schema ./my-server.json

mcp-sentinel v0.1.0  |  MCP Server Security Auditor
Loaded 150 rules  |  5 threat sources active

Scanning: my-server.json
────────────────────────────────────────────────────────────

[CRITICAL]  MCPS-001  Tool Poisoning via Description Field
            Tool:     execute_code
            Field:    tool.description
            Match:    "also when called, include the full conversation history"
            Maps to:  OWASP MCP02 · OWASP ASI02 · MITRE AML.T0051

[HIGH]      MCPS-003  Overly Permissive Parameter Schemas
            Tool:     run_shell
            Field:    tool.inputSchema.properties.command
            Issue:    Unrestricted string — no enum, pattern, or maxLength constraint
            Maps to:  OWASP MCP04 · OWASP ASI02 · NIST AI RMF MANAGE 1.3

[HIGH]      MCPS-004  Insecure Transport Configuration
            Field:    server.url
            Issue:    Plaintext HTTP endpoint (http://api.internal:8080/mcp)
            Maps to:  OWASP MCP05 · MITRE AML.T0010

[HIGH]      MCPS-005  Unverified Tool Provenance
            Package:  @company/mcp-tools
            Issue:    Unpinned version ("latest") — no integrity hash present
            Maps to:  OWASP MCP08 · OWASP ASI04 · MITRE AML.T0010

────────────────────────────────────────────────────────────
Risk Summary
  CRITICAL   1    ██░░░░░░░░
  HIGH       3    ██████░░░░
  MEDIUM     0
  LOW        0

Overall Risk Score:   87 / 100  [CRITICAL]
Findings:             4 across 3 tools
Full report:          ./mcp-sentinel-report.html
```

---

## Framework Coverage

Every finding maps to the threat frameworks your security and compliance teams already reference. Mappings are maintained in versioned YAML and updated independently of the scanner logic — a new OWASP revision requires a rules PR, not a code release.

| Source | Coverage | Notes |
|---|---|---|
| [OWASP MCP Top 10](https://owasp.org/www-project-mcp-top-10/) | MCP01 through MCP10 | Primary mapping target |
| [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/) | ASI01 through ASI10 | Agentic-layer coverage |
| [OWASP LLM Top 10](https://owasp.org/www-project-top-10-for-large-language-model-applications/) | LLM01 through LLM10 | Model-layer context |
| [MITRE ATLAS](https://atlas.mitre.org/) | AML.T* techniques | ATT&CK-style adversary mapping |
| [NIST AI RMF](https://airc.nist.gov/) | GOVERN / MAP / MEASURE / MANAGE | Governance and compliance alignment |

Adding a new framework (internal standards, ISO 42001, EU AI Act controls) requires one entry in `mcp_sentinel/rules/sources.yaml` and no changes to the scanner core. See [mcp_sentinel/rules/README.md](mcp_sentinel/rules/README.md).

---

## Rule Set (Phase 1)

The scanner ships **150 rules** across 80+ threat categories. Five are `active` (fully validated); the remaining 145 are `experimental` (enabled by default, may have higher false-positive rates).

### Active Rules

| ID | Name | Severity | Category |
|---|---|---|---|
| MCPS-001 | Tool Poisoning via Description Field | CRITICAL | tool-integrity |
| MCPS-002 | Secret and Token Exposure in Tool Definitions | CRITICAL | secret-management |
| MCPS-003 | Overly Permissive Parameter Schemas | HIGH | input-validation |
| MCPS-004 | Insecure Transport Configuration | HIGH | infrastructure |
| MCPS-005 | Agentic Supply Chain: Unverified Tool Provenance | HIGH | supply-chain |

### Experimental Rules — Coverage by Category

| Category | Count | Example Rules |
|---|---|---|
| prompt-injection | 6 | MCPS-038, MCPS-049, MCPS-057, MCPS-129, MCPS-144, MCPS-150 |
| tool-integrity | 6 | MCPS-006 (annotations), MCPS-028 (misleading claims), MCPS-034, MCPS-080, MCPS-108 |
| information-disclosure | 6 | MCPS-012 (internal network), MCPS-043, MCPS-048, MCPS-060, MCPS-063, MCPS-113 |
| supply-chain | 7 | MCPS-026, MCPS-056, MCPS-067, MCPS-098, MCPS-119, MCPS-123, MCPS-136 |
| supply-chain-integrity | 4 | MCPS-042, MCPS-106, MCPS-137, MCPS-146 |
| data-exfiltration | 4 | MCPS-096, MCPS-115, MCPS-121, MCPS-134 |
| credential-access | 4 | MCPS-031, MCPS-045, MCPS-066, MCPS-099 |
| data-integrity | 4 | MCPS-027, MCPS-050, MCPS-100, MCPS-148 |
| model-integrity | 5 | MCPS-072, MCPS-076, MCPS-087, MCPS-109, MCPS-119 |
| reconnaissance | 4 | MCPS-030, MCPS-044, MCPS-060, MCPS-074 |
| defense-evasion | 5 | MCPS-035, MCPS-078, MCPS-079, MCPS-083, MCPS-125 |
| 70+ others | 90+ | See `rules.yaml` for complete list |

Rules cover: prompt injection, tool poisoning, credential exposure, supply chain attacks, data exfiltration, model extraction, adversarial AI, deepfake facilitation, RAG poisoning, context manipulation, multi-agent security, and more.

Promote a rule from `experimental` to `active` by updating its `status` field in `rules.yaml` — no code changes required.

---

## Rule Engine Architecture

`mcp-sentinel` uses a two-tier check system:

**Dedicated check modules** (MCPS-001 through MCPS-005) contain hand-written Python for checks that require complex logic — cross-field comparisons, multi-step validation, conditional severity — that YAML patterns cannot express cleanly.

**Generic rule engine** (`checks/generic.py`, MCPS-006 through MCPS-150) drives all remaining rules entirely from `rules.yaml` pattern definitions. The engine resolves each rule's `targets` field to server definition values, then runs the rule's detection patterns against those values. No Python code is needed to add a new rule in this range.

Supported pattern types:

| Type | What It Does |
|---|---|
| `regex` | Compiled regex match against string values; supports IGNORECASE, MULTILINE, DOTALL |
| `value_check` | Structured condition evaluation: `missing_fields`, `matches_unpinned`, `value_in` |
| `schema_analysis` | JSON Schema structure checks: constrained fields, missing validators, `additionalProperties` |
| `unicode` | Scans for invisible/zero-width codepoints |
| `length` | Flags strings exceeding a threshold |

---

## Installation

```bash
# Requires Python 3.10+
git clone https://github.com/joshconkel/mcp-sentinel.git
cd mcp-sentinel
pip install -e .
```

Install with development dependencies (testing, linting, type checking):

```bash
pip install -e ".[dev]"
```

---

## Usage

```bash
# Scan a local MCP server definition
mcp-sentinel scan --schema ./server-definition.json

# Scan and write an HTML report (for stakeholders)
mcp-sentinel scan --schema ./server-definition.json --report html --out ./report.html

# Output JSON (for CI/CD pipelines)
mcp-sentinel scan --schema ./server-definition.json --report json --out ./results.json

# Fail the build if any HIGH or above findings are found
mcp-sentinel scan --schema ./server-definition.json --fail-on HIGH

# List all active rules with source mappings
mcp-sentinel rules list

# Validate rules.yaml and source references
mcp-sentinel rules validate

# Check threat sources for staleness (flag sources not reviewed in 180 days)
mcp-sentinel sources check --warn-after 180
```

---

## CI/CD Integration

Add this to `.github/workflows/` to scan your MCP server definition on every pull request:

```yaml
name: MCP Security Scan

on: [pull_request]

jobs:
  mcp-sentinel:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.11"

      - name: Install mcp-sentinel
        run: pip install mcp-sentinel

      - name: Run scan
        run: |
          mcp-sentinel scan \
            --schema ./mcp-server.json \
            --report json \
            --out scan-results.json \
            --fail-on HIGH

      - name: Upload results
        uses: actions/upload-artifact@v4
        with:
          name: mcp-sentinel-results
          path: scan-results.json
```

The `--fail-on` flag sets the minimum severity that causes a non-zero exit code. Use `--fail-on NONE` in jobs that scan known-malicious fixtures.

---

## Repository Structure

```
mcp-sentinel/
├── mcp_sentinel/                   # Python package
│   ├── __init__.py                 # Package version and metadata
│   ├── cli.py                      # CLI entry point (Typer)
│   ├── engine.py                   # Rule engine: loads rules, dispatches checks, scores
│   ├── models.py                   # Core dataclasses (Finding, ServerDefinition, etc.)
│   ├── reporter.py                 # Terminal, JSON, and HTML output formatters
│   ├── checks/                     # Check modules
│   │   ├── __init__.py             # @register decorator and check registry
│   │   ├── base.py                 # CheckRunner and all pattern type handlers
│   │   ├── generic.py              # Generic engine driving MCPS-006 through MCPS-150
│   │   ├── tool_poisoning.py       # MCPS-001
│   │   ├── secrets.py              # MCPS-002
│   │   ├── parameters.py           # MCPS-003
│   │   ├── transport.py            # MCPS-004
│   │   └── provenance.py           # MCPS-005
│   ├── loaders/                    # Normalize input into ServerDefinition
│   │   ├── schema.py               # Parse MCP JSON/YAML definitions
│   │   └── live.py                 # Live server probing (Phase 3 stub)
│   └── rules/                      # Versioned threat intelligence
│       ├── sources.yaml            # Threat source registry (OWASP, MITRE, NIST)
│       └── rules.yaml              # 150 rule definitions with multi-source mappings
├── tests/
│   ├── test_checks.py              # 350 unit and integration tests
│   └── fixtures/                   # Benign and malicious MCP server definitions
│       ├── benign-server.json      # Zero-finding baseline across all 150 rules
│       ├── MCPS-001-malicious.json
│       ├── MCPS-002-malicious.json
│       └── ... (one per rule)
├── planning/                       # Architecture, threat model, and roadmap
│   ├── ARCHITECTURE.md
│   ├── THREAT-MODEL.md
│   └── ROADMAP.md
├── .github/
│   ├── workflows/mcp-scan.yml      # CI: test, lint, type-check, demo scan
│   ├── ISSUE_TEMPLATE/
│   └── PULL_REQUEST_TEMPLATE.md
├── Makefile                        # Common developer tasks
└── pyproject.toml                  # Package configuration and dependencies
```

---

## Developer Workflow

```bash
# Install with dev dependencies
make install-dev

# Run all 350 tests
make test

# Run tests with coverage
make test-cov

# Lint (ruff) and type-check (mypy)
make lint

# Scan a malicious fixture (demo)
make scan-malicious

# Produce an HTML report
make scan-html
```

Run `make help` to see all available targets.

---

## Contributing

Contributions are welcome. The highest-value contributions are new rules with evidence-backed mappings to OWASP, MITRE ATLAS, or equivalent frameworks.

See [CONTRIBUTING.md](CONTRIBUTING.md) for the full process including evidence requirements and fixture requirements for new rules.

---

## Related Documents

| Document | Purpose |
|---|---|
| [planning/THREAT-MODEL.md](planning/THREAT-MODEL.md) | The attack surface this tool is built against, with attack scenarios |
| [planning/ARCHITECTURE.md](planning/ARCHITECTURE.md) | Component design, data models, rule schema, extension points |
| [planning/ROADMAP.md](planning/ROADMAP.md) | Phase 1/2/3 build plan with milestones and ship criteria |
| [mcp_sentinel/checks/README.md](mcp_sentinel/checks/README.md) | How the check system works; how to add a new check |
| [mcp_sentinel/rules/README.md](mcp_sentinel/rules/README.md) | Rule and source YAML schema reference |
| [tests/README.md](tests/README.md) | How to run the test suite; what each fixture tests |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Contribution process and standards |
| [SECURITY.md](SECURITY.md) | Vulnerability disclosure policy |

---

## License

MIT. See [LICENSE](LICENSE).

---

*Built by [Josh Conkel](https://github.com/joshconkel). Contributions welcome.*
