# Security Policy

mcp-sentinel is a security tool. Vulnerabilities in the tool itself undermine the trust of everyone using it to secure their own systems. We take reports seriously and aim to respond quickly.

---

## Supported Versions

| Version | Supported |
|---|---|
| `main` branch | Yes |
| Tagged releases | Latest tag only |

---

## Reporting a Vulnerability

**Do not open a public GitHub Issue for security vulnerabilities.**

Report vulnerabilities privately via one of the following:

- **GitHub Private Security Advisory** (preferred): [github.com/joshconkel/mcp-sentinel/security/advisories/new](https://github.com/joshconkel/mcp-sentinel/security/advisories/new)
- **Email**: josh.conkel@gmail.com with subject line `[mcp-sentinel SECURITY]`

### What to include in your report

- **Vulnerability type** (e.g., command injection, path traversal, arbitrary code execution, credential exposure)
- **Component affected** (e.g., which loader, check module, CLI command, or rule)
- **Affected versions or commits**
- **Steps to reproduce** — a minimal reproducer is ideal
- **Impact assessment** — what can an attacker do, and under what conditions?
- **Suggested fix** (optional but appreciated)

---

## Response Timeline

| Milestone | Target |
|---|---|
| Initial acknowledgment | Within 48 hours |
| Severity assessment and triage | Within 5 business days |
| Fix or mitigation | Severity-dependent (see below) |
| Public disclosure | Coordinated with reporter |

**Severity-based fix targets:**

- CRITICAL / HIGH: fix targeted within 14 days of confirmed report
- MEDIUM: fix targeted within 30 days
- LOW / INFO: addressed in next scheduled release

If you have not received an acknowledgment within 48 hours, follow up via email.

---

## Scope

**In scope:**

- **Rule engine**: vulnerabilities in how rules are loaded, parsed, or executed
- **Loaders**: vulnerabilities triggered by malicious MCP server definition files (e.g., YAML parsing exploits, path traversal in file targets)
- **CLI**: argument injection or unsafe file handling
- **Dynamic probing** (Phase 3): vulnerabilities introduced when connecting to live MCP endpoints
- **LLM integration** (Phase 2): prompt injection or data leakage via the Anthropic API integration
- **Dependency vulnerabilities**: critical CVEs in runtime dependencies

**Out of scope:**

- Vulnerabilities in MCP servers being scanned (these are findings, not tool vulnerabilities)
- Theoretical vulnerabilities without demonstrated impact
- Social engineering

---

## What mcp-sentinel Processes

Because mcp-sentinel scans potentially attacker-controlled input, the tool must be hardened against malicious content. Known risk areas and mitigations:

**Malicious YAML/JSON input**
mcp-sentinel parses untrusted MCP server definition files. We use safe YAML loading (`yaml.safe_load`) and validate all input against the MCP schema before processing to mitigate deserialization and injection risks.

**Regex denial of service (ReDoS)**
Rule patterns are regular expressions applied to attacker-controlled content. A crafted tool description could cause catastrophic backtracking. Rule authors must test patterns against ReDoS tools before contributing. The engine applies per-pattern timeouts.

**Path traversal in file targets**
The `--target` flag accepts file paths. We validate that paths resolve within expected boundaries and do not follow symlinks to unintended locations.

**LLM prompt injection via tool descriptions** (Phase 2)
When semantic analysis is enabled, tool descriptions are sent to the Anthropic API. A malicious tool description may attempt to manipulate the LLM analysis result. We treat the API response as untrusted data and do not execute any instructions returned by it.

---

## Coordinated Disclosure

We support coordinated disclosure. If you report a vulnerability, we will work with you to understand the issue, develop a fix, prepare a security advisory, and credit you (unless you prefer anonymity) upon release. We ask for reasonable time to address the issue before public disclosure. Good-faith security researchers acting within this policy will not face legal action.
