# planning/

Design and planning documents for `mcp-sentinel`. These are reference documents for contributors, not user-facing documentation.

---

## Documents

### THREAT-MODEL.md

The adversary model and attack surface analysis that `mcp-sentinel` is built against.

Covers:
- The three-layer MCP attack surface (user, LLM/agent runtime, MCP server layer, backend systems)
- Adversary types and their capabilities (external attackers, compromised dependencies, malicious server operators, insider/misconfiguration)
- Per-vulnerability-class attack scenarios with concrete examples for each of the five Phase 1 checks
- A full attack chain showing how MCPS-001 through MCPS-005 combine into a single end-to-end compromise
- Explicit scope boundary: what this tool does not cover (model layer, agent runtime, backend systems)

**Read this first** if you want to understand why a check exists before reading its code.

### ARCHITECTURE.md

The technical design of the `mcp_sentinel` package.

Covers:
- Component overview diagram and data flow
- Key data models (`ServerDefinition`, `ToolDefinition`, `Finding`, `RiskScore`, `SourceMapping`)
- The rule schema (`rules.yaml` full annotated example)
- The source registry schema (`sources.yaml`)
- All five detection pattern types with behavior descriptions (`regex`, `length`, `unicode`, `value_check`, `schema_analysis`)
- Extension points: adding a rule (YAML only), adding a source (YAML only), adding a check type (one new Python method), adding an output format (one new class)
- Risk scoring formula (severity weights, 100-point cap)
- Phase boundaries: what ships in Phase 1 vs Phase 2 vs Phase 3

**Read this** when implementing a new check type, output format, or loader.

### ROADMAP.md

The three-phase build plan with milestones, ship criteria, and future directions.

| Phase | Scope | Status |
|---|---|---|
| Phase 1 | Static analysis of MCP server definition files | Active development |
| Phase 2 | LLM-assisted semantic analysis of tool descriptions | Planned |
| Phase 3 | Dynamic probing of live MCP servers | Planned |

Phase 2 adds the Anthropic SDK as a dependency and uses an LLM as a second-pass analyzer for subtle tool poisoning that regex cannot catch. Phase 3 adds `loaders/live.py` (currently a stub) and dynamic check modules. Both phases are designed to be additive: they extend the existing engine, reporter, and model layer without replacing them.

---

## Relationship to Code

These documents describe the intended design. Where the code diverges from the documents, the code is authoritative. If you notice a gap, updating the relevant document is a valid and welcome contribution.

The `THREAT-MODEL.md` in particular should evolve as new attack patterns are discovered and new checks are added. Each new check should have a corresponding section in the threat model explaining the attack scenario it covers.
