---
dfd_artifact_version: 1
service_name: mcp-sentinel
repo: https://github.com/joshconkel/mcp-sentinel
scanned_commit: 6655cb0e62a7ce2229e1c2f752f0a0275db0610e
generated: 2026-07-23
notation: yourdon-demarco

trust_zones:
  - id: ScanRuntime
    name: Local Scan Runtime
    network: local
    ownership: org
    description: Per-invocation CLI scan of a static MCP server definition. No network calls at runtime.
  - id: RuleMaintenance
    name: Rule Maintenance Pipeline
    network: local
    ownership: org
    description: Offline, maintainer-run pipeline that ingests MITRE ATLAS data and drafts new detection rules.
  - id: third_party
    name: Third-Party Vendor
    network: public_internet
    ownership: third_party
    description: External systems reached only from the Rule Maintenance Pipeline, never from the scan runtime.

external_interfaces:
  - id: Operator
    label: Security Engineer / Operator
    role: external_entity
    layer: api
    direction: inbound
    zone: external
    classification: []
    description: Runs `mcp-sentinel scan --schema <file>` locally or in CI.
  - id: Stakeholder
    label: Security / Compliance Stakeholder
    role: external_entity
    layer: api
    direction: inbound
    zone: external
    classification: [FINDING]
    description: Consumes the HTML report for a risk-scored view mapped to OWASP/MITRE/NIST.
  - id: RuleMaintainer
    label: Rule Maintainer
    role: external_entity
    layer: api
    direction: inbound
    zone: external
    classification: []
    description: Reviews staged rule drafts before promotion into the live rule set.
  - id: GitHubAtlas
    label: MITRE ATLAS data
    role: external_entity
    layer: database
    direction: outbound
    zone: third_party
    classification: [PUBLIC]
    description: Fetched from raw.githubusercontent.com, unpinned branch, no integrity check.
  - id: AnthropicAPI
    label: Anthropic API
    role: external_entity
    layer: database
    direction: outbound
    zone: third_party
    classification: [SECRET, PUBLIC]
    description: Optional rule-drafting backend (--backend anthropic); default backend is local LM Studio.
  - id: D1
    label: MCP Server Definition
    role: data_store
    layer: database
    direction: inbound
    zone: ScanRuntime
    classification: [CODE]
    description: The user-supplied MCP server JSON/YAML being audited — treat as untrusted input if sourced from a third-party MCP catalog.
  - id: D3
    label: Scan Reports
    role: data_store
    layer: database
    direction: outbound
    zone: ScanRuntime
    classification: [FINDING]
    description: Terminal/JSON/HTML output; JSON exit codes are CI-consumable.

boundary_crossings:
  - id: e_atlas_github
    from: ATLASIngest
    to: GitHubAtlas
    checks_triggered: [network, ownership]
    classification: [PUBLIC]
    stride_notes: "Tampering — unpinned main/master fetch, no commit hash or checksum verification before it feeds rule generation."
    reviewer_note: "Consider pinning to a specific commit SHA or verifying a checksum."
  - id: e_atlas_anthropic
    from: ATLASIngest
    to: AnthropicAPI
    checks_triggered: [network, ownership, auth]
    classification: [SECRET, PUBLIC]
    stride_notes: "Information disclosure — lower severity than a typical scanner-to-LLM edge since only public MITRE ATLAS text is sent, not proprietary source."
    reviewer_note: "Confirm this optional backend is opt-in only and never triggered automatically."
  - id: e_promote_rules
    from: PromoteStaged
    to: D2
    checks_triggered: [auth]
    classification: [WRITE]
    stride_notes: "Elevation of privilege / tampering — this is the only path that changes what mcp-sentinel will ever detect."
    reviewer_note: "Confirm rules.yaml changes require PR review / CODEOWNERS separate from general repo write access."

nodes:
  - {id: CLI, label: "1.0 CLI", role: process, layer: api, file: mcp_sentinel/cli.py, line: 38, zone: ScanRuntime}
  - {id: SchemaLoader, label: "2.0 Schema Loader", role: process, layer: service, file: mcp_sentinel/loaders/schema.py, line: 158, zone: ScanRuntime}
  - {id: RuleEngine, label: "3.0 Rule Engine", role: process, layer: service, file: mcp_sentinel/engine.py, line: 79, zone: ScanRuntime}
  - {id: Reporter, label: "4.0 Reporter", role: process, layer: service, file: mcp_sentinel/reporter.py, line: 242, zone: ScanRuntime}
  - {id: ATLASIngest, label: "5.0 ATLAS Ingest", role: process, layer: service, file: scripts/ingest_atlas.py, line: 1, zone: RuleMaintenance}
  - {id: PromoteStaged, label: "6.0 Promote Staged", role: process, layer: service, file: scripts/promote_staged.py, line: 1, zone: RuleMaintenance}
  - {id: D2, label: "D2 rules.yaml / sources.yaml", role: data_store, layer: database, file: mcp_sentinel/rules/rules.yaml, line: 1, zone: ScanRuntime}
  - {id: D4, label: "D4 Staged Rule Drafts", role: data_store, layer: database, file: mcp_sentinel/rules/staged, line: 1, zone: RuleMaintenance}
  - {id: LMStudio, label: "LM Studio (local)", role: external_entity, layer: service, file: scripts/ingest_atlas.py, line: 452, zone: RuleMaintenance}

assumptions:
  - "live.py (Phase 3 dynamic probing of a running MCP server) is an explicit NotImplementedError placeholder, not yet active — excluded from boundary crossings until implemented."
  - "Treated LM Studio as staying inside the Rule Maintenance trust zone since it's the default local backend; only Anthropic is treated as a third-party crossing."

open_questions:
  - "Confirm whether the fetched ATLAS.yaml should be pinned to a commit SHA or checksum-verified before it feeds rule generation."
  - "Confirm the --backend anthropic path is opt-in only, never triggered in an automated/CI context without explicit configuration."
  - "Confirm rules.yaml changes via promote_staged.py require PR review / CODEOWNERS, separate from general repo write access."
  - "Confirm whether MCP server definitions being scanned could originate from an untrusted third-party catalog, which would change D1's classification from CODE to an externally-sourced, potentially attacker-controlled input."
---

# Threat Model Draft: mcp-sentinel

Draft for threat-modeling prep, generated by the dfd-threat-model skill. Not a substitute for a reviewed architecture diagram.

```mermaid
flowchart TD
    subgraph Legend["Legend"]
        direction LR
        L1[External Entity]
        L2((1.0<br/>Process))
        L3[[D1 Data Store]]
        L1 ==>|"[TAG] sync, crosses boundary"| L2
        L2 -.->|"async / event"| L3
    end

    Operator[Security Engineer / Operator]
    Stakeholder[Security / Compliance Stakeholder]
    RuleMaintainer[Rule Maintainer]
    GitHubAtlas[MITRE ATLAS data*<br/>raw.githubusercontent.com]
    AnthropicAPI[Anthropic API*<br/>optional backend]
    LMStudio[LM Studio*<br/>local, default backend]

    subgraph ScanRuntime["Local Scan Runtime (per-invocation, no network calls)"]
        CLI((1.0<br/>CLI))
        SchemaLoader((2.0<br/>Schema Loader))
        RuleEngine((3.0<br/>Rule Engine))
        Reporter((4.0<br/>Reporter))
        D1[[D1 MCP Server<br/>Definition]]
        D2[[D2 rules.yaml /<br/>sources.yaml]]
        D3[[D3 Scan Reports<br/>terminal/JSON/HTML]]
    end

    subgraph RuleMaintenance["Rule Maintenance Pipeline (offline, dev-time)"]
        ATLASIngest((5.0<br/>ATLAS Ingest))
        PromoteStaged((6.0<br/>Promote Staged))
        D4[[D4 Staged Rule<br/>Drafts]]
    end

    Operator -->|"[CODE] scan --schema path"| CLI
    CLI -->|"file path"| SchemaLoader
    SchemaLoader -.-|"[CODE] server definition"| D1
    SchemaLoader -->|"ServerDefinition"| RuleEngine
    D2 -.-|"[PUBLIC] rules + source mappings"| RuleEngine
    RuleEngine -->|"[FINDING] List of Finding"| Reporter
    Reporter -->|"[FINDING] terminal output"| Operator
    Reporter -->|"[FINDING] JSON/HTML report"| D3
    D3 -.->|"[FINDING] shared report"| Stakeholder

    ATLASIngest ==>|"[PUBLIC] fetch ATLAS.yaml, unpinned branch"| GitHubAtlas
    ATLASIngest ==>|"[SECRET][PUBLIC] api_key + threat-intel text"| AnthropicAPI
    ATLASIngest -->|"[PUBLIC] threat-intel text"| LMStudio
    ATLASIngest -->|"[PUBLIC] draft rule YAML"| D4
    RuleMaintainer -.-|"[CODE] review drafts"| D4
    RuleMaintainer -->|"promote command"| PromoteStaged
    PromoteStaged -.-|"[CODE] draft YAML"| D4
    PromoteStaged ==>|"[WRITE] validated rule entries"| D2

    classDef api fill:#4a9eff,stroke:#1e5a99,color:#000
    classDef service fill:#4ade80,stroke:#1e8f4a,color:#000
    classDef database fill:#fbbf24,stroke:#a86f00,color:#000

    class Operator,Stakeholder,RuleMaintainer api;
    class CLI,SchemaLoader,RuleEngine,Reporter,ATLASIngest,PromoteStaged service;
    class LMStudio service;
    class GitHubAtlas,AnthropicAPI database;
    class D1,D2,D3,D4 database,store;
```

## Assumptions

- `live.py` (Phase 3 dynamic probing of a running MCP server) is an explicit `NotImplementedError` placeholder, not yet active — excluded from boundary crossings until implemented.
- Treated LM Studio as staying inside the Rule Maintenance trust zone since it's the default local backend; only Anthropic is treated as a third-party crossing.

## Items for a human reviewer to verify

- **ATLAS fetch (`e_atlas_github`)**: confirm whether the fetched `ATLAS.yaml` should be pinned to a commit SHA or checksum-verified before it feeds rule generation.
- **Anthropic backend (`e_atlas_anthropic`)**: confirm the `--backend anthropic` path is opt-in only, never triggered in an automated/CI context without explicit configuration.
- **Rule promotion (`e_promote_rules`)**: confirm `rules.yaml` changes via `promote_staged.py` require PR review / CODEOWNERS, separate from general repo write access.
- **Input provenance (D1)**: confirm whether MCP server definitions being scanned could originate from an untrusted third-party catalog, which would change D1's classification from `CODE` to an externally-sourced, potentially attacker-controlled input.
