# Architecture: mcp-sentinel

This document describes the technical design of `mcp-sentinel`: its components,
data flow, rule schema, extension model, and the decisions behind the structure.

---

## Design Goals

1. **Separation of rules from scanner logic.** Threat intelligence evolves faster
   than scanner code. Rules, sources, and mappings live in YAML and are updated
   independently of the Python core. A new OWASP update should require a rules
   PR, not a code release.

2. **Multi-source mapping without coupling.** A single finding maps to multiple
   frameworks (OWASP MCP, OWASP Agentic, MITRE ATLAS, NIST AI RMF) without any
   source being required. Adding or removing a source never breaks existing rules.

3. **Pluggable check types.** Static regex, schema analysis, unicode scanning,
   and (in later phases) dynamic probing are all first-class check types. Adding
   a new detection method does not require changing the rule schema.

4. **CI/CD native.** JSON output, configurable exit codes, and a single-command
   interface make integration into GitHub Actions, GitLab CI, and other pipelines
   straightforward.

5. **Extensible output.** Terminal output is for humans. JSON output is for
   pipelines. HTML output is for stakeholders. All three derive from the same
   finding model.

---

## Component Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                          CLI (cli.py)                           │
│                    Typer-based entry point                      │
│         scan / rules list / rules update / sources check       │
└────────┬────────────────────────────────────────────────────────┘
         │
         ▼
┌─────────────────────────────────────────────────────────────────┐
│                       Loader Layer                              │
│                                                                 │
│   ┌─────────────────────┐    ┌──────────────────────────────┐  │
│   │   schema.py          │    │   live.py  (Phase 3)         │  │
│   │   Parse MCP JSON /   │    │   Connect to running MCP     │  │
│   │   YAML definitions   │    │   server via SSE / WebSocket │  │
│   └──────────┬──────────┘    └──────────────┬───────────────┘  │
└──────────────┼────────────────────────────────┼─────────────────┘
               │  normalized ServerDefinition   │
               ▼                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                     Rule Engine (engine.py)                     │
│                                                                 │
│   1. Load sources.yaml  →  build source registry               │
│   2. Load rules.yaml    →  build rule set (filtered by status) │
│   3. For each rule:                                             │
│      a. Resolve applicable checks against ServerDefinition      │
│      b. Run each check (regex / schema_analysis / value_check / │
│         unicode / dynamic)                                      │
│      c. Collect Finding objects (rule_id, severity, field,      │
│         match, mappings, remediation)                           │
│   4. Score: aggregate severity into overall risk score          │
└────────────────────────────────┬────────────────────────────────┘
                                 │  List[Finding]
                                 ▼
┌─────────────────────────────────────────────────────────────────┐
│                      Reporter (reporter.py)                     │
│                                                                 │
│   ┌─────────────┐   ┌────────────────┐   ┌──────────────────┐  │
│   │  Terminal   │   │      JSON      │   │       HTML       │  │
│   │  Rich table │   │  CI/CD output  │   │  Stakeholder     │  │
│   │  with color │   │  with exit     │   │  report with     │  │
│   │  and counts │   │  code support  │   │  charts and      │  │
│   └─────────────┘   └────────────────┘   │  remediation     │  │
│                                          └──────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

---

## Data Flow

```
Input: MCP server definition (JSON or YAML file, or live server URL)
  │
  ▼
Loader normalizes to ServerDefinition dataclass
  │
  ▼
Rule Engine loads sources.yaml → SourceRegistry
Rule Engine loads rules.yaml   → RuleSet
  │
  ▼
For each Rule in RuleSet:
  For each Check in Rule.detection.patterns:
    Apply Check to ServerDefinition fields
    If match: emit Finding(rule_id, severity, field, match, source_mappings)
  │
  ▼
RiskScorer aggregates findings → RiskScore(overall, by_severity, by_tool)
  │
  ▼
Reporter formats output → terminal / JSON / HTML
  │
  ▼
Exit code: 0 (clean) | 1 (findings at or above --fail-on threshold)
```

---

## Key Data Models

### ServerDefinition

Normalized intermediate representation of any MCP server definition.

```python
@dataclass
class ServerDefinition:
    source_path: str
    server_url: str | None
    transport: str | None           # "http" | "https" | "stdio" | "websocket"
    tools: list[ToolDefinition]
    packages: list[PackageReference]
    env: dict[str, str]
    config: dict[str, Any]
    raw: dict[str, Any]             # original parsed document for fallback access
```

### ToolDefinition

```python
@dataclass
class ToolDefinition:
    name: str
    description: str
    input_schema: dict[str, Any]    # JSON Schema object
    annotations: dict[str, Any]
```

### Finding

```python
@dataclass
class Finding:
    rule_id: str                    # e.g. "MCPS-001"
    rule_name: str
    severity: Severity              # CRITICAL | HIGH | MEDIUM | LOW | INFO
    field: str                      # e.g. "tool.description"
    tool_name: str | None
    match: str | None               # the matched value or pattern
    detail: str                     # human-readable description of the finding
    source_mappings: list[SourceMapping]
    remediation: str
```

### SourceMapping

```python
@dataclass
class SourceMapping:
    source_id: str                  # e.g. "owasp-mcp"
    source_name: str                # e.g. "OWASP MCP Top 10"
    entry_id: str                   # e.g. "MCP02"
    entry_name: str                 # e.g. "Insecure Tool & Resource Management"
    entry_url: str
```

---

## Rule Schema (rules.yaml)

Each rule in `rules.yaml` follows this structure. All fields except `id`,
`name`, `severity`, `category`, `detection_type`, `targets`, `detection`,
and `mappings` are optional.

```yaml
- id: MCPS-001                         # Unique rule identifier
  name: "Human-readable rule name"
  status: active                       # active | experimental | deprecated
  severity: CRITICAL                   # CRITICAL | HIGH | MEDIUM | LOW | INFO
  category: tool-integrity             # Grouping for report organization
  detection_type: static               # static | dynamic | both

  description: >
    Full explanation of the vulnerability class.

  targets:                             # Fields in ServerDefinition to inspect
    - field: tool.description
    - field: tool.annotations

  detection:
    patterns:
      - type: regex                    # regex | value_check | schema_analysis | unicode | length
        description: "What this pattern detects"
        expression: "pattern here"
        flags: [IGNORECASE]
        severity_override: MEDIUM      # Optional: override rule severity for this pattern only

      - type: schema_analysis
        description: "What structural condition this detects"
        condition:
          field_type: string
          field_name_matches:
            regex: "(command|cmd|shell)"
            flags: [IGNORECASE]
          missing_constraints: [enum, pattern, maxLength]

  mappings:
    owasp-mcp:                         # Must match an `id` in sources.yaml
      id: "MCP02"
      name: "Entry name from source"
      url: "https://direct-link-to-entry"
      notes: "Optional context about this mapping"   # Optional

  remediation: >
    Actionable remediation steps.

  references:
    - "https://url-one"
    - "https://url-two"

  tags: [tag1, tag2]
  added: "2026-05-16"
  updated: "2026-05-16"
```

---

## Source Registry Schema (sources.yaml)

```yaml
sources:
  - id: owasp-mcp                      # Referenced by rule mappings
    name: "OWASP MCP Top 10"
    description: "..."
    url: "https://..."
    github: "https://..."              # Optional: for update checking
    version: "2025"
    entry_prefix: "MCP"
    entry_format: "MCP{nn}"           # Display format for entry IDs
    update_frequency: quarterly        # For staleness checking
    last_checked: "2026-05-16"
    active: true
```

Rules reference sources by `id`. If a source is set to `active: false` or
removed entirely, its mappings are omitted from output without breaking any
rule definitions.

---

## Check Types

### `regex`
Runs a compiled regular expression against the string value of a target field.
Supports flags (`IGNORECASE`, `MULTILINE`, `DOTALL`). A match produces a Finding.

### `value_check`
Evaluates a structured condition against a field value. Supports:
- `value_in: [list]` — field value is one of a set
- `missing_fields: [list]` — a dict field is missing expected keys
- `matches_unpinned: true` — version string matches unpinned patterns ("latest", "^x", "*")
- `not_in: reference_field` — value not present in another field's list

### `schema_analysis`
Evaluates JSON Schema structure of tool input schemas. Supports:
- `field_type` — expected JSON Schema type
- `field_name_matches` — regex match against property names
- `missing_constraints` — required JSON Schema keywords absent
- `additionalProperties` — value or absence check
- `all_properties_lack` — all properties in the schema missing a keyword

### `unicode`
Scans string values for codepoints in a block list. Detects invisible/zero-width
characters used to hide content from human reviewers.

### `length`
Flags string values exceeding a character threshold. Used to detect
suspiciously long descriptions that may contain hidden payloads.

### `dynamic` (Phase 3)
Sends crafted tool call payloads to a live MCP server and inspects responses
for injected instructions, over-returned data, or missing authentication.

---

## Extension Points

### Adding a New Rule
Edit `rules/rules.yaml`. No code changes required. Rules with `status: experimental`
are run but labeled as such in output. Rules with `status: deprecated` are skipped.

### Adding a New Source
Edit `rules/sources.yaml`. Add one entry. Reference the new `id` in any rule's
`mappings` block. Existing rules without the new source mapping are unaffected.

### Adding a New Check Type
1. Implement the check logic in `checks/base.py` as a new `CheckType` handler.
2. Add the new type name to the `type` enum in the rule schema validator.
3. Existing rules that do not use the new type are unaffected.

### Adding a New Output Format
Implement a new formatter class in `reporter.py` inheriting from `BaseFormatter`.
Wire it to a new `--report` CLI option value.

---

## Risk Scoring

The overall risk score (0-100) is computed from the finding set:

| Severity | Points per finding |
|---|---|
| CRITICAL | 25 |
| HIGH | 10 |
| MEDIUM | 4 |
| LOW | 1 |
| INFO | 0 |

Score is capped at 100. The score is intended for relative comparison and
dashboard display, not as a definitive risk rating.

---

## Phase Boundaries

| Phase | Scope | Status |
|---|---|---|
| Phase 1 | Static analysis of MCP server definition files | Active development |
| Phase 2 | LLM-assisted semantic analysis of tool descriptions | Planned |
| Phase 3 | Dynamic probing of live MCP servers | Planned |

Dynamic probing (Phase 3) shares the same Finding, Reporter, and Rule Engine
components. The only new addition is `loaders/live.py` and `checks/dynamic.py`.
The architecture is designed so Phase 3 is additive, not a rewrite.

---

## Dependencies (Phase 1)

| Package | Purpose |
|---|---|
| `typer` | CLI framework |
| `rich` | Terminal formatting and color output |
| `pydantic` | Data model validation |
| `pyyaml` | YAML rule and source loading |
| `jsonschema` | Validating MCP server definition schemas |
| `jinja2` | HTML report templating |

No LLM API dependencies in Phase 1. The Anthropic SDK is added in Phase 2.
