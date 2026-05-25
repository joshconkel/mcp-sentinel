# mcp\_sentinel/rules/

Versioned threat intelligence that drives the scanner. The engine loads these files at startup. All changes to detection behavior, framework mappings, and source references go here without touching Python code.

\---

## Files

|File|Purpose|
|-|-|
|`rules.yaml`|150 rule definitions: detection patterns, severity, mappings, remediation|
|`sources.yaml`|Threat source registry: OWASP, MITRE ATLAS, NIST AI RMF|

\---

## sources.yaml

Defines the threat intelligence sources that rules can map to. The engine resolves `source\_id` references in rules against this registry at startup. Sources with `active: false` are excluded from finding output without breaking any rule.

### Current Sources

|ID|Name|Version|Entry Format|Coverage|
|-|-|-|-|-|
|`owasp-mcp`|OWASP MCP Top 10|2025|`MCP{nn}`|MCP01–MCP10|
|`owasp-agentic`|OWASP Top 10 for Agentic Applications|2026|`ASI{nn}`|ASI01–ASI10|
|`owasp-llm`|OWASP Top 10 for LLM Applications|2025|`LLM{nn}`|LLM01–LLM10|
|`mitre-atlas`|MITRE ATLAS|4.5|`AML.T{nnnn}\[.nnn]`|AML.T\* techniques|
|`nist-ai-rmf`|NIST AI Risk Management Framework|1.0|`{FUNCTION} {n}.{n}`|GOVERN / MAP / MEASURE / MANAGE|

### Schema

```yaml
version: "1.0"
schema\_version: "1.0"
last\_updated: "2026-05-16"

sources:
  - id: owasp-mcp                        # Referenced by rule mappings. Lowercase, hyphenated.
    name: "OWASP MCP Top 10"             # Human-readable name shown in reports
    description: >
      One to two sentences on the source's scope and relevance.
    url: "https://..."                   # Primary reference URL
    github: "https://..."               # Optional: repo URL used for staleness checking
    version: "2025"                      # Version of the source document
    entry\_prefix: "MCP"                  # Short prefix shown in finding output
    entry\_format: "MCP{nn}"             # Display format (e.g. MCP01, MCP02)
    update\_frequency: quarterly          # annually | biannually | quarterly | ad\_hoc
    last\_checked: "2026-05-16"          # ISO date: update when you review for changes
    active: true
```

### Adding a New Source

Add one entry to `sources.yaml`. The new `id` can immediately be referenced in any rule's `mappings` block. Existing rules without a mapping to the new source are unaffected.

Once added, run these commands to verify:

```bash
mcp-sentinel sources check     # Confirms the source appears in the active registry
mcp-sentinel rules validate    # Confirms no rules have broken source references
```

### Updating Source Versions

When a source publishes a new version (e.g. OWASP releases an updated MCP Top 10):

1. Update the `version` field
2. Update `last\_checked` to today's date
3. Review affected rules for entry ID or name changes
4. Update any changed entry IDs in rule `mappings` blocks

Run `mcp-sentinel sources check --warn-after 180` in CI to flag sources not reviewed within 180 days.

\---

## rules.yaml

### Overview

The current rule set contains **150 rules** (MCPS-001 through MCPS-150):

* **5 active** — fully validated, no known false positives on the benign fixture
* **145 experimental** — enabled by default; may have higher false-positive rates on edge-case servers

All 150 rules run as part of a standard scan. The `status` field controls labeling in output, not execution. Promote a rule from `experimental` to `active` by changing its `status` field — no Python code changes are required.

### Top-Level Schema

```yaml
version: "1.0"
rules:
  - id: MCPS-001                     # Unique rule ID. Sequential, never reused.
    name: "Human-readable rule name"
    status: active                   # active | experimental | deprecated
    severity: CRITICAL               # CRITICAL | HIGH | MEDIUM | LOW | INFO
    category: tool-integrity         # Dot-free string grouping related rules
    detection\_type: static           # static | dynamic | both

    description: >
      Full explanation of the vulnerability class and why it matters to agentic AI security.

    targets:                         # One or more ServerDefinition fields to inspect
      - field: tool.description
      - field: tool.annotations

    detection:
      patterns:
        - type: regex                # Pattern type — see Pattern Types section
          description: "..."
          expression: "..."
          flags: \[IGNORECASE]
          severity\_override: MEDIUM  # Optional: overrides rule severity for this pattern only

    mappings:                        # Source framework references (all optional)
      owasp-mcp:
        id: "MCP02"
        name: "Insecure Tool and Resource Management"
        url: "https://owasp.org/www-project-mcp-top-10/#mcp02"
      mitre-atlas:
        id: "AML.T0051"
        name: "LLM Prompt Injection"
        url: "https://atlas.mitre.org/techniques/AML.T0051"

    remediation: >
      Numbered list of concrete remediation steps.

    references:
      - "https://owasp.org/..."
      - "https://arxiv.org/..."

    tags:
      - prompt-injection
      - tool-poisoning
      - static

    added: "2026-05-16"              # ISO date the rule was first added
    updated: "2026-05-19"           # ISO date of last modification
```

\---

### Target Fields

The `targets` block tells the generic engine which `ServerDefinition` fields to extract and pass to the detection patterns. Multiple targets mean the rule runs against each independently.

|Field Path|Value Type|What Gets Checked|
|-|-|-|
|`tool.description`|`str`|Description string of each tool|
|`tool.name`|`str`|Name string of each tool|
|`tool.annotations`|`str`|Stringified annotations dict of each tool|
|`tool.inputSchema`|`dict`|Full input schema dict; also each property's `"default"` value as a string|
|`server.url`|`str`|Server URL string|
|`server.transport`|`str`|Transport type string|
|`server.config`|`dict`|Server config dict|
|`server.env` or `server.env.\*`|`str`|Each environment variable value, checked individually|
|`server.packages\[]`|`dict` + `str`|Full package dict (for `missing\_fields` checks) and the version string (for `matches\_unpinned` checks)|

**Usage across the current rule set:** `tool.description` (123 rules), `tool.inputSchema` (87), `tool.annotations` (57), `server.url` (47), `server.env.\*` (37), `server.packages\[]` (24), `tool.name` (21), `server.transport` (7).

\---

### Pattern Types

Rules use one or more of five pattern types in their `detection.patterns` list. Each pattern may also carry a `severity\_override` that replaces the rule-level severity for findings from that specific pattern.

#### `regex`

Compiled regular expression matched against a string value. The engine skips regex checks when the target value is a dict.

```yaml
- type: regex
  description: "Instruction override language"
  expression: "(ignore|override|forget|disregard).{0,60}(system|instructions|previous|above)"
  flags: \[IGNORECASE]               # Optional: IGNORECASE | MULTILINE | DOTALL
  severity\_override: HIGH           # Optional
```

**Usage:** 271 patterns across 150 rules — the most common pattern type.

#### `value\_check`

Structured condition evaluation against a field value. Three conditions are supported and evaluated independently when both are present in a single pattern.

```yaml
- type: value\_check
  description: "Package without pinned version"
  condition:
    matches\_unpinned: true          # Version string matches unpinned patterns (latest, \*, ^, >=, \~>)
  severity\_override: HIGH

- type: value\_check
  description: "Package without integrity hash"
  condition:
    missing\_fields:                 # Flat key lookup — checks literal key presence in a dict
      - integrity
      - checksum
      - sha256
  severity\_override: HIGH

- type: value\_check
  description: "Insecure transport value"
  condition:
    value\_in:                       # String equality check against a set of known-bad values
      - "http"
      - "ws"
```

**`missing\_fields` note:** The lookup is **flat** — it checks whether the literal key string exists in the dict, not nested key access. A key like `"annotations.destructiveHint"` checks for that exact string as a dict key, not `dict\["annotations"]\["destructiveHint"]`. This is used in experimental rules that check for security annotation presence in `tool.inputSchema`.

**Usage:** 38 patterns. `missing\_fields` (23 patterns), `matches\_unpinned` (17), `value\_in` (4).

#### `schema\_analysis`

Inspects JSON Schema structure for dangerous property names lacking required constraints. Requires **both** `field\_name\_matches` and `missing\_constraints` to be present — either alone is a no-op.

```yaml
- type: schema\_analysis
  description: "Unconstrained string parameter with dangerous semantic name"
  condition:
    field\_name\_matches:
      regex: "(command|cmd|shell|exec|query|sql|path|file|url|endpoint|script|eval)"
      flags: \[IGNORECASE]
    field\_type: string               # Only inspect properties of this JSON Schema type
    missing\_constraints:             # Fire if ALL of these are absent from the property definition
      - enum
      - pattern
      - maxLength
  severity\_override: LOW
```

The pattern fires when a property's name matches the `field\_name\_matches` regex AND the property definition is missing all of the listed `missing\_constraints`. Adding any one of the listed constraints suppresses the finding for that property.

**Usage:** 38 patterns.

#### `unicode`

Scans for invisible or zero-width Unicode codepoints that can be used to conceal injected content.

```yaml
- type: unicode
  description: "Zero-width or invisible characters used to conceal content"
  flag\_codepoints:
    - "U+200B"   # Zero-width space
    - "U+200C"   # Zero-width non-joiner
    - "U+200D"   # Zero-width joiner
    - "U+FEFF"   # Zero-width no-break space (BOM)
    - "U+2060"   # Word joiner
```

**Usage:** 13 patterns, primarily on `tool.description` and `tool.annotations`.

#### `length`

Flags strings exceeding a character threshold. Used to detect suspiciously long tool descriptions that may contain hidden payloads alongside their visible content.

```yaml
- type: length
  description: "Suspiciously long description suggesting hidden payload"
  threshold\_chars: 600
  severity\_override: MEDIUM
```

**Usage:** 3 patterns.

\---

### Mappings

The `mappings` block links a rule to specific entries in the threat source registry. Every source ID used must exist in `sources.yaml`. Mappings are optional at the individual source level — a rule may map to some sources and not others.

```yaml
mappings:
  owasp-mcp:
    id: "MCP02"
    name: "Insecure Tool and Resource Management"
    url: "https://owasp.org/www-project-mcp-top-10/#mcp02"
  owasp-agentic:
    id: "ASI02"
    name: "Tool Misuse and Exploitation"
    url: "https://genai.owasp.org/..."
  owasp-llm:
    id: "LLM01"
    name: "Prompt Injection"
    url: "https://owasp.org/..."
  mitre-atlas:
    id: "AML.T0051"
    name: "LLM Prompt Injection"
    url: "https://atlas.mitre.org/techniques/AML.T0051"
  nist-ai-rmf:
    id: "MANAGE 2.4"
    name: "Risk treatments are monitored and managed"
    url: "https://airc.nist.gov/Docs/1"
```

**Coverage across the current rule set:** `mitre-atlas` (140 rules), `owasp-mcp` (120), `owasp-llm` (76), `nist-ai-rmf` (33), `owasp-agentic` (24).

\---

### Adding a New Rule

#### For YAML-driven rules (the common case)

Add the rule entry to `rules.yaml`. No Python changes are required. The generic engine picks it up automatically.

1. Choose the next sequential ID (`MCPS-151` etc.)
2. Start with `status: experimental`
3. Write at least one detection pattern (prefer `regex` for broad coverage, `schema\_analysis` for parameter structure)
4. Map to at least one active source in `sources.yaml`
5. Create `tests/fixtures/MCPS-NNN-malicious.json`
6. Verify the benign fixture does not trigger the rule
7. Add a `TestMCPSNNN` class to `tests/test\_checks.py`

Run `mcp-sentinel rules validate` to confirm the new rule has no broken source references.

#### For dedicated Python check modules (complex logic)

See [mcp\_sentinel/checks/README.md](../checks/README.md) for the full workflow. Use this path when the detection requires cross-field comparisons, conditional severity based on multiple values, or logic that cannot be expressed as YAML patterns.

#### Promoting a Rule to `active`

Change `status: experimental` to `status: active` in the rule entry. No other changes are needed. Before promoting, verify:

* Zero false positives on `tests/fixtures/benign-server.json`
* The malicious fixture triggers a finding reliably
* Detection logic has been reviewed for real-world edge cases

\---

### Rule Lifecycle

```
experimental  →  active  →  deprecated
```

* **experimental:** Enabled by default. Labeled in output. May have higher false-positive rates. Change detection logic freely.
* **active:** Fully validated. Changes to detection patterns should be treated as breaking changes and noted in `CHANGELOG.md`.
* **deprecated:** Rule ID is retired. Entry remains in `rules.yaml` as a record. Engine skips deprecated rules.

Rule IDs are never reused. A deprecated rule's ID is permanently retired even if the rule is conceptually replaced by a new one.

