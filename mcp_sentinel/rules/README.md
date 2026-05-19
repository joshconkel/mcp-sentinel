# mcp_sentinel/rules/

Versioned threat intelligence that drives the scanner. The engine loads these files at startup. All changes to detection behavior, framework mappings, and source references go here without touching Python code.

---

## Files

| File | Purpose |
|---|---|
| `rules.yaml` | Rule definitions: detection patterns, severity, mappings, remediation |
| `sources.yaml` | Threat source registry: OWASP, MITRE, NIST, and any custom sources |

---

## sources.yaml

Defines the threat intelligence sources that rules can map to. The engine resolves `source_id` references in rules against this registry. Sources with `active: false` are excluded from output without breaking any rule.

### Schema

```yaml
version: "1.0"
sources:
  - id: owasp-mcp                    # Referenced by rule mappings. Lowercase, hyphenated.
    name: "OWASP MCP Top 10"         # Human-readable name shown in output
    description: "..."               # One to two sentences on relevance
    url: "https://..."               # Primary reference URL
    github: "https://..."            # Optional: repository URL for staleness checking
    version: "2025"                  # Version of the source document
    entry_prefix: "MCP"              # Short prefix used in finding output
    entry_format: "MCP{nn}"          # Display format for entry IDs (e.g. MCP01, MCP02)
    update_frequency: quarterly      # annually | biannually | quarterly | ad_hoc
    last_checked: "2026-05-16"       # ISO date: update when you review for changes
    active: true
```

### Adding a New Source

Add one entry to `sources.yaml`. The new `id` can then be referenced in any rule's `mappings` block. Existing rules without a mapping to the new source are unaffected.

Once a source is added, run `mcp-sentinel sources check` to verify it appears in the active registry, and `mcp-sentinel rules validate` to confirm no rules have broken references.

### Updating Source Versions

When a source publishes a new version (e.g., OWASP releases an updated MCP Top 10):

1. Update the `version` field
2. Update the `last_checked` field to today
3. Review affected rules for any entry ID or name changes
4. Update rule `mappings` blocks if entry IDs changed

---

## rules.yaml

### Schema

```yaml
version: "1.0"
rules:
  - id: MCPS-001                        # Unique rule identifier. Sequential, never reused.
    name: "Human-readable rule name"
    status: active                      # active | experimental | deprecated
    severity: CRITICAL                  # CRITICAL | HIGH | MEDIUM | LOW | INFO
    category: tool-integrity            # Grouping for report organization
    detection_type: static              # static | dynamic | both

    description: >
      Full explanation of the vulnerability class and why it matters.

    targets:                            # Fields in ServerDefinition to inspect
      - field: tool.description
      - field: tool.annotations

    detection:
      patterns:
        - type: regex                   # regex | value_check | schema_analysis | unicode | length
          description: "What this pattern detects"
          expression: "regex pattern"
          flags: [IGNORECASE]           # Optional: IGNORECASE | MULTILINE | DOTALL
          severity_override: MEDIUM     # Optional: override rule severity for this pattern only

        - type: length
          description: "Suspiciously long description"
          threshold_chars: 600
          severity_override: MEDIUM

        - type: unicode
          description: "Invisible characters"
          flag_codepoints: ["U+200B", "U+200C"]

        - type: value_check
          description: "What this condition checks"
          condition:
            value_in: ["http", "ws"]          # field value must be one of these
            missing_fields: ["integrity"]     # dict must be missing these keys
            matches_unpinned: true            # version string is unpinned

        - type: schema_analysis
          description: "Dangerous unconstrained parameter"
          condition:
            field_type: string
            field_name_matches:
              regex: "(command|cmd|shell)"
              flags: [IGNORECASE]
            missing_constraints: [enum, pattern, maxLength]

    mappings:                           # source_id must match an entry in sources.yaml
      owasp-mcp:
        id: "MCP02"
        name: "Insecure Tool & Resource Management"
        url: "https://owasp.org/www-project-mcp-top-10/#mcp02"
        notes: "Optional context"       # Optional

      mitre-atlas:
        id: "AML.T0051"
        name: "LLM Prompt Injection"
        url: "https://atlas.mitre.org/techniques/AML.T0051"

    remediation: >
      Numbered, actionable remediation steps.

    references:
      - "https://url-one"

    tags: [tool-poisoning, static]
    added: "2026-05-16"
    updated: "2026-05-16"
```

### Rule Status Lifecycle

```
experimental  ──►  active  ──►  deprecated
```

New rules start as `experimental`. They run and produce findings but are labeled as such in output. Promotion to `active` requires passing fixtures and review. `deprecated` rules are skipped entirely by the engine.

### Detection Pattern Types

| Type | Key Fields | What It Checks |
|---|---|---|
| `regex` | `expression`, `flags` | Regex match against a string field value |
| `length` | `threshold_chars` | String length exceeds a threshold |
| `unicode` | `flag_codepoints` | Invisible or zero-width Unicode characters present |
| `value_check` | `condition` | Structured condition: value membership, missing keys, unpinned versions |
| `schema_analysis` | `condition` | JSON Schema structure: property names, missing constraints, `additionalProperties` |

### Severity Override

A `severity_override` on a pattern replaces the rule-level severity for findings produced by that specific pattern. This lets a single rule produce different severity findings depending on match type. For example, MCPS-001 is declared as CRITICAL at the rule level, but the length pattern (suspiciously long description) overrides to MEDIUM since length alone is not definitive evidence of poisoning.

### Adding a New Rule

See the full process in [checks/README.md](../checks/README.md) and [../../CONTRIBUTING.md](../../CONTRIBUTING.md).

Quick requirements:

- Rule `id` must be sequential and never reused (even after deprecation)
- At least one mapping to an active source is required
- At least one detection pattern is required
- New rules start as `status: experimental`
- A malicious fixture file is required before the rule can be merged

---

## Staleness Checking

Run `mcp-sentinel sources check` to flag any source whose `last_checked` date is older than the threshold (default 120 days). Update `last_checked` in `sources.yaml` after manually reviewing the source for changes. This is a manual process by design — automated staleness updates without human review could silently miss breaking changes to source entry IDs.
