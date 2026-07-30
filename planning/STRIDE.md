---
stride_questions_artifact_version: 1
source_dfd_artifact: dfd-mcp-sentinel-latest.md
source_scanned_commit: 6655cb0e62a7ce2229e1c2f752f0a0275db0610e
generated: 2026-07-30
summary:
  total_questions: 13
  answered: 7
  partial: 4
  unknown: 2
---

# STRIDE Threat-Model Questions: mcp-sentinel

Draft prep material for a human-led threat-modeling session, generated from `dfd-mcp-sentinel-latest.md` (scanned at commit `6655cb0e`). Not a finished threat model — every "Answered" item should still be spot-checked in the session, and every "Unknown" item needs a human answer.

**Summary: 13 total questions — 7 answered from code, 4 partial, 2 unknown.**

## Spoofing

### Rule Maintainer (`scripts/promote_staged.py`)
**Q:** Does anything verify the person running `promote_staged.py` actually holds rule-maintainer authority, or does the script trust whoever has local/CI execution access?
**A:** *Answered* — no identity check anywhere in the script's documented behavior; authority is enforced entirely by repo permissions, outside the codebase. Same pattern flagged in the source DFD's `open_questions`.

### MITRE ATLAS data source (`scripts/ingest_atlas.py:92`)
**Q:** Is the fetch of `ATLAS.yaml` from `raw.githubusercontent.com` protected against a spoofed/MITM'd response beyond standard TLS, or could a network-level attacker substitute different content in transit?
**A:** *Unknown* — the code uses a standard HTTPS GET with no additional integrity check (no hash/signature verification of the response body). Standard TLS protects against in-transit substitution from a network attacker, but nothing verifies the *content* actually came from the real MITRE ATLAS project versus a compromised or unpinned branch — this overlaps with the Tampering question below.

## Repudiation

### CLI (`mcp_sentinel/cli.py:38`)
**Q:** Is there a durable record of who ran a scan, against which schema file, and with what result — beyond whatever the operator's own terminal/CI log happens to retain?
**A:** *Partial* — `reporter.py` writes JSON/HTML output with findings, and JSON output is CI-consumable with exit codes, but nothing in the codebase itself centralizes "who ran this and when" beyond the invoking environment's own logging. For a local CLI tool this may be an acceptable design choice rather than a gap — worth confirming that's an intentional decision, not an oversight.

### ATLAS Ingest / Promote Staged (`scripts/ingest_atlas.py`, `scripts/promote_staged.py`)
**Q:** If a promoted rule turns out to be wrong (too broad, too narrow, or actively suppresses a true positive), is there a durable record of which run of `ingest_atlas.py` drafted it and who ran `promote_staged.py` to promote it?
**A:** *Unknown* — no logging calls found in either script beyond stdout progress messages. Git commit history is the only attribution trail; needs a human answer on whether that's considered sufficient.

## Tampering

### `e_atlas_github`: ATLAS Ingest → MITRE ATLAS data (`scripts/ingest_atlas.py:92`)
**Q:** Since the fetch targets `main`/`master` unpinned with no commit hash or checksum, what happens downstream if the upstream file is later corrupted or maliciously altered — does anything re-validate the content before it shapes generated detection rules?
**A:** *Answered* — no re-validation found; the fetched YAML is parsed and fed directly into rule-drafting logic. This is the single most-flagged finding across every artifact generated for this repo so far (DFD boundary crossing, DFD open question, and now here) — a strong signal it's the first thing worth discussing live.

### D1: MCP Server Definition input (`mcp_sentinel/loaders/schema.py:70`)
**Q:** Since this is untrusted input (a schema file describing someone else's MCP server), is it protected against malformed or oversized input causing resource exhaustion or unsafe deserialization?
**A:** *Answered* — `MAX_FILE_BYTES = 10 * 1024 * 1024` (10MB) is enforced before parsing begins (`schema.py:70-71`), explicitly to prevent memory exhaustion from crafted input. YAML parsing uses `yaml.safe_load`, not `yaml.load`, preventing arbitrary Python object construction (`schema.py:118`, confirmed by the codebase's own `THREAT-MODEL.md` which documents this as an intentional control). This is a genuinely well-handled input boundary.

### D1: Tool count limit (`mcp_sentinel/loaders/schema.py:73`)
**Q:** `MAX_TOOLS = 500` caps how many tool definitions are parsed — what happens to tools beyond that limit, and could that silently produce an incomplete (falsely clean) scan result?
**A:** *Partial* — per the code comment, tools beyond the limit are "silently dropped with a warning." A warning is logged, but if a scanned server definition has 600 tools and tool #550 contains a real finding, the scan result would not surface it, and a user skimming a PASS result might not notice the warning. Worth discussing whether this should be a hard error instead of a silent drop for anything over the limit.

## Information Disclosure

### `e_atlas_anthropic`: ATLAS Ingest → Anthropic API (`scripts/ingest_atlas.py:507`)
**Q:** Confirmed the data sent is public MITRE ATLAS text, not proprietary source — is there any code path where local context (e.g., staged rule drafts already in progress, or repo-specific configuration) could get appended to that prompt beyond the public ATLAS text?
**A:** *Partial* — the primary flow sends ATLAS technique descriptions, which are public. Didn't fully trace every prompt-construction path in `ingest_atlas.py` to confirm no other local file content is ever concatenated in; worth a closer look in the live session rather than asserting a full negative here.

### D3: Scan Reports (`mcp_sentinel/reporter.py:242`)
**Q:** If a scanned MCP server definition contains something sensitive-looking (an accidentally hardcoded credential in an example, an internal hostname), does the HTML/JSON report echo that content back verbatim, and where does that report end up (is it access-controlled the same way the input was)?
**A:** *Unknown* — the reporter renders finding details, which by design include snippets of what triggered a rule; if the input itself contained sensitive content, the report likely would too. This is a reasonable design (the report needs to show evidence) but worth confirming report distribution/storage doesn't widen exposure beyond who already had access to the input file.

## Denial of Service

### ATLAS Ingest (`scripts/ingest_atlas.py:456`)
**Q:** Does the ATLAS ingest process bound its own runtime if the GitHub fetch or the LLM backend call hangs?
**A:** *Answered* — explicit timeouts configured: `timeout=30` on the initial fetch (`ingest_atlas.py:410`) and a configurable `timeout=180` default on LLM backend calls (`ingest_atlas.py:456-462`), with an additional `delay` parameter for inter-call rate limiting (`ingest_atlas.py:951`). Bounded on both ends.

### D1: MCP Server Definition parsing (`mcp_sentinel/loaders/schema.py:70`)
**Q:** Already covered under Tampering, but from a pure availability angle — could a maliciously crafted (not just oversized) definition cause pathological parsing time (e.g., YAML billion-laughs style expansion) even under the 10MB cap?
**A:** *Unknown* — `yaml.safe_load` mitigates unsafe object construction but doesn't inherently prevent algorithmic complexity attacks from deeply nested or anchor-heavy YAML within the size cap. Worth a quick test with a deliberately pathological (but under 10MB) YAML file rather than assuming the size cap alone is sufficient.

## Elevation of Privilege

### `e_promote_rules`: Promote Staged → D2 rules.yaml (write) (`scripts/promote_staged.py`)
**Q:** Can the write path into `rules.yaml` be reached by anyone other than the intended rule-maintainer role, given that `promote_staged.py` writes directly to it with no additional runtime authorization check?
**A:** *Partial* — the script itself performs no auth check; whatever gates this is entirely outside the script, in repo-level branch protection / CODEOWNERS. Could not confirm from code whether that protection actually exists on `rules.yaml` specifically, as opposed to general repo write access. This is the single highest-value question in the whole document, for the same reason as the ATLAS-fetch finding above: it's the only path that changes what mcp-sentinel will ever detect, and it keeps surfacing across every artifact generated for this repo.

### CLI / Rule Engine (`mcp_sentinel/cli.py:38`, `mcp_sentinel/engine.py:79`)
**Q:** Does the scan process itself ever require or acquire elevated privilege beyond reading the input file and the rules config — i.e., is there any code path where a scan could write outside its own report output?
**A:** *Answered* — the scan runtime (`CLI` → `SchemaLoader` → `RuleEngine` → `Reporter`) is read-only with respect to the codebase it scans, by design and by what the code actually does; the only writes are report output files. This is a clean, narrow blast radius by design — a genuinely positive finding worth noting, not just a gap.

## Cases considered but not applicable

- No Spoofing/Repudiation questions generated for `Stakeholder` (the compliance/security consumer of reports) — this entity only reads output, has no invocation path to impersonate or attribute.
- No Elevation of Privilege questions generated for `GitHubAtlas` or `AnthropicAPI` — per the STRIDE-per-element mapping, EoP applies only to processes, not to the external entities themselves; the relevant EoP-adjacent concern (what the ATLAS ingest process does with what it fetches) is covered under Tampering instead.
