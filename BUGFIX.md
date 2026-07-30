# Bugfix Inventory: mcp-sentinel

This is a working inventory of security-relevant gaps identified in the **current,
already-implemented** codebase — as distinct from the Phase 2 (LLM-Assisted Semantic
Analysis) proposal, which has no code yet and is tracked instead as concrete tasks in
[`planning/ROADMAP.md`](planning/ROADMAP.md) and a new attack-scenario section in
[`planning/THREAT-MODEL.md`](planning/THREAT-MODEL.md).

Every item here came out of a DFD + STRIDE-questionnaire pass against the existing `Local
Scan Runtime` and `Rule Maintenance Pipeline` (see `planning/DFD.md` and the STRIDE
questionnaire generated from it), consolidated into a single prioritized list. Nothing below
has been fixed yet — this is a backlog, not a changelog. When an item is resolved, move its
entry to `CHANGELOG.md` under `### Fixed` and remove it (or mark it `Status: Fixed`) here.

Sorted by severity, not by STRIDE category, since this document exists to prioritize work
rather than to organize a review session.

## Summary

| ID | Title | STRIDE Area | Severity | Status |
|---|---|---|---|---|
| SECFIX-001 | `promote_staged.py` has no runtime auth check on the rules.yaml write path | Elevation of Privilege | Critical | Open |
| SECFIX-002 | ATLAS fetch is unpinned and unverified | Tampering | High | Open |
| SECFIX-003 | Tools beyond `MAX_TOOLS = 500` are silently dropped | Tampering | High | Open |
| SECFIX-004 | No attribution for rule drafting or promotion | Repudiation | High | Open |
| SECFIX-005 | Scan reports may echo sensitive input content | Information Disclosure | High | Open |
| SECFIX-006 | `--backend anthropic` opt-in-only guarantee is unconfirmed | Information Disclosure | High | Open |
| SECFIX-007 | No durable record of who ran a scan, or when | Repudiation | Medium | Open |
| SECFIX-008 | ATLAS-to-Anthropic prompt scope not fully traced | Information Disclosure | Medium | Open |
| SECFIX-009 | YAML algorithmic-complexity risk within the size cap | Denial of Service | Medium | Open |

---

## SECFIX-001 — `promote_staged.py` has no runtime auth check on the rules.yaml write path

**Severity:** Critical
**STRIDE Area:** Elevation of Privilege
**Location:** `scripts/promote_staged.py`

**Issue:** `promote_staged.py` writes validated rule entries directly into `rules.yaml` with
no runtime identity or authorization check of its own. Whatever protection exists is entirely
external (repo branch protection / CODEOWNERS), and it's unconfirmed whether that protection
is actually scoped to `mcp_sentinel/rules/rules.yaml` specifically, as opposed to general repo
write access. This is the only path that changes what mcp-sentinel will ever detect — a
compromise here silently redefines the tool's entire detection surface.

**Recommended fix:** Confirm (and if absent, add) branch protection / CODEOWNERS specifically
scoped to `rules.yaml`, separate from general repo write access. Consider a lightweight
runtime attestation (e.g. requiring a signed promotion record) rather than relying solely on
external repo configuration that can't be verified from the code itself.

**Source:** DFD edge `e_promote_rules`; STRIDE questionnaire Spoofing Q ("Rule Maintainer") +
Elevation of Privilege Q ("e_promote_rules: Promote Staged"), treated as one finding since
both point at the same underlying gap; DFD `open_questions`.

---

## SECFIX-002 — ATLAS fetch is unpinned and unverified

**Severity:** High
**STRIDE Area:** Tampering
**Location:** `scripts/ingest_atlas.py:92`, `:410`

**Issue:** `ATLAS.yaml` is fetched from `raw.githubusercontent.com` on an unpinned
`main`/`master` branch with no commit hash, checksum, or signature verification, before the
content shapes generated detection rules. This is the single most-corroborated finding across
every artifact produced for this repo so far — flagged independently by the DFD
boundary-crossing note, the DFD's own `open_questions`, and both a Spoofing and a Tampering
question in the STRIDE questionnaire.

**Recommended fix:** Pin the fetch to a specific, reviewed commit SHA, or verify a
checksum/signature before the fetched content is allowed to feed rule-drafting logic.

**Source:** DFD edge `e_atlas_github`; STRIDE questionnaire Spoofing Q ("MITRE ATLAS data
source") + Tampering Q ("e_atlas_github"), treated as one finding.

---

## SECFIX-003 — Tools beyond `MAX_TOOLS = 500` are silently dropped

**Severity:** High
**STRIDE Area:** Tampering
**Location:** `mcp_sentinel/loaders/schema.py:73`

**Issue:** Tool definitions beyond the 500-tool cap are silently dropped with only a log
warning. A server definition with 600 tools, where tool #550 contains a real finding, produces
an incomplete scan result — and a user skimming a PASS summary may not notice the warning that
explains why.

**Recommended fix:** Make exceeding the tool-count limit a hard error (or a clearly non-PASS
status/exit code) rather than a silent drop, so an incomplete scan can never be mistaken for a
clean one.

**Source:** STRIDE questionnaire Tampering Q ("D1: Tool count limit").

---

## SECFIX-004 — No attribution for rule drafting or promotion

**Severity:** High
**STRIDE Area:** Repudiation
**Location:** `scripts/ingest_atlas.py`, `scripts/promote_staged.py`

**Issue:** If a promoted rule later turns out to be wrong (too broad, too narrow, or actively
suppressing a true positive), there is no logging in either script beyond stdout progress
messages. Git commit history is the only attribution trail for which run drafted it and who
promoted it — and this compounds directly with SECFIX-001, since a compromised or careless
promotion currently leaves no independent record to investigate.

**Recommended fix:** Add structured logging (actor, timestamp, source commit/run) at both the
drafting and promotion steps, rather than relying on git history alone to reconstruct
provenance after an incident.

**Source:** STRIDE questionnaire Repudiation Q ("ATLAS Ingest / Promote Staged").

---

## SECFIX-005 — Scan reports may echo sensitive input content

**Severity:** High
**STRIDE Area:** Information Disclosure
**Location:** `mcp_sentinel/reporter.py:242`

**Issue:** If a scanned MCP server definition contains sensitive-looking content (a
hardcoded credential in an example, an internal hostname), the HTML/JSON scan report likely
echoes it back verbatim as finding evidence. It's unconfirmed whether report
distribution/storage is access-controlled equivalently to the original input file — meaning
a report could become a secondary leakage path for the exact kind of secrets MCPS-002 exists
to catch in the input itself.

**Recommended fix:** Confirm and document that generated reports are handled with at least
the same access controls as the input they were derived from. Consider a redaction option for
finding snippets that themselves match a secret-pattern rule.

**Source:** STRIDE questionnaire Information Disclosure Q ("D3: Scan Reports").

---

## SECFIX-006 — `--backend anthropic` opt-in-only guarantee is unconfirmed

**Severity:** High
**STRIDE Area:** Information Disclosure
**Location:** `scripts/ingest_atlas.py:507`; DFD edge `e_atlas_anthropic`

**Issue:** It's unconfirmed whether the `--backend anthropic` path (classified `[SECRET,
PUBLIC]` in the DFD) could ever be triggered automatically — e.g. in an unattended CI
context — rather than strictly via an explicit operator flag. This is a genuine open question
the DFD flags directly; it wasn't independently asked by the STRIDE questionnaire, so it had
no other artifact corroborating or resolving it.

**Recommended fix:** Confirm, and if needed add an explicit guard so this backend can only
ever be reached via a deliberate, explicit flag — never a default or environment-inferred
behavior — since it is currently the only path in the codebase where API-key-bearing traffic
leaves the org.

**Source:** DFD edge `e_atlas_anthropic` `reviewer_note` + `open_questions`.

---

## SECFIX-007 — No durable record of who ran a scan, or when

**Severity:** Medium
**STRIDE Area:** Repudiation
**Location:** `mcp_sentinel/cli.py:38`

**Issue:** No durable, tool-owned record of who ran a scan, against which schema file, or
with what result exists beyond whatever the operator's own terminal/CI logging happens to
retain.

**Recommended fix:** Confirm whether this is an intentional design choice for a local CLI
tool (plausible and acceptable) or a gap worth closing with an optional durable scan-log
output. Either way, document the decision explicitly rather than leaving it implicit.

**Source:** STRIDE questionnaire Repudiation Q ("CLI").

---

## SECFIX-008 — ATLAS-to-Anthropic prompt scope not fully traced

**Severity:** Medium
**STRIDE Area:** Information Disclosure
**Location:** `scripts/ingest_atlas.py:507`

**Issue:** The primary ATLAS-to-Anthropic prompt flow is confirmed to send only public MITRE
ATLAS text, but not every prompt-construction code path was traced to rule out
local/repo-specific content (e.g. in-progress staged rule drafts) ever being concatenated
into the same prompt.

**Recommended fix:** Trace every code path that constructs the Anthropic-backend prompt to
confirm no local file content can be appended beyond the public ATLAS text; add an explicit
test asserting this if none exists.

**Source:** STRIDE questionnaire Information Disclosure Q ("e_atlas_anthropic").

---

## SECFIX-009 — YAML algorithmic-complexity risk within the size cap

**Severity:** Medium
**STRIDE Area:** Denial of Service
**Location:** `mcp_sentinel/loaders/schema.py:118`

**Issue:** `yaml.safe_load` prevents unsafe object construction but doesn't inherently
prevent algorithmic-complexity attacks (deeply nested or anchor-heavy YAML) from causing
pathological parse time, even within the existing 10MB size cap.

**Recommended fix:** Test parsing against a deliberately pathological (but under-10MB) YAML
file. Add a parse-time budget/timeout if the test reveals a real slowdown, rather than
assuming the size cap alone is sufficient.

**Source:** STRIDE questionnaire Denial of Service Q ("D1: MCP Server Definition parsing").

---

## Confirmed-good — no action needed

For completeness, three items were checked and found to already be working as intended; they
are not bugs and are listed here so they aren't mistakenly re-flagged later:

- **Input size cap + safe parsing** (`mcp_sentinel/loaders/schema.py:70-71,118`) — `MAX_FILE_BYTES = 10MB` is enforced before parsing, and `yaml.safe_load` (not `yaml.load`) prevents arbitrary object construction.
- **ATLAS-ingest network timeouts** (`scripts/ingest_atlas.py:410,456-462`) — explicit timeouts bound both the GitHub fetch and the LLM backend call.
- **Scan runtime's read-only blast radius** (`mcp_sentinel/cli.py:38`, `mcp_sentinel/engine.py:79`) — the `CLI → SchemaLoader → RuleEngine → Reporter` path is read-only with respect to the codebase it scans; the only writes are report output files.
