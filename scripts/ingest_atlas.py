#!/usr/bin/env python3
"""
scripts/ingest_atlas.py

Ingest the MITRE ATLAS data and batch-generate mcp-sentinel rule drafts
for relevant techniques.

Reads from the ATLAS project's YAML-native format published at:
  https://github.com/mitre-atlas/atlas-data

The primary source file is dist/ATLAS.yaml — a fully rendered, self-contained
bundle with all tactics, techniques, mitigations, and case studies.

Backends
--------
  lmstudio   Local model via LMStudio OpenAI-compatible API (default).
             No extra dependencies. Uses whatever model is currently loaded.

  anthropic  Anthropic API.
             Requires: pip install -e ".[phase2]" and ANTHROPIC_API_KEY.

Usage
-----
  # Show bundle statistics (no LLM needed)
  python scripts/ingest_atlas.py --stats

  # List relevant techniques with scores, mitigation count, case study count
  python scripts/ingest_atlas.py --list

  # List every technique including traditional ML evasion
  python scripts/ingest_atlas.py --list --filter all --include-subtechniques

  # Generate rules for all not-yet-covered relevant techniques
  python scripts/ingest_atlas.py

  # Single technique, dry run first
  python scripts/ingest_atlas.py --technique AML.T0053 --dry-run
  python scripts/ingest_atlas.py --technique AML.T0053

  # Filter to a specific tactic
  python scripts/ingest_atlas.py --tactic execution
  python scripts/ingest_atlas.py --tactic credential-access

  # Include sub-techniques
  python scripts/ingest_atlas.py --include-subtechniques --min-score 20

  # Re-generate a technique that already has a draft
  python scripts/ingest_atlas.py --technique AML.T0110 --force

  # Anthropic backend
  python scripts/ingest_atlas.py --backend anthropic

  # Use the locally extracted ATLAS.yaml (no network needed)
  python scripts/ingest_atlas.py --bundle path/to/dist/ATLAS.yaml

Output
------
  mcp_sentinel/rules/staged/MCPS-{NNN}-atlas-{TECHNIQUE_ID}-draft.yaml
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any

import requests
import yaml

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

REPO_ROOT  = Path(__file__).parent.parent
RULES_DIR  = REPO_ROOT / "mcp_sentinel" / "rules"
STAGED_DIR = RULES_DIR / "staged"
RULES_FILE = RULES_DIR / "rules.yaml"

CACHE_DIR      = Path.home() / ".cache" / "mcp-sentinel"
CACHE_FILE     = CACHE_DIR / "atlas-data.yaml"
CACHE_TTL_DAYS = 7

ATLAS_URLS = [
    "https://raw.githubusercontent.com/mitre-atlas/atlas-data/main/dist/ATLAS.yaml",
    "https://raw.githubusercontent.com/mitre-atlas/atlas-data/master/dist/ATLAS.yaml",
]

# ---------------------------------------------------------------------------
# Relevance configuration
# ---------------------------------------------------------------------------

LLM_KEYWORDS: frozenset[str] = frozenset({
    "llm", "language model", "large language", "prompt", "injection",
    "jailbreak", "tool", "agent", "api", "inference", "context",
    "supply chain", "credential", "token", "secret", "mcp", "plugin",
    "chatbot", "generative", "foundation model", "fine-tun", "rag",
    "retrieval", "embedding", "agentic", "ai agent", "system prompt",
})

# Tactic shortnames most relevant to MCP attack surface.
# Shortnames are the tactic name lowercased and hyphenated.
RELEVANT_TACTIC_SHORTNAMES: frozenset[str] = frozenset({
    "execution",
    "initial-access",
    "persistence",
    "defense-evasion",
    "credential-access",
    "privilege-escalation",
    "collection",
    "exfiltration",
    "impact",
    "ai-attack-staging",    # was ml-attack-staging in older STIX bundles
})

KNOWN_RELEVANT_IDS: frozenset[str] = frozenset({
    # Core LLM attack techniques
    "AML.T0051",      # LLM Prompt Injection
    "AML.T0051.000",  # Direct
    "AML.T0051.001",  # Indirect
    "AML.T0051.002",  # Triggered
    "AML.T0054",      # LLM Jailbreak
    "AML.T0068",      # LLM Prompt Obfuscation
    "AML.T0065",      # LLM Prompt Crafting
    # MCP / AI agent tool techniques (added in ATLAS v5)
    "AML.T0053",      # AI Agent Tool Invocation
    "AML.T0080",      # AI Agent Context Poisoning
    "AML.T0080.000",  # Memory
    "AML.T0080.001",  # Thread
    "AML.T0081",      # Modify AI Agent Configuration
    "AML.T0083",      # Credentials from AI Agent Configuration
    "AML.T0084",      # Discover AI Agent Configuration
    "AML.T0084.001",  # Tool Definitions  <- directly the MCP attack surface
    "AML.T0086",      # Exfiltration via AI Agent Tool Invocation
    "AML.T0098",      # AI Agent Tool Credential Harvesting
    "AML.T0099",      # AI Agent Tool Data Poisoning
    "AML.T0104",      # Publish Poisoned AI Agent Tool
    "AML.T0110",      # AI Agent Tool Poisoning
    "AML.T0109",      # AI Supply Chain Rug Pull
    # Supply chain and inference
    "AML.T0010",      # ML Supply Chain Compromise
    "AML.T0010.001",  # AI Software
    "AML.T0010.005",  # AI Agent Tool
    "AML.T0040",      # AI Model Inference API Access
    # Prompt and system attacks
    "AML.T0056",      # Extract LLM System Prompt
    "AML.T0057",      # LLM Data Leakage
    "AML.T0067",      # LLM Trusted Output Components Manipulation
    "AML.T0070",      # RAG Poisoning
    "AML.T0071",      # False RAG Entry Injection
    "AML.T0082",      # RAG Credential Harvesting
    "AML.T0093",      # Prompt Infiltration via Public-Facing Application
    # Data and impact
    "AML.T0020",      # Poison Training Data
    "AML.T0077",      # LLM Response Rendering
    "AML.T0101",      # Data Destruction via AI Agent Tool Invocation
})

# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class Tactic:
    atlas_id:    str
    name:        str
    shortname:   str
    description: str
    url:         str


@dataclass
class Mitigation:
    atlas_id:    str
    name:        str
    description: str
    url:         str


@dataclass
class CaseStudy:
    atlas_id: str
    name:     str
    summary:  str
    url:      str


@dataclass
class Technique:
    atlas_id:        str
    name:            str
    description:     str
    url:             str
    tactic_ids:      list[str]
    tactic_names:    list[str]   # derived shortnames e.g. ["execution"]
    is_subtechnique: bool
    parent_id:       str | None
    maturity:        str         # demonstrated | feasible | theoretical

    tactic:        Tactic | None     = None
    mitigations:   list[Mitigation]  = field(default_factory=list)
    subtechniques: list["Technique"] = field(default_factory=list)
    case_studies:  list[CaseStudy]   = field(default_factory=list)

    @property
    def tactic_name(self) -> str:
        if self.tactic:
            return self.tactic.name
        return (
            self.tactic_names[0].replace("-", " ").title()
            if self.tactic_names else "Unknown"
        )

    def relevance_score(self) -> int:
        score = 0
        text = (self.name + " " + self.description).lower()
        for kw in LLM_KEYWORDS:
            if kw in text:
                score += 10
        if self.atlas_id in KNOWN_RELEVANT_IDS:
            score += 30
        for shortname in self.tactic_names:
            if shortname in RELEVANT_TACTIC_SHORTNAMES:
                score += 5
        score += min(len(self.mitigations) * 2, 10)
        score += min(len(self.case_studies) * 3, 15)
        if self.is_subtechnique:
            score += 5
        return min(score, 100)

# ---------------------------------------------------------------------------
# ATLAS YAML-native parser
# ---------------------------------------------------------------------------

def _shortname(name: str) -> str:
    return name.lower().replace(" ", "-").replace("/", "-")

def _tech_url(aid: str) -> str:
    return f"https://atlas.mitre.org/techniques/{aid}"

def _tactic_url(aid: str) -> str:
    return f"https://atlas.mitre.org/tactics/{aid}"

def _mit_url(aid: str) -> str:
    return f"https://atlas.mitre.org/mitigations/{aid}"

def _study_url(aid: str) -> str:
    return f"https://atlas.mitre.org/studies/{aid}"


class ATLASBundle:
    """
    Parsed ATLAS data bundle (YAML-native format, v5+).

    Source structure (dist/ATLAS.yaml):
      id, name, version
      matrices[0]:
        tactics:     flat list of tactic dicts
        techniques:  flat list of all techniques (parent + sub combined)
        mitigations: flat list of mitigation dicts
      case-studies:  flat list at top level (not inside matrix)

    Technique fields:
      id, name, description, object-type, tactics (list of tactic IDs),
      subtechnique-of (parent ID, only on sub-techniques), maturity

    Mitigation.techniques: list of {id, use} dicts linking to techniques
    CaseStudy.procedure:   list of {technique, tactic, description} step dicts
    """

    def __init__(self, raw: dict[str, Any]) -> None:
        self.version: str = raw.get("version", "unknown")
        matrix = raw["matrices"][0]

        # Tactics
        self.tactics: dict[str, Tactic] = {}
        for t in matrix.get("tactics", []):
            tac = Tactic(
                atlas_id=t["id"], name=t["name"],
                shortname=_shortname(t["name"]),
                description=t.get("description", ""),
                url=_tactic_url(t["id"]),
            )
            self.tactics[tac.atlas_id] = tac

        _id_to_sn = {tid: tac.shortname for tid, tac in self.tactics.items()}

        # Techniques (flat list covering both parent and sub-techniques)
        self.techniques: dict[str, Technique] = {}
        for t in matrix.get("techniques", []):
            tac_ids   = t.get("tactics", [])
            tac_names = [_id_to_sn.get(tid, tid) for tid in tac_ids]
            tech = Technique(
                atlas_id=t["id"], name=t["name"],
                description=t.get("description", ""),
                url=_tech_url(t["id"]),
                tactic_ids=tac_ids, tactic_names=tac_names,
                is_subtechnique="subtechnique-of" in t,
                parent_id=t.get("subtechnique-of"),
                maturity=t.get("maturity", ""),
            )
            if tac_ids:
                tech.tactic = self.tactics.get(tac_ids[0])
            self.techniques[tech.atlas_id] = tech

        # Resolve sub-technique parent links
        for tech in self.techniques.values():
            if tech.parent_id and tech.parent_id in self.techniques:
                self.techniques[tech.parent_id].subtechniques.append(tech)

        # Mitigations — link to techniques via mitigation.techniques[].id
        self.mitigations: dict[str, Mitigation] = {}
        for m in matrix.get("mitigations", []):
            mit = Mitigation(
                atlas_id=m["id"], name=m["name"],
                description=m.get("description", ""),
                url=_mit_url(m["id"]),
            )
            self.mitigations[mit.atlas_id] = mit
            for ref in m.get("techniques", []):
                tid = ref.get("id", "")
                if tid in self.techniques:
                    self.techniques[tid].mitigations.append(mit)

        # Case studies — link to techniques via procedure[].technique
        self.case_studies: dict[str, CaseStudy] = {}
        for cs_raw in raw.get("case-studies", []):
            cs = CaseStudy(
                atlas_id=cs_raw["id"], name=cs_raw["name"],
                summary=cs_raw.get("summary", ""),
                url=_study_url(cs_raw["id"]),
            )
            self.case_studies[cs.atlas_id] = cs
            seen: set[str] = set()
            for step in cs_raw.get("procedure", []):
                tid = step.get("technique", "")
                if tid and tid in self.techniques and tid not in seen:
                    self.techniques[tid].case_studies.append(cs)
                    seen.add(tid)

    def filter_relevant(
        self,
        include_subtechniques: bool = False,
        min_score: int = 10,
    ) -> list[Technique]:
        return sorted(
            [
                t for t in self.techniques.values()
                if (include_subtechniques or not t.is_subtechnique)
                and t.relevance_score() >= min_score
            ],
            key=lambda t: t.relevance_score(),
            reverse=True,
        )

    def get_technique(self, atlas_id: str) -> Technique | None:
        return self.techniques.get(atlas_id.upper())

    def stats(self) -> dict[str, Any]:
        parent = [t for t in self.techniques.values() if not t.is_subtechnique]
        subs   = [t for t in self.techniques.values() if t.is_subtechnique]
        return {
            "version":           self.version,
            "techniques":        len(self.techniques),
            "parent_techniques": len(parent),
            "subtechniques":     len(subs),
            "tactics":           len(self.tactics),
            "mitigations":       len(self.mitigations),
            "case_studies":      len(self.case_studies),
        }

# ---------------------------------------------------------------------------
# Bundle fetching with local cache
# ---------------------------------------------------------------------------

def fetch_bundle(
    urls: list[str]   = ATLAS_URLS,
    cache_file: Path  = CACHE_FILE,
    max_age_days: int = CACHE_TTL_DAYS,
    no_cache: bool    = False,
    verbose: bool     = True,
) -> dict[str, Any]:
    if not no_cache and cache_file.exists():
        age = (
            datetime.now(tz=timezone.utc).timestamp()
            - cache_file.stat().st_mtime
        ) / 86400
        if age < max_age_days:
            if verbose:
                print(f"Using cached bundle ({age:.1f}d old): {cache_file}")
            return yaml.safe_load(cache_file.read_text(encoding="utf-8"))
        if verbose:
            print(f"Cache is {age:.1f}d old — re-downloading.")

    last_error: Exception | None = None
    for url in urls:
        if verbose:
            print(f"Fetching: {url}")
        try:
            resp = requests.get(
                url,
                headers={"User-Agent": "mcp-sentinel/0.1 ATLAS-ingestion"},
                timeout=30,
            )
            resp.raise_for_status()
            raw_text = resp.text
            data = yaml.safe_load(raw_text)
            cache_file.parent.mkdir(parents=True, exist_ok=True)
            cache_file.write_text(raw_text, encoding="utf-8")
            if verbose:
                print(f"Cached to: {cache_file}")
            return data
        except Exception as exc:
            last_error = exc
            if verbose:
                print(f"  Failed: {exc}")

    if cache_file.exists():
        if verbose:
            print(f"All URLs failed — using stale cache: {cache_file}")
        return yaml.safe_load(cache_file.read_text(encoding="utf-8"))

    raise RuntimeError(
        "Could not fetch the ATLAS bundle and no cache exists.\n"
        "Download manually:\n"
        f"  curl -L {urls[0]} -o {cache_file}\n"
        "Then re-run with --bundle <path>."
    ) from last_error

# ---------------------------------------------------------------------------
# LLM backends
# ---------------------------------------------------------------------------

class LLMBackend(ABC):
    @abstractmethod
    def complete(self, system: str, user: str) -> str: ...
    @property
    @abstractmethod
    def name(self) -> str: ...


class LMStudioBackend(LLMBackend):
    def __init__(
        self,
        host: str = "http://localhost:1234",
        model: str = "local-model",
        temperature: float = 0.2,
        max_tokens: int = 2048,
        timeout: int = 180,
    ) -> None:
        self.host = host.rstrip("/")
        self.model = model
        self.temperature = temperature
        self.max_tokens = max_tokens
        self.timeout = timeout
        self._endpoint = f"{self.host}/v1/chat/completions"

    @property
    def name(self) -> str:
        return f"LMStudio ({self.host})"

    def complete(self, system: str, user: str) -> str:
        payload = {
            "model": self.model,
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        }
        try:
            resp = requests.post(
                self._endpoint, json=payload,
                timeout=self.timeout,
                headers={"Content-Type": "application/json"},
            )
            resp.raise_for_status()
        except requests.exceptions.ConnectionError as exc:
            raise RuntimeError(
                f"Cannot reach LMStudio at {self.host}. "
                "Is LMStudio running with a model loaded?"
            ) from exc
        return resp.json()["choices"][0]["message"]["content"]


class AnthropicBackend(LLMBackend):
    DEFAULT_MODEL = "claude-sonnet-4-20250514"

    def __init__(
        self,
        model: str | None = None,
        temperature: float = 0.2,
        max_tokens: int = 2048,
    ) -> None:
        try:
            import anthropic as _anthropic
        except ImportError as exc:
            raise RuntimeError("Run: pip install -e '.[phase2]'") from exc
        api_key = os.environ.get("ANTHROPIC_API_KEY")
        if not api_key:
            raise RuntimeError("ANTHROPIC_API_KEY environment variable is not set.")
        self._client = _anthropic.Anthropic(api_key=api_key)
        self.model = model or self.DEFAULT_MODEL
        self.temperature = temperature
        self.max_tokens = max_tokens

    @property
    def name(self) -> str:
        return f"Anthropic ({self.model})"

    def complete(self, system: str, user: str) -> str:
        msg = self._client.messages.create(
            model=self.model,
            max_tokens=self.max_tokens,
            system=system,
            messages=[{"role": "user", "content": user}],
        )
        return msg.content[0].text

# ---------------------------------------------------------------------------
# Rule ID and skip-logic
# ---------------------------------------------------------------------------

def load_existing_rules() -> list[dict[str, Any]]:
    if not RULES_FILE.exists():
        return []
    data = yaml.safe_load(RULES_FILE.read_text(encoding="utf-8"))
    return data.get("rules", []) if data else []


def already_mapped_atlas_ids() -> dict[str, str]:
    mapped: dict[str, str] = {}
    for rule in load_existing_rules():
        atlas = rule.get("mappings", {}).get("mitre-atlas", {})
        if atlas.get("id"):
            mapped[atlas["id"].upper()] = rule["id"]
    return mapped


def staged_atlas_ids() -> set[str]:
    ids: set[str] = set()
    if not STAGED_DIR.exists():
        return ids
    for f in STAGED_DIR.glob("*-atlas-AML-*-draft.yaml"):
        parts = f.stem.split("-atlas-", 1)
        if len(parts) == 2:
            raw = parts[1].replace("-draft", "").replace("-", ".")
            ids.add(raw.upper())
    return ids


def next_rule_id(existing: list[dict[str, Any]]) -> str:
    used: set[int] = set()
    for rule in existing:
        m = re.match(r"MCPS-(\d+)", rule.get("id", ""))
        if m:
            used.add(int(m.group(1)))
    if STAGED_DIR.exists():
        for f in STAGED_DIR.glob("MCPS-*.yaml"):
            m = re.match(r"MCPS-(\d+)", f.name)
            if m:
                used.add(int(m.group(1)))
    n = 1
    while n in used:
        n += 1
    return f"MCPS-{n:03d}"

# ---------------------------------------------------------------------------
# Prompts
# ---------------------------------------------------------------------------

_EXAMPLE_1 = (
    '{"name":"Tool Poisoning via Description Field","severity":"CRITICAL",'
    '"category":"tool-integrity","detection_type":"static",'
    '"description":"MCP tool description fields are treated as authoritative context '
    'by the LLM. Adversaries embed hidden instructions to redirect agent behavior '
    'or exfiltrate conversation content.",'
    '"targets":[{"field":"tool.description"},{"field":"tool.annotations"}],'
    '"patterns":['
    '{"type":"regex","description":"Instruction override language",'
    '"expression":"(ignore|override|forget|disregard).{0,60}(system|instructions|previous|above)",'
    '"flags":["IGNORECASE"],"condition":{},"threshold_chars":null,"severity_override":null},'
    '{"type":"length","description":"Suspiciously long description",'
    '"expression":null,"flags":[],"condition":{},"threshold_chars":600,'
    '"severity_override":"MEDIUM"}],'
    '"mappings":{"mitre-atlas":{"id":"AML.T0051","name":"LLM Prompt Injection",'
    '"url":"https://atlas.mitre.org/techniques/AML.T0051"},'
    '"owasp-mcp":{"id":"MCP02","name":"Insecure Tool and Resource Management",'
    '"url":"https://owasp.org/www-project-mcp-top-10/#mcp02"}},'
    '"remediation":"(1) Validate descriptions. (2) Enforce length limits. '
    '(3) Scan for invisible Unicode.",'
    '"tags":["tool-poisoning","prompt-injection","static"]}'
)

_EXAMPLE_2 = (
    '{"name":"AI Agent Tool Poisoning via Definition Injection","severity":"CRITICAL",'
    '"category":"tool-integrity","detection_type":"static",'
    '"description":"Adversaries distribute MCP tool definitions containing hidden '
    'instructions that redirect agent behavior when the tool is invoked. '
    'Unlike prompt injection via user input, this attack is baked into the '
    'tool definition and persists across sessions.",'
    '"targets":[{"field":"tool.description"},{"field":"tool.name"},{"field":"tool.annotations"}],'
    '"patterns":['
    '{"type":"regex","description":"Hidden instruction appended to legitimate description",'
    '"expression":"(also when called|when this tool is (used|invoked|called)).{0,80}'
    '(also|additionally|instead|forward|send|output)",'
    '"flags":["IGNORECASE"],"condition":{},"threshold_chars":null,"severity_override":null},'
    '{"type":"regex","description":"Covert C2 reference in tool metadata",'
    '"expression":"(exfiltrate|c2|command.and.control|beacon).{0,40}(url|endpoint|server)",'
    '"flags":["IGNORECASE"],"condition":{},"threshold_chars":null,"severity_override":null},'
    '{"type":"unicode","description":"Invisible characters concealing payload",'
    '"expression":null,"flags":[],"condition":{},"threshold_chars":null,"severity_override":null}],'
    '"mappings":{"mitre-atlas":{"id":"AML.T0110","name":"AI Agent Tool Poisoning",'
    '"url":"https://atlas.mitre.org/techniques/AML.T0110"},'
    '"owasp-mcp":{"id":"MCP08","name":"Insecure MCP Component Supply Chain",'
    '"url":"https://owasp.org/www-project-mcp-top-10/#mcp08"}},'
    '"remediation":"(1) Verify tool definitions against signed manifests. '
    '(2) Scan for hidden instructions and invisible Unicode. '
    '(3) Allowlist approved tool publishers.",'
    '"tags":["tool-poisoning","supply-chain","static"]}'
)

SYSTEM_PROMPT = f"""\
You are a security rule author for mcp-sentinel, a static analysis tool that \
audits MCP (Model Context Protocol) server definition files for vulnerabilities.

Your task: given a MITRE ATLAS technique, produce ONE mcp-sentinel rule \
definition as a JSON object. The rule will be reviewed by a human before use.

OUTPUT FORMAT
-------------
Output ONLY a valid JSON object. No markdown fences, no explanation, no preamble.
The response must be parseable directly by json.loads().

SCHEMA
------
{{
  "name":           "Rule name, 5-10 words",
  "severity":       "CRITICAL | HIGH | MEDIUM | LOW | INFO",
  "category":       "lowercase-hyphenated-category",
  "detection_type": "static | dynamic | both",
  "description":    "2-4 sentences on the vulnerability in MCP context.",
  "targets": [
    {{"field": "tool.description"}},
    {{"field": "server.url"}}
  ],
  "patterns": [
    {{
      "type":             "regex | value_check | schema_analysis | unicode | length",
      "description":      "What this specific pattern detects",
      "expression":       "regex string (only for type=regex)",
      "flags":            ["IGNORECASE"],
      "condition":        {{}},
      "threshold_chars":  null,
      "severity_override": null
    }}
  ],
  "mappings": {{
    "mitre-atlas": {{"id": "AML.TXXXX", "name": "...", "url": "..."}}
  }},
  "remediation": "Numbered steps as one string.",
  "tags": ["tag1", "tag2"]
}}

PATTERN TYPES
-------------
regex           Regex against a string field. Use tight quantifiers: .{{0,40}} not .*.
                Avoid \\b; use (^| )word( |$) for word boundary intent.
length          Flag strings over threshold_chars. Secondary signal only.
unicode         Detect invisible/zero-width codepoints. No extra fields.
value_check     condition keys: value_in (list), missing_fields (list), matches_unpinned (bool).
schema_analysis condition.field_name_matches: {{regex, flags}}; field_type; missing_constraints.

TARGET FIELDS
-------------
tool.description, tool.name, tool.annotations, tool.inputSchema,
server.url, server.transport, server.packages[], server.env.*

SEVERITY: CRITICAL=full takeover | HIGH=clear attack path | MEDIUM=conditional | LOW=informational
DETECTION: static=visible in definition file (prefer) | dynamic=requires live probe | both

EXAMPLES
--------
Example 1 — AML.T0051 LLM Prompt Injection:
{_EXAMPLE_1}

Example 2 — AML.T0110 AI Agent Tool Poisoning:
{_EXAMPLE_2}
"""


def _truncate(text: str, max_chars: int = 1800) -> str:
    if len(text) <= max_chars:
        return text
    return text[:max_chars] + f"\n... [truncated at {max_chars} chars]"


def build_user_prompt(tech: Technique, rule_id: str) -> str:
    lines: list[str] = [
        "Generate a mcp-sentinel rule for this MITRE ATLAS technique.",
        f"\nRULE ID TO USE: {rule_id}",
        "\nTECHNIQUE",
        f"  ID:       {tech.atlas_id}",
        f"  Name:     {tech.name}",
        f"  Tactic:   {tech.tactic_name}",
        f"  Maturity: {tech.maturity}",
        f"  URL:      {tech.url}",
    ]
    lines.append(f"\nDESCRIPTION\n{_truncate(tech.description)}")
    if tech.is_subtechnique and tech.parent_id:
        lines.append(f"\nPARENT TECHNIQUE: {tech.parent_id}")
    if tech.subtechniques:
        lines.append(f"\nSUB-TECHNIQUES ({len(tech.subtechniques)})")
        for sub in tech.subtechniques[:6]:
            lines.append(f"  {sub.atlas_id}: {sub.name}")
    if tech.mitigations:
        lines.append("\nATLAS MITIGATIONS (use for remediation field)")
        for mit in tech.mitigations[:5]:
            lines.append(f"  {mit.atlas_id}: {mit.name}")
            if mit.description:
                lines.append(f"    {_truncate(mit.description, 300)}")
    if tech.case_studies:
        lines.append("\nCASE STUDIES (use vocabulary for detection patterns)")
        for cs in tech.case_studies[:3]:
            lines.append(f"  {cs.atlas_id}: {cs.name}")
            if cs.summary:
                lines.append(f"    {_truncate(cs.summary, 500)}")
    lines.append(
        "\nMAPPINGS: always include mitre-atlas. Add owasp-mcp, owasp-agentic, "
        "owasp-llm, or nist-ai-rmf where clearly applicable.\n"
        "\nGenerate at least 2 detection patterns. Output ONLY the JSON object."
    )
    return "\n".join(lines)

# ---------------------------------------------------------------------------
# Parsing and validation
# ---------------------------------------------------------------------------

def extract_json(text: str) -> dict[str, Any]:
    text = re.sub(r"^```(?:json)?\s*", "", text.strip(), flags=re.MULTILINE)
    text = re.sub(r"\s*```$", "", text.strip(), flags=re.MULTILINE)
    text = text.strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    m = re.search(r"\{.*\}", text, re.DOTALL)
    if m:
        try:
            return json.loads(m.group(0))
        except json.JSONDecodeError:
            pass
    raise ValueError(f"No valid JSON in output. First 200: {text[:200]!r}")


REQUIRED_FIELDS = {"name", "severity", "category", "detection_type",
                   "description", "patterns", "mappings", "remediation"}
VALID_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
VALID_DETECTIONS = {"static", "dynamic", "both"}
VALID_PATTERN_TYPES = {"regex", "value_check", "schema_analysis", "unicode", "length"}


def validate_rule_dict(rule: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    missing = REQUIRED_FIELDS - set(rule.keys())
    if missing:
        errors.append(f"Missing fields: {missing}")
    if rule.get("severity") not in VALID_SEVERITIES:
        errors.append(f"Invalid severity: {rule.get('severity')!r}")
    if rule.get("detection_type") not in VALID_DETECTIONS:
        errors.append(f"Invalid detection_type: {rule.get('detection_type')!r}")
    patterns = rule.get("patterns", [])
    if not isinstance(patterns, list) or not patterns:
        errors.append("patterns must be a non-empty list")
    else:
        for i, p in enumerate(patterns):
            if not isinstance(p, dict):
                errors.append(f"patterns[{i}] not a dict")
                continue
            if p.get("type") not in VALID_PATTERN_TYPES:
                errors.append(f"patterns[{i}].type={p.get('type')!r} not valid")
            if p.get("type") == "regex" and p.get("expression"):
                try:
                    flags = 0
                    for f in p.get("flags", []):
                        flags |= getattr(re, f, 0)
                    re.compile(p["expression"], flags)
                except re.error as exc:
                    errors.append(f"patterns[{i}] bad regex: {exc}")
    if not isinstance(rule.get("mappings"), dict) or not rule["mappings"]:
        errors.append("mappings must be a non-empty dict")
    return errors

# ---------------------------------------------------------------------------
# Rule assembly
# ---------------------------------------------------------------------------

def assemble_rule_yaml(
    rule_dict: dict[str, Any],
    rule_id: str,
    tech: Technique,
) -> dict[str, Any]:
    today = date.today().isoformat()
    patterns = []
    for p in rule_dict.get("patterns", []):
        clean: dict[str, Any] = {"type": p.get("type", ""), "description": p.get("description", "")}
        if p.get("expression"):
            clean["expression"] = p["expression"]
        if p.get("flags"):
            clean["flags"] = p["flags"]
        if p.get("condition"):
            clean["condition"] = p["condition"]
        if p.get("threshold_chars") is not None:
            clean["threshold_chars"] = p["threshold_chars"]
        if p.get("severity_override"):
            clean["severity_override"] = p["severity_override"]
        patterns.append(clean)

    mappings: dict[str, Any] = dict(rule_dict.get("mappings", {}))
    mappings["mitre-atlas"] = {"id": tech.atlas_id, "name": tech.name, "url": tech.url}

    return {
        "id": rule_id, "name": rule_dict["name"], "status": "experimental",
        "severity": rule_dict["severity"], "category": rule_dict.get("category", "uncategorized"),
        "detection_type": rule_dict.get("detection_type", "static"),
        "description": rule_dict["description"], "targets": rule_dict.get("targets", []),
        "detection": {"patterns": patterns}, "mappings": mappings,
        "remediation": rule_dict["remediation"],
        "references": rule_dict.get("references", [tech.url]),
        "tags": rule_dict.get("tags", []), "added": today, "updated": today,
    }

# ---------------------------------------------------------------------------
# Generation pipeline
# ---------------------------------------------------------------------------

def generate_rules(
    bundle: ATLASBundle,
    techniques: list[Technique],
    backend: LLMBackend,
    out_dir: Path,
    dry_run: bool = False,
    force: bool = False,
    delay: float = 1.5,
    max_retries: int = 2,
) -> None:
    existing_rules = load_existing_rules()
    in_rules  = already_mapped_atlas_ids()
    in_staged = staged_atlas_ids()
    out_dir.mkdir(parents=True, exist_ok=True)

    total, success, skipped, failed = len(techniques), 0, 0, 0
    print(f"\nmcp-sentinel ATLAS rule generator  (ATLAS v{bundle.version})")
    print(f"Techniques: {total}  Backend: {backend.name}  Mode: {'DRY RUN' if dry_run else 'write'}")
    print(f"Output: {out_dir}\n")

    for i, tech in enumerate(techniques, 1):
        aid, safe_id, label = tech.atlas_id, tech.atlas_id.replace(".", "-"), f"[{i:>3}/{total}]"

        if aid in in_rules and not force:
            print(f"{label} SKIP  {aid} — already in rules.yaml as {in_rules[aid]}")
            skipped += 1
            continue
        if aid in in_staged and not force:
            print(f"{label} SKIP  {aid} — draft already staged")
            skipped += 1
            continue

        rule_id = next_rule_id(existing_rules)
        print(
            f"{label} GEN   {rule_id} <- {aid} "
            f"(score={tech.relevance_score()}, {len(tech.mitigations)}mit, {len(tech.case_studies)}cs)"
            f"  {tech.name}"
        )

        raw: str | None = None
        for attempt in range(1, max_retries + 2):
            try:
                raw = backend.complete(SYSTEM_PROMPT, build_user_prompt(tech, rule_id))
                break
            except Exception as exc:
                if attempt <= max_retries:
                    wait = attempt * 3
                    print(f"             retry {attempt}/{max_retries} in {wait}s ({exc})")
                    time.sleep(wait)
                else:
                    print(f"             FAIL (LLM): {exc}")

        if raw is None:
            failed += 1
            continue

        try:
            rule_dict = extract_json(raw)
        except ValueError as exc:
            print(f"             FAIL (parse): {exc}")
            failed += 1
            continue

        errors = validate_rule_dict(rule_dict)
        if errors:
            print(f"             WARN: {'; '.join(errors)}")

        assembled = assemble_rule_yaml(rule_dict, rule_id, tech)

        if dry_run:
            print("             --- DRY RUN ---")
            print(yaml.dump(assembled, default_flow_style=False, allow_unicode=True, indent=2, sort_keys=False))
        else:
            filename = f"{rule_id}-atlas-{safe_id}-draft.yaml"
            out_path = out_dir / filename
            out_path.write_text(
                yaml.dump(assembled, default_flow_style=False, allow_unicode=True, indent=2, sort_keys=False),
                encoding="utf-8",
            )
            print(f"             wrote: {out_path.relative_to(REPO_ROOT)}")

        existing_rules.append({"id": rule_id})
        in_staged.add(aid)
        success += 1
        if i < total:
            time.sleep(delay)

    print(f"\nDone.  {success} generated,  {skipped} skipped,  {failed} failed.")
    if not dry_run and success > 0:
        print("\nNext steps:")
        print(f"  1. Review drafts in {out_dir.relative_to(REPO_ROOT)}/")
        print("  2. Check regex: replace .* with .{0,40}")
        print("  3. Write a malicious fixture in tests/fixtures/")
        print("  4. Add to rules.yaml + checks/generic.py _GENERIC_RULE_IDS")
        print("  5. mcp-sentinel rules validate")

# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Ingest MITRE ATLAS YAML data and generate mcp-sentinel rule drafts.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--technique", metavar="ID", default=None,
                        help="Process one technique (e.g. AML.T0053 or T0053).")
    parser.add_argument("--tactic", metavar="NAME", default=None,
                        help="Filter to a tactic shortname (e.g. execution, credential-access).")
    parser.add_argument("--filter", choices=["llm", "all"], default="llm",
                        help="'llm': MCP/LLM-relevant (default).  'all': everything.")
    parser.add_argument("--min-score", type=int, default=10, metavar="N",
                        help="Minimum relevance score 0-100 (default: 10).")
    parser.add_argument("--include-subtechniques", action="store_true",
                        help="Include sub-techniques. Default: parent only.")
    parser.add_argument("--no-cache", action="store_true",
                        help="Force re-download even if cache is fresh.")
    parser.add_argument("--cache-ttl", type=int, default=CACHE_TTL_DAYS, metavar="DAYS",
                        help=f"Cache TTL in days (default: {CACHE_TTL_DAYS}).")
    parser.add_argument("--bundle", type=Path, default=None, metavar="FILE",
                        help="Use a local ATLAS.yaml file instead of downloading.")
    parser.add_argument("--backend", choices=["lmstudio", "anthropic"], default="lmstudio",
                        help="LLM backend (default: lmstudio).")
    parser.add_argument("--host", default="http://localhost:1234",
                        help="LMStudio base URL.")
    parser.add_argument("--model", default=None,
                        help="Model name. Ignored by LMStudio; used by Anthropic.")
    parser.add_argument("--temperature", type=float, default=0.2)
    parser.add_argument("--retries", type=int, default=2, metavar="N")
    parser.add_argument("--delay", type=float, default=1.5)
    parser.add_argument("--out", type=Path, default=STAGED_DIR)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--force", action="store_true",
                        help="Re-generate even if a draft or rules.yaml entry exists.")
    parser.add_argument("--stats", action="store_true",
                        help="Print bundle statistics and exit.")
    parser.add_argument("--list", action="store_true",
                        help="List matching techniques and exit.")

    args = parser.parse_args()

    if args.bundle:
        print(f"Loading: {args.bundle}")
        data = yaml.safe_load(args.bundle.read_text(encoding="utf-8"))
    else:
        data = fetch_bundle(no_cache=args.no_cache, max_age_days=args.cache_ttl)

    bundle = ATLASBundle(data)

    if args.stats:
        s = bundle.stats()
        print(f"\nMITRE ATLAS v{s['version']}")
        print(f"  Parent techniques: {s['parent_techniques']}")
        print(f"  Sub-techniques:    {s['subtechniques']}")
        print(f"  Tactics:           {s['tactics']}")
        print(f"  Mitigations:       {s['mitigations']}")
        print(f"  Case studies:      {s['case_studies']}")
        in_rules = already_mapped_atlas_ids()
        in_staged = staged_atlas_ids()
        print(f"\n  In rules.yaml: {len(in_rules)}")
        for aid, rid in sorted(in_rules.items()):
            print(f"    {aid:20} -> {rid}")
        print(f"  Staged:        {len(in_staged)}")
        print(f"\nTactics:")
        for tac in sorted(bundle.tactics.values(), key=lambda t: t.atlas_id):
            count = sum(1 for t in bundle.techniques.values()
                        if tac.atlas_id in t.tactic_ids and not t.is_subtechnique)
            print(f"  {tac.atlas_id:12} {tac.name:35} ({count} parent techniques)")
        return

    # Build technique list
    if args.technique:
        raw_id = args.technique.upper().strip()
        if not raw_id.startswith("AML."):
            raw_id = f"AML.{raw_id}"
        tech = bundle.get_technique(raw_id)
        if tech is None:
            print(f"ERROR: {raw_id!r} not found. Run --list to see options.", file=sys.stderr)
            sys.exit(1)
        techniques = [tech]
    elif args.filter == "all":
        techniques = sorted(
            [t for t in bundle.techniques.values()
             if args.include_subtechniques or not t.is_subtechnique],
            key=lambda t: t.atlas_id,
        )
    else:
        techniques = bundle.filter_relevant(
            include_subtechniques=args.include_subtechniques,
            min_score=args.min_score,
        )

    if args.tactic:
        tf = args.tactic.lower().replace(" ", "-")
        techniques = [t for t in techniques
                      if tf in t.tactic_names or (t.tactic and tf in t.tactic.shortname)]

    if args.list:
        in_rules  = already_mapped_atlas_ids()
        in_staged = staged_atlas_ids()
        print(f"\nMITRE ATLAS v{bundle.version} — {len(techniques)} techniques\n")
        print(f"{'ID':<16} {'Score':>5}  {'Mit':>3}  {'CS':>3}  {'Maturity':<13}  {'Status':<14}  {'Tactic':<22}  Name")
        print("-" * 108)
        for t in techniques:
            status = f"in {in_rules[t.atlas_id]}" if t.atlas_id in in_rules else \
                     "staged" if t.atlas_id in in_staged else "new"
            sub = " (sub)" if t.is_subtechnique else ""
            print(
                f"{t.atlas_id:<16} {t.relevance_score():>5}  "
                f"{len(t.mitigations):>3}  {len(t.case_studies):>3}  "
                f"{t.maturity:<13}  {status:<14}  {t.tactic_name:<22}  {t.name}{sub}"
            )
        new_count = sum(1 for t in techniques if t.atlas_id not in in_rules and t.atlas_id not in in_staged)
        print(f"\n  {new_count} new | {sum(1 for t in techniques if t.atlas_id in in_staged)} staged"
              f" | {sum(1 for t in techniques if t.atlas_id in in_rules)} in rules.yaml")
        return

    if not techniques:
        print("No techniques matched the filters.")
        return

    backend: LLMBackend = (
        LMStudioBackend(host=args.host, model=args.model or "local-model", temperature=args.temperature)
        if args.backend == "lmstudio"
        else AnthropicBackend(model=args.model, temperature=args.temperature)
    )

    generate_rules(
        bundle=bundle, techniques=techniques, backend=backend,
        out_dir=args.out, dry_run=args.dry_run, force=args.force,
        delay=args.delay, max_retries=args.retries,
    )


if __name__ == "__main__":
    main()
