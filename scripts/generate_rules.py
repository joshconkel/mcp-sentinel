#!/usr/bin/env python3
"""
scripts/generate_rules.py

Batch-generates mcp-sentinel rule YAML drafts from OWASP source entries
using a local LLM via LMStudio or the Anthropic API.

Backends
--------
  lmstudio   Local model via LMStudio OpenAI-compatible API (default).
             Works with any model loaded in LMStudio. Tested with Qwen 3.6 27B.
             Requires LMStudio running at http://localhost:1234 (configurable).

  anthropic  Anthropic API.
             Requires: pip install -e ".[phase2]"
             Requires: ANTHROPIC_API_KEY environment variable.

Usage
-----
  # All OWASP MCP Top 10 entries
  python scripts/generate_rules.py --source owasp-mcp

  # Single entry
  python scripts/generate_rules.py --source owasp-mcp --entry MCP03

  # All Agentic Top 10 entries using Anthropic
  python scripts/generate_rules.py --source owasp-agentic --backend anthropic

  # Dry run: print without writing
  python scripts/generate_rules.py --source owasp-mcp --dry-run

  # Custom LMStudio host or model name
  python scripts/generate_rules.py --source owasp-mcp --host http://192.168.1.5:1234

Output
------
  rules/staged/MCPS-{NNN}-{source}-{entry_id}-draft.yaml
  Each draft has status: experimental and must be reviewed before promotion.
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
from datetime import date
from pathlib import Path
from typing import Any

import requests
import yaml

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

REPO_ROOT    = Path(__file__).parent.parent
RULES_DIR    = REPO_ROOT / "mcp_sentinel" / "rules"
STAGED_DIR   = RULES_DIR / "staged"
RULES_FILE   = RULES_DIR / "rules.yaml"
SOURCES_FILE = RULES_DIR / "sources.yaml"


# ---------------------------------------------------------------------------
# Source entry model
# ---------------------------------------------------------------------------

@dataclass
class SourceEntry:
    """A single entry from an OWASP source document."""
    source_id:   str          # e.g. "owasp-mcp"
    entry_id:    str          # e.g. "MCP03"
    title:       str          # e.g. "Excessive Tool Permissions"
    description: str          # Full entry text for the LLM prompt
    url:         str          # Canonical URL for this entry
    source_name: str          # e.g. "OWASP MCP Top 10"


# ---------------------------------------------------------------------------
# Built-in OWASP entry registry
# ---------------------------------------------------------------------------
# Used when live fetch is unavailable. Content is abbreviated but sufficient
# for rule generation. Update by running with --fetch to pull live content.

BUILT_IN_ENTRIES: dict[str, list[dict[str, str]]] = {

    "owasp-mcp": [
        {
            "id": "MCP01",
            "title": "Token Mismanagement and Secret Exposure",
            "description": (
                "MCP servers that embed API keys, connection strings, long-lived tokens, "
                "or other credentials directly in tool definitions, parameter defaults, "
                "or server configuration expose those secrets to any system that can read "
                "the server definition — including the LLM itself, which may reproduce "
                "them in outputs or logs. Attackers can retrieve exposed credentials via "
                "prompt injection, debug traces, or compromised context windows."
            ),
            "url": "https://owasp.org/www-project-mcp-top-10/#mcp01",
        },
        {
            "id": "MCP02",
            "title": "Insecure Tool and Resource Management",
            "description": (
                "Tool description fields are treated as authoritative context by the LLM. "
                "Malicious or compromised MCP servers can embed hidden instructions in "
                "these fields to redirect agent behavior, override system prompts, grant "
                "the server elevated capabilities, or exfiltrate conversation content. "
                "This includes tool poisoning via description manipulation and hidden "
                "directives using invisible Unicode characters or abnormally long "
                "descriptions that contain embedded payloads."
            ),
            "url": "https://owasp.org/www-project-mcp-top-10/#mcp02",
        },
        {
            "id": "MCP03",
            "title": "Excessive Tool Permissions and Scope",
            "description": (
                "MCP tools that declare permissions, capabilities, or data access beyond "
                "what is necessary for their stated function violate the principle of "
                "least privilege. Overly broad tool scopes create a larger blast radius "
                "when a tool is misused or when an agent is compromised via upstream "
                "injection. Tools with no input validation, no output filtering, and "
                "access to multiple sensitive systems amplify every other vulnerability "
                "in the tool layer."
            ),
            "url": "https://owasp.org/www-project-mcp-top-10/#mcp03",
        },
        {
            "id": "MCP04",
            "title": "Injection Attacks via Agent-Controlled Input",
            "description": (
                "MCP tools that accept unrestricted string parameters for shell commands, "
                "file paths, SQL queries, or HTTP endpoints create a direct path from "
                "agent-controlled input to privileged system operations. When an agent "
                "is induced via prompt injection or goal hijacking to call such a tool "
                "with attacker-controlled values, the result is command injection, "
                "path traversal, SSRF, or SQL injection at the tool layer. JSON Schema "
                "input constraints (enum, pattern, maxLength) are the primary mitigation."
            ),
            "url": "https://owasp.org/www-project-mcp-top-10/#mcp04",
        },
        {
            "id": "MCP05",
            "title": "Insecure Authentication and Authorization",
            "description": (
                "MCP servers that do not require authentication for tool invocation, "
                "accept weak or static credentials, or fail to authorize callers against "
                "the tools they invoke allow unauthorized actors to trigger privileged "
                "operations. Servers exposed over plaintext HTTP additionally allow "
                "network attackers to intercept credentials and inject malicious tool "
                "results. Cross-site WebSocket hijacking allows malicious web pages to "
                "invoke local MCP servers without user knowledge."
            ),
            "url": "https://owasp.org/www-project-mcp-top-10/#mcp05",
        },
        {
            "id": "MCP06",
            "title": "Context Window Manipulation and Overflow",
            "description": (
                "Adversaries can manipulate an agent's context window by injecting "
                "malicious content through tool results, retrieved documents, or external "
                "data sources. Large injected payloads can also overflow the context "
                "window, causing earlier system prompt instructions to be dropped. "
                "Attackers exploit this to replace security-critical instructions with "
                "adversarial ones or to cause the model to forget safety constraints "
                "that appeared earlier in the context."
            ),
            "url": "https://owasp.org/www-project-mcp-top-10/#mcp06",
        },
        {
            "id": "MCP07",
            "title": "Insecure Data Handling and Excessive Data Exposure",
            "description": (
                "MCP tools that return entire database records, file contents, or API "
                "responses when only a subset of the data is needed expose sensitive "
                "information to the LLM context — from which it may be reproduced in "
                "outputs, logged, or extracted via prompt injection. Lack of output "
                "filtering, field-level redaction, and data minimization practices "
                "makes this a common source of PII and credential leakage."
            ),
            "url": "https://owasp.org/www-project-mcp-top-10/#mcp07",
        },
        {
            "id": "MCP08",
            "title": "Insecure MCP Component Supply Chain",
            "description": (
                "MCP server packages, remote server URLs, and tool definitions sourced "
                "from external registries without integrity verification are vulnerable "
                "to supply chain compromise. An attacker who poisons a package or "
                "intercepts a server URL can silently introduce malicious tool "
                "definitions that manipulate agent behavior, exfiltrate data, or "
                "establish persistence. Unpinned version specifiers such as 'latest' "
                "or '^1.0' allow compromised updates to be automatically adopted."
            ),
            "url": "https://owasp.org/www-project-mcp-top-10/#mcp08",
        },
        {
            "id": "MCP09",
            "title": "Misconfigured Cross-Origin and Access Policies",
            "description": (
                "MCP servers that accept connections from any origin, lack CORS policies, "
                "or do not validate the origin of WebSocket upgrade requests are "
                "vulnerable to cross-site request forgery and cross-site WebSocket "
                "hijacking. A malicious web page can silently initiate connections to "
                "a locally-running MCP server and invoke tools using the victim's "
                "credentials and session context without the user's knowledge."
            ),
            "url": "https://owasp.org/www-project-mcp-top-10/#mcp09",
        },
        {
            "id": "MCP10",
            "title": "Insufficient Logging and Monitoring of Tool Activity",
            "description": (
                "MCP servers that do not log tool invocations, parameter values, caller "
                "identities, or tool results provide no basis for detecting compromise, "
                "auditing agent behavior, or responding to incidents. Without structured "
                "audit logs, it is impossible to determine whether a tool was invoked "
                "legitimately, what data was accessed, or whether a prompt injection "
                "successfully redirected agent activity. Log tampering and absence of "
                "alerting on anomalous patterns compound this risk."
            ),
            "url": "https://owasp.org/www-project-mcp-top-10/#mcp10",
        },
    ],

    "owasp-agentic": [
        {
            "id": "ASI01",
            "title": "Uncontrolled Memory and Context Manipulation",
            "description": (
                "Agentic AI systems that persist memory across sessions or share context "
                "between agents without validation are vulnerable to poisoning attacks "
                "where adversarial content written to memory in one session influences "
                "behavior in future sessions. Memory stores without access controls "
                "allow one agent to read or overwrite another agent's context, enabling "
                "privilege escalation and cross-agent manipulation."
            ),
            "url": "https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/",
        },
        {
            "id": "ASI02",
            "title": "Tool Misuse and Exploitation",
            "description": (
                "Agents granted access to powerful tools (shell execution, database "
                "write, file system modification, email sending) without appropriate "
                "constraints, confirmation requirements, or scope limitations can be "
                "induced via prompt injection or goal manipulation to misuse those tools "
                "in ways not intended by the system designer. The same capabilities that "
                "make an agent useful also define its potential blast radius when misused."
            ),
            "url": "https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/",
        },
        {
            "id": "ASI03",
            "title": "Inadequate Human Oversight and Approval Gates",
            "description": (
                "Agentic systems that execute irreversible or high-impact actions without "
                "human review — such as sending emails, making purchases, deleting records, "
                "or deploying code — provide no opportunity to catch mistakes or adversarial "
                "manipulation before damage occurs. The absence of configurable approval "
                "gates, action previews, and reversibility mechanisms transforms prompt "
                "injection from an information-disclosure risk into a direct harm risk."
            ),
            "url": "https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/",
        },
        {
            "id": "ASI04",
            "title": "Agentic Supply Chain Vulnerabilities",
            "description": (
                "Multi-agent systems that load sub-agents, tools, or plugins from "
                "external sources at runtime without provenance verification are "
                "vulnerable to supply chain attacks. A compromised orchestration "
                "framework, malicious agent package, or poisoned model artifact can "
                "silently alter the behavior of all agents in the system. Unlike "
                "traditional supply chains, agentic supply chains compose at runtime, "
                "making pre-deployment audits insufficient."
            ),
            "url": "https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/",
        },
        {
            "id": "ASI05",
            "title": "Excessive Autonomy and Uncontrolled Scope Creep",
            "description": (
                "Agents that can independently spawn sub-agents, acquire new tools, "
                "request additional permissions, or extend their own operational scope "
                "may autonomously expand their capabilities beyond the designer's intent. "
                "Without hard limits on recursion depth, tool acquisition, and permission "
                "escalation, a compromised or misaligned agent can progressively "
                "accumulate capabilities and take actions that were never authorized."
            ),
            "url": "https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/",
        },
        {
            "id": "ASI06",
            "title": "Goal Hijacking and Objective Misalignment",
            "description": (
                "Adversaries can manipulate an agent's stated objective through prompt "
                "injection in retrieved content, tool results, or inter-agent messages, "
                "causing the agent to pursue attacker-defined goals while appearing to "
                "work toward its legitimate objective. Long-horizon tasks are especially "
                "vulnerable because the original goal may be forgotten or reframed over "
                "many reasoning steps."
            ),
            "url": "https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/",
        },
        {
            "id": "ASI07",
            "title": "Prompt Injection in Multi-Agent Communication",
            "description": (
                "In multi-agent systems, messages between agents are typically trusted "
                "implicitly. An attacker who can influence the output of one agent can "
                "inject instructions into the input of downstream agents, propagating "
                "the attack across the entire pipeline. Unlike single-agent prompt "
                "injection, multi-agent injection is harder to detect because the "
                "malicious instruction arrives from a trusted peer rather than an "
                "obviously external source."
            ),
            "url": "https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/",
        },
        {
            "id": "ASI08",
            "title": "Sensitive Information Leakage via Agent Context",
            "description": (
                "Agents that accumulate PII, credentials, business-sensitive data, or "
                "system prompts in their context window may inadvertently reproduce this "
                "information in tool parameters, inter-agent messages, or user-visible "
                "outputs. Agents with access to multiple data sources are especially "
                "prone to cross-contamination where data from one source appears in "
                "a response about a different topic."
            ),
            "url": "https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/",
        },
        {
            "id": "ASI09",
            "title": "Insecure Cross-Agent Communication",
            "description": (
                "Inter-agent communication channels that lack authentication, integrity "
                "verification, or encryption allow adversaries to impersonate agents, "
                "replay messages, modify in-transit instructions, or inject rogue agents "
                "into orchestration pipelines. An attacker who can send messages that "
                "appear to originate from a trusted orchestrator agent can direct "
                "worker agents to perform arbitrary actions."
            ),
            "url": "https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/",
        },
        {
            "id": "ASI10",
            "title": "Resource Exhaustion and Denial of Service",
            "description": (
                "Agentic systems without rate limits, budget caps, recursion limits, "
                "or timeout enforcement can be induced to consume unbounded compute, "
                "API credits, memory, or external service quotas. An attacker who can "
                "trigger an agent loop, cause repeated expensive tool calls, or initiate "
                "exponentially branching sub-agent trees can exhaust resources, incur "
                "unexpected costs, or render the agent system unavailable."
            ),
            "url": "https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/",
        },
    ],

    "owasp-llm": [
        {
            "id": "LLM01",
            "title": "Prompt Injection",
            "description": (
                "Prompt injection occurs when an attacker manipulates an LLM through "
                "crafted inputs, causing it to execute unintended actions or override "
                "its original instructions. Direct injection alters system prompts; "
                "indirect injection embeds malicious instructions in external content "
                "the model processes (documents, web pages, tool results)."
            ),
            "url": "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
        },
        {
            "id": "LLM02",
            "title": "Sensitive Information Disclosure",
            "description": (
                "LLMs can inadvertently reveal sensitive information — including PII, "
                "financial records, health data, system prompts, or proprietary business "
                "logic — through their responses. Training data memorization, contextual "
                "oversharing, and insufficient output filtering are primary vectors."
            ),
            "url": "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
        },
        {
            "id": "LLM03",
            "title": "Supply Chain Vulnerabilities",
            "description": (
                "LLM supply chains encompass pre-trained models, fine-tuning datasets, "
                "plugins, tools, and third-party integrations. Compromise at any layer "
                "can introduce vulnerabilities, backdoors, or biases that propagate to "
                "all downstream deployments."
            ),
            "url": "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
        },
        {
            "id": "LLM04",
            "title": "Data and Model Poisoning",
            "description": (
                "Poisoning attacks manipulate the training or fine-tuning data to "
                "introduce backdoors, biases, or malicious behaviors into the model. "
                "Compromised models may behave correctly on most inputs while failing "
                "predictably on specific trigger inputs crafted by the attacker."
            ),
            "url": "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
        },
        {
            "id": "LLM05",
            "title": "Insecure Output Handling",
            "description": (
                "Applications that pass LLM outputs directly to downstream systems "
                "without validation are vulnerable to secondary injection. LLM output "
                "rendered as HTML causes XSS; output passed to shell causes command "
                "injection; output used in SQL causes SQLi. The LLM becomes an "
                "unintentional code-generation surface."
            ),
            "url": "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
        },
        {
            "id": "LLM06",
            "title": "Excessive Agency",
            "description": (
                "Granting an LLM-based agent overly broad permissions, capabilities, "
                "or autonomy enables it to take unintended high-impact actions when "
                "manipulated or misaligned. The principle of least privilege must "
                "apply to agent capabilities, tool access, and permission scopes."
            ),
            "url": "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
        },
        {
            "id": "LLM07",
            "title": "System Prompt Leakage",
            "description": (
                "System prompts containing business logic, safety instructions, "
                "credentials, or proprietary information can be extracted through "
                "direct prompt injection, indirect manipulation, or model responses "
                "that inadvertently reproduce prompt content."
            ),
            "url": "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
        },
        {
            "id": "LLM08",
            "title": "Vector and Embedding Weaknesses",
            "description": (
                "Retrieval-augmented generation (RAG) systems are vulnerable to "
                "embedding-based attacks where adversarial content is injected into "
                "vector stores to influence retrieval results and thereby manipulate "
                "model responses. Poisoned embeddings can cause models to retrieve "
                "and act on attacker-controlled content."
            ),
            "url": "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
        },
        {
            "id": "LLM09",
            "title": "Misinformation and Hallucination",
            "description": (
                "LLMs can generate plausible but false information that users trust "
                "due to the model's authoritative presentation. In security contexts, "
                "hallucinated function signatures, package names, or security "
                "recommendations can lead to vulnerable implementations."
            ),
            "url": "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
        },
        {
            "id": "LLM10",
            "title": "Unbounded Consumption",
            "description": (
                "LLM applications without rate limits, token budgets, or resource "
                "controls are vulnerable to resource exhaustion attacks. Adversarially "
                "crafted inputs that cause excessive computation, large output generation, "
                "or model recursion can degrade availability and incur significant cost."
            ),
            "url": "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
        },
    ],
}


# ---------------------------------------------------------------------------
# Source metadata (mirrors sources.yaml)
# ---------------------------------------------------------------------------

SOURCE_META: dict[str, dict[str, str]] = {
    "owasp-mcp": {
        "name": "OWASP MCP Top 10",
        "source_id": "owasp-mcp",
    },
    "owasp-agentic": {
        "name": "OWASP Top 10 for Agentic Applications",
        "source_id": "owasp-agentic",
    },
    "owasp-llm": {
        "name": "OWASP Top 10 for Large Language Model Applications",
        "source_id": "owasp-llm",
    },
}


# ---------------------------------------------------------------------------
# LLM backends
# ---------------------------------------------------------------------------

class LLMBackend(ABC):
    """Base class for LLM backends. Swap by subclassing."""

    @abstractmethod
    def complete(self, system: str, user: str) -> str:
        """Send system + user prompt; return raw model response."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable backend name for logging."""


class LMStudioBackend(LLMBackend):
    """
    Local model via LMStudio's OpenAI-compatible HTTP API.

    LMStudio uses whatever model is currently loaded — the model parameter
    is sent but ignored. Any string works; we default to 'local-model'.

    Tested with Qwen 3.6 27B (lmstudio-community/Qwen2.5-72B-Instruct-GGUF
    and similar). The /v1/chat/completions endpoint is used directly via
    requests to avoid requiring the openai package.
    """

    def __init__(
        self,
        host: str = "http://localhost:1234",
        model: str = "local-model",
        temperature: float = 0.2,
        max_tokens: int = 2048,
        timeout: int = 120,
    ) -> None:
        self.host        = host.rstrip("/")
        self.model       = model
        self.temperature = temperature
        self.max_tokens  = max_tokens
        self.timeout     = timeout
        self._endpoint   = f"{self.host}/v1/chat/completions"

    @property
    def name(self) -> str:
        return f"LMStudio ({self.host})"

    def complete(self, system: str, user: str) -> str:
        payload = {
            "model":       self.model,
            "temperature": self.temperature,
            "max_tokens":  self.max_tokens,
            "messages": [
                {"role": "system",  "content": system},
                {"role": "user",    "content": user},
            ],
        }
        try:
            resp = requests.post(
                self._endpoint,
                json=payload,
                timeout=self.timeout,
                headers={"Content-Type": "application/json"},
            )
            resp.raise_for_status()
        except requests.exceptions.ConnectionError:
            raise RuntimeError(
                f"Cannot reach LMStudio at {self.host}. "
                "Ensure LMStudio is running and a model is loaded."
            )
        data = resp.json()
        return data["choices"][0]["message"]["content"]


class AnthropicBackend(LLMBackend):
    """
    Anthropic API backend.

    Requires:  pip install -e ".[phase2]"
    Requires:  ANTHROPIC_API_KEY environment variable.

    Uses claude-sonnet-4-20250514 by default. Override with --model.
    """

    DEFAULT_MODEL = "claude-sonnet-4-20250514"

    def __init__(
        self,
        model: str | None = None,
        temperature: float = 0.2,
        max_tokens: int = 2048,
    ) -> None:
        try:
            import anthropic as _anthropic
        except ImportError:
            raise RuntimeError(
                "Anthropic package not installed. "
                "Run: pip install -e '.[phase2]'"
            )

        api_key = os.environ.get("ANTHROPIC_API_KEY")
        if not api_key:
            raise RuntimeError(
                "ANTHROPIC_API_KEY environment variable is not set."
            )

        self._client     = _anthropic.Anthropic(api_key=api_key)
        self.model       = model or self.DEFAULT_MODEL
        self.temperature = temperature
        self.max_tokens  = max_tokens

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
# Rule ID management
# ---------------------------------------------------------------------------

def load_existing_rules() -> list[dict[str, Any]]:
    """Load existing rules from rules.yaml; return empty list if not found."""
    if not RULES_FILE.exists():
        return []
    data = yaml.safe_load(RULES_FILE.read_text(encoding="utf-8"))
    return data.get("rules", []) if data else []


def next_rule_id(existing: list[dict[str, Any]]) -> str:
    """
    Return the next sequential MCPS-NNN ID.
    Scans both rules.yaml and staged/ to avoid collisions.
    """
    used: set[int] = set()

    for rule in existing:
        m = re.match(r"MCPS-(\d+)", rule.get("id", ""))
        if m:
            used.add(int(m.group(1)))

    # Also scan staged files
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
# Prompt construction
# ---------------------------------------------------------------------------

SYSTEM_PROMPT = """\
You are a security rule author for mcp-sentinel, a static analysis tool that \
audits MCP (Model Context Protocol) server definitions for security vulnerabilities.

Your task: given an OWASP security entry, produce a single mcp-sentinel rule \
definition as a JSON object. The rule will be validated against the schema and \
reviewed by a human before use.

OUTPUT FORMAT
-------------
Output ONLY a single valid JSON object. No markdown, no explanation, no \
code fences, no preamble. The JSON must be parseable by json.loads().

SCHEMA
------
{
  "name": "Short descriptive rule name (5-10 words)",
  "severity": "CRITICAL | HIGH | MEDIUM | LOW | INFO",
  "category": "lowercase-hyphenated-category",
  "detection_type": "static | dynamic | both",
  "description": "2-4 sentences explaining the vulnerability and why it matters.",
  "targets": [
    {"field": "tool.description"},
    {"field": "server.url"}
  ],
  "patterns": [
    {
      "type": "regex | value_check | schema_analysis | unicode | length",
      "description": "What this specific pattern detects",
      "expression": "regex pattern string (only for type=regex or schema_analysis)",
      "flags": ["IGNORECASE"],
      "condition": {},
      "threshold_chars": null,
      "severity_override": null
    }
  ],
  "mappings": {
    "SOURCE_ID": {
      "id": "ENTRY_ID",
      "name": "Entry name from source",
      "url": "https://direct-link-to-entry"
    }
  },
  "remediation": "Numbered remediation steps as a single string.",
  "tags": ["tag1", "tag2"]
}

PATTERN TYPES
-------------
regex          - Regex match against a string field value.
                 Required fields: expression (string), flags (list).
                 Example: detect "also when called" in tool descriptions.

length         - Flag strings exceeding a character threshold.
                 Required fields: threshold_chars (int).
                 Example: flag descriptions > 600 chars.

unicode        - Detect invisible/zero-width Unicode characters.
                 No extra fields required.

value_check    - Structured condition against a field value.
                 Required fields: condition (object).
                 Condition keys: value_in (list), missing_fields (list),
                 matches_unpinned (bool).
                 Example: flag version="latest".

schema_analysis - JSON Schema structure evaluation.
                 Required fields: condition (object).
                 Condition keys: field_type, field_name_matches (regex+flags),
                 missing_constraints (list), additionalProperties.
                 Example: string param named "command" with no constraints.

SEVERITY GUIDANCE
-----------------
CRITICAL  - Direct code execution, credential exfiltration, or full agent compromise.
HIGH      - Significant risk with a clear attack path (transport, supply chain, injection).
MEDIUM    - Meaningful risk requiring specific conditions to exploit.
LOW       - Defense-in-depth or informational findings.

TARGETS (common field paths in ServerDefinition)
-----------------
tool.description          - Tool description text (primary target for poisoning)
tool.annotations          - Tool annotation metadata
tool.inputSchema          - Full JSON Schema of tool inputs
tool.inputSchema.properties.* - Individual parameter definitions
server.url                - Server endpoint URL
server.transport          - Transport protocol declaration
server.packages[].version - Declared package versions
server.packages[]         - Full package reference objects
server.env.*              - Environment variable values
server.websocket.origins  - WebSocket allowed origins

EXAMPLE OUTPUT
--------------
{"name":"Tool Poisoning via Description Field","severity":"CRITICAL","category":"tool-integrity","detection_type":"static","description":"MCP tool description fields are treated as authoritative context by the LLM. A malicious server may embed hidden instructions that redirect agent behavior or exfiltrate conversation content.","targets":[{"field":"tool.description"},{"field":"tool.annotations"}],"patterns":[{"type":"regex","description":"Instruction override language in description","expression":"(ignore|override|forget|disregard).{0,60}(system|instructions|previous|above)","flags":["IGNORECASE"],"condition":{},"threshold_chars":null,"severity_override":null},{"type":"length","description":"Suspiciously long description","expression":null,"flags":[],"condition":{},"threshold_chars":600,"severity_override":"MEDIUM"}],"mappings":{"owasp-mcp":{"id":"MCP02","name":"Insecure Tool and Resource Management","url":"https://owasp.org/www-project-mcp-top-10/#mcp02"},"mitre-atlas":{"id":"AML.T0051","name":"LLM Prompt Injection","url":"https://atlas.mitre.org/techniques/AML.T0051"}},"remediation":"(1) Validate tool descriptions against safe patterns. (2) Enforce maximum description length. (3) Scan for invisible Unicode characters.","tags":["tool-poisoning","prompt-injection","static"]}
"""


def build_user_prompt(entry: SourceEntry, rule_id: str) -> str:
    """Build the user-turn prompt for a specific OWASP entry."""
    return f"""\
Generate a mcp-sentinel rule for the following OWASP entry.

RULE ID TO USE: {rule_id}

SOURCE: {entry.source_name} — {entry.entry_id}: {entry.title}
URL: {entry.url}

ENTRY DESCRIPTION:
{entry.description}

MAPPING INSTRUCTIONS:
- Always include a mapping for source_id="{entry.source_id}" with \
entry id="{entry.entry_id}".
- If the vulnerability also relates to MITRE ATLAS, include a mapping \
for source_id="mitre-atlas" with the most relevant AML.T technique.
- If it relates to OWASP LLM Top 10, include a mapping for source_id="owasp-llm".

Generate at least 2 detection patterns. Focus on what can be detected \
statically from an MCP server definition file (tool descriptions, schemas, \
transport config, package declarations). If the vulnerability is not \
statically detectable, set detection_type="dynamic" and write patterns \
that could probe a live server.

Output only the JSON object, nothing else.
"""


# ---------------------------------------------------------------------------
# Response parsing and validation
# ---------------------------------------------------------------------------

def extract_json(text: str) -> dict[str, Any]:
    """
    Extract a JSON object from LLM output.

    Models sometimes wrap output in markdown fences or add preamble
    despite instructions. This handles the common cases.
    """
    # Strip markdown code fences
    text = re.sub(r"^```(?:json)?\s*", "", text.strip(), flags=re.MULTILINE)
    text = re.sub(r"\s*```$", "", text.strip(), flags=re.MULTILINE)
    text = text.strip()

    # Try direct parse
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    # Find first { ... } block
    m = re.search(r"\{.*\}", text, re.DOTALL)
    if m:
        try:
            return json.loads(m.group(0))
        except json.JSONDecodeError:
            pass

    raise ValueError(f"Could not extract valid JSON from model output:\n{text[:300]}")


REQUIRED_FIELDS = {
    "name", "severity", "category", "detection_type",
    "description", "patterns", "mappings", "remediation",
}

VALID_SEVERITIES   = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
VALID_DETECTIONS   = {"static", "dynamic", "both"}
VALID_PATTERN_TYPES = {"regex", "value_check", "schema_analysis", "unicode", "length"}


def validate_rule_dict(rule: dict[str, Any]) -> list[str]:
    """Return a list of validation errors. Empty list means valid."""
    errors: list[str] = []

    missing = REQUIRED_FIELDS - set(rule.keys())
    if missing:
        errors.append(f"Missing required fields: {missing}")

    if rule.get("severity") not in VALID_SEVERITIES:
        errors.append(f"Invalid severity: {rule.get('severity')!r}")

    if rule.get("detection_type") not in VALID_DETECTIONS:
        errors.append(f"Invalid detection_type: {rule.get('detection_type')!r}")

    patterns = rule.get("patterns", [])
    if not isinstance(patterns, list) or len(patterns) == 0:
        errors.append("patterns must be a non-empty list")
    else:
        for i, p in enumerate(patterns):
            if not isinstance(p, dict):
                errors.append(f"patterns[{i}] is not a dict")
                continue
            if p.get("type") not in VALID_PATTERN_TYPES:
                errors.append(
                    f"patterns[{i}].type={p.get('type')!r} not in "
                    f"{VALID_PATTERN_TYPES}"
                )

    if not isinstance(rule.get("mappings"), dict) or not rule["mappings"]:
        errors.append("mappings must be a non-empty dict")

    return errors


# ---------------------------------------------------------------------------
# Rule assembly
# ---------------------------------------------------------------------------

def assemble_rule_yaml(
    rule_dict: dict[str, Any],
    rule_id: str,
    entry: SourceEntry,
) -> dict[str, Any]:
    """
    Merge the LLM-generated dict with required metadata fields.
    Returns a dict ready for yaml.dump().
    """
    today = date.today().isoformat()

    # Clean up patterns: remove null/empty fields
    patterns = []
    for p in rule_dict.get("patterns", []):
        clean = {
            "type":        p.get("type", ""),
            "description": p.get("description", ""),
        }
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

    return {
        "id":             rule_id,
        "name":           rule_dict["name"],
        "status":         "experimental",
        "severity":       rule_dict["severity"],
        "category":       rule_dict.get("category", "uncategorized"),
        "detection_type": rule_dict.get("detection_type", "static"),
        "description":    rule_dict["description"],
        "targets":        rule_dict.get("targets", []),
        "detection":      {"patterns": patterns},
        "mappings":       rule_dict["mappings"],
        "remediation":    rule_dict["remediation"],
        "references":     rule_dict.get("references", [entry.url]),
        "tags":           rule_dict.get("tags", []),
        "added":          today,
        "updated":        today,
    }


# ---------------------------------------------------------------------------
# Main generation pipeline
# ---------------------------------------------------------------------------

def generate_rules(
    source_id: str,
    entry_filter: str | None,
    backend: LLMBackend,
    out_dir: Path,
    dry_run: bool = False,
    delay: float = 1.0,
) -> None:
    """
    Generate rule drafts for all (or one) entries from a source.

    Args:
        source_id:    Which source to process (e.g. "owasp-mcp").
        entry_filter: If set, process only this entry ID (e.g. "MCP03").
        backend:      The LLM backend to use.
        out_dir:      Directory to write staged drafts.
        dry_run:      Print output without writing files.
        delay:        Seconds to wait between API calls (rate limiting).
    """
    if source_id not in BUILT_IN_ENTRIES:
        print(f"ERROR: Unknown source '{source_id}'. "
              f"Available: {', '.join(BUILT_IN_ENTRIES)}", file=sys.stderr)
        sys.exit(1)

    meta      = SOURCE_META[source_id]
    raw_entries = BUILT_IN_ENTRIES[source_id]

    if entry_filter:
        raw_entries = [
            e for e in raw_entries
            if e["id"].upper() == entry_filter.upper()
        ]
        if not raw_entries:
            print(f"ERROR: Entry '{entry_filter}' not found in {source_id}.",
                  file=sys.stderr)
            sys.exit(1)

    entries: list[SourceEntry] = [
        SourceEntry(
            source_id=source_id,
            entry_id=e["id"],
            title=e["title"],
            description=e["description"],
            url=e["url"],
            source_name=meta["name"],
        )
        for e in raw_entries
    ]

    existing_rules = load_existing_rules()
    out_dir.mkdir(parents=True, exist_ok=True)

    total   = len(entries)
    success = 0
    skipped = 0
    failed  = 0

    print(f"\nmcp-sentinel rule generator")
    print(f"Source:  {meta['name']} ({total} entries)")
    print(f"Backend: {backend.name}")
    print(f"Output:  {out_dir}")
    print(f"Mode:    {'DRY RUN' if dry_run else 'write'}")
    print()

    for i, entry in enumerate(entries, 1):
        rule_id = next_rule_id(existing_rules)

        # Check if a draft already exists for this source+entry
        existing_drafts = list(out_dir.glob(f"*-{source_id}-{entry.entry_id}-draft.yaml"))
        if existing_drafts and not dry_run:
            print(f"[{i}/{total}] SKIP  {entry.entry_id}: {entry.title}")
            print(f"           draft already exists: {existing_drafts[0].name}")
            skipped += 1
            continue

        print(f"[{i}/{total}] GEN   {rule_id} <- {entry.entry_id}: {entry.title}")

        try:
            user_prompt = build_user_prompt(entry, rule_id)
            raw_output  = backend.complete(SYSTEM_PROMPT, user_prompt)
        except Exception as exc:
            print(f"           FAIL (LLM error): {exc}")
            failed += 1
            continue

        try:
            rule_dict = extract_json(raw_output)
        except ValueError as exc:
            print(f"           FAIL (parse error): {exc}")
            failed += 1
            continue

        errors = validate_rule_dict(rule_dict)
        if errors:
            print(f"           WARN (validation): {'; '.join(errors)}")
            # Continue anyway — human reviewer will fix

        assembled = assemble_rule_yaml(rule_dict, rule_id, entry)

        if dry_run:
            print(f"           --- DRY RUN OUTPUT ---")
            print(yaml.dump(assembled, default_flow_style=False, allow_unicode=True,
                            indent=2, sort_keys=False))
        else:
            filename = f"{rule_id}-{source_id}-{entry.entry_id}-draft.yaml"
            out_path = out_dir / filename
            out_path.write_text(
                yaml.dump(
                    assembled,
                    default_flow_style=False,
                    allow_unicode=True,
                    indent=2,
                    sort_keys=False,
                ),
                encoding="utf-8",
            )
            print(f"           wrote: {out_path.relative_to(REPO_ROOT)}")

        # Register this ID so the next iteration increments correctly
        existing_rules.append({"id": rule_id})
        success += 1

        if i < total:
            time.sleep(delay)

    print()
    print(f"Done. {success} generated, {skipped} skipped, {failed} failed.")
    if not dry_run and success > 0:
        print(f"\nNext steps:")
        print(f"  1. Review drafts in {out_dir.relative_to(REPO_ROOT)}/")
        print(f"  2. Add malicious fixture for each rule in tests/fixtures/")
        print(f"  3. Promote to rules.yaml: change status to 'active'")
        print(f"  4. Run: mcp-sentinel rules validate")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Batch-generate mcp-sentinel rule drafts from OWASP entries.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )

    parser.add_argument(
        "--source",
        required=True,
        choices=list(BUILT_IN_ENTRIES.keys()),
        help="OWASP source to generate rules from.",
    )
    parser.add_argument(
        "--entry",
        default=None,
        metavar="ID",
        help="Generate only this entry (e.g. MCP03). Omit for all entries.",
    )
    parser.add_argument(
        "--backend",
        choices=["lmstudio", "anthropic"],
        default="lmstudio",
        help="LLM backend (default: lmstudio).",
    )
    parser.add_argument(
        "--host",
        default="http://localhost:1234",
        help="LMStudio base URL (default: http://localhost:1234).",
    )
    parser.add_argument(
        "--model",
        default=None,
        help=(
            "Model name. For LMStudio: ignored (uses loaded model). "
            "For Anthropic: defaults to claude-sonnet-4-20250514."
        ),
    )
    parser.add_argument(
        "--temperature",
        type=float,
        default=0.2,
        help="Sampling temperature (default: 0.2). Lower = more deterministic.",
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=STAGED_DIR,
        help=f"Output directory for drafts (default: {STAGED_DIR}).",
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=1.0,
        help="Seconds between API calls (default: 1.0). Increase for rate limiting.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print generated rules without writing files.",
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="List available entries for a source and exit.",
    )

    args = parser.parse_args()

    if args.list:
        print(f"\n{SOURCE_META[args.source]['name']} entries:\n")
        for e in BUILT_IN_ENTRIES[args.source]:
            print(f"  {e['id']:6}  {e['title']}")
        print()
        return

    # Build backend
    if args.backend == "lmstudio":
        backend: LLMBackend = LMStudioBackend(
            host=args.host,
            model=args.model or "local-model",
            temperature=args.temperature,
        )
    else:
        backend = AnthropicBackend(
            model=args.model,
            temperature=args.temperature,
        )

    generate_rules(
        source_id=args.source,
        entry_filter=args.entry,
        backend=backend,
        out_dir=args.out,
        dry_run=args.dry_run,
        delay=args.delay,
    )


if __name__ == "__main__":
    main()
