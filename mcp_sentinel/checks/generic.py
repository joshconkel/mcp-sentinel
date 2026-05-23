"""
generic.py: YAML-driven check module for mcp-sentinel.

Handles rules MCPS-006 through MCPS-122 (and any future rules) whose
detection logic can be fully expressed through the rules.yaml pattern
schema. Resolves target field paths from ServerDefinition and dispatches
each rule's patterns through CheckRunner.

No rule-specific code lives here. Adding a new rule requires only:
  1. An entry in rules.yaml with targets and detection patterns
  2. A line in _GENERIC_RULE_IDS below
  3. A malicious fixture file in tests/fixtures/

Supported target field paths
-----------------------------
  tool.description         All tool description strings
  tool.name                All tool name strings
  tool.annotations         All tool annotation dicts (as string for text patterns)
  tool.inputSchema         All tool input schemas (as dict for schema_analysis)
  server.url               Server URL string
  server.transport         Transport declaration string
  server.config            Server config dict (for value_check/missing_fields)
  server.env               All environment variable values
"""

from __future__ import annotations

from typing import Any

from mcp_sentinel.checks import register
from mcp_sentinel.checks.base import CheckRunner
from mcp_sentinel.models import Finding, RuleDefinition, ServerDefinition

# ---------------------------------------------------------------------------
# Rule IDs handled by this generic module.
# Add new YAML-driven rule IDs here as they are defined in rules.yaml.
# ---------------------------------------------------------------------------

_GENERIC_RULE_IDS: list[str] = [
    "MCPS-006",   # Hidden Instructions in Tool Annotations
    "MCPS-007",   # LLM Jailbreak Trigger Language
    "MCPS-008",   # Credentials Embedded in Server URL
    "MCPS-009",   # Dangerous Tool Name Keywords
    "MCPS-010",   # SSRF via Unrestricted URL Parameter
    "MCPS-011",   # Unfiltered External Content Pass-Through
    "MCPS-012",   # Internal Network Infrastructure Disclosure
    "MCPS-013",   # Unrestricted Filesystem Access Pattern
    "MCPS-014",   # Bulk or Unfiltered Data Return Pattern
    "MCPS-015",   # Insecure Webhook or Callback URL Parameter
    "MCPS-016",   # Capability Self-Grant in Tool Definition
    "MCPS-017",   # Tool Memory Write and Persistence Pattern
    "MCPS-018",   # Numeric Parameter Without Range Constraints
    "MCPS-019",   # Executable Code or Script Parameter
    "MCPS-020",   # Placeholder and Default Credential Values
    "MCPS-021",   # Misconfigured Cross-Origin and CORS Policies
    "MCPS-022",   # Insufficient Logging and Monitoring Indicators
    "MCPS-023",   # Missing Human Oversight for High-Risk Operations
    "MCPS-024",   # Cross-Agent Instruction Propagation Risk
    "MCPS-025",   # Unauthenticated Cross-Agent Communication
    "MCPS-026",   # Untrusted External Source References in Tool Definitions
    "MCPS-027",   # Data and Model Poisoning Patterns in Tool Definitions
    "MCPS-028",   # Misleading Security Claims in Tool Metadata
    "MCPS-029",   # Covert Data Exfiltration via Rendered Image URLs
    "MCPS-030",   # Cloud and AI Service Enumeration via MCP Tools
    "MCPS-031",   # Credential Harvesting via Agent Tool Definitions
    "MCPS-032",   # RAG Poisoning via Tool Description Injection
    "MCPS-033",   # Destructive Tool Invocation via MCP Definition
    "MCPS-034",   # Trusted Output Manipulation via Tool Metadata
    "MCPS-035",   # Deferred Malicious Instructions in Tool Definitions
    "MCPS-036",   # Supply Chain Rug Pull via Package Update
    "MCPS-037",   # Public Code Repository Exposure in MCP Definitions
    "MCPS-038",   # LLM Prompt Crafting via MCP Definition Poisoning
    "MCPS-039",   # Unrestricted Data Access via AI Agent Tools
    "MCPS-040",   # Unrestricted AI Agent Tool Access Definition
    "MCPS-041",   # Covert AI Agent C2 via Hidden Instructions
    "MCPS-042",   # Supply Chain Poisoned MCP Tool Definition
    "MCPS-043",   # Agent Configuration Leakage via Metadata
    "MCPS-044",   # Agent Tool Discovery and Capability Enumeration
    "MCPS-045",   # Hardcoded Application Access Tokens in MCP Definitions
    "MCPS-046",   # Unauthorized AI Agent Deployment Configuration
    "MCPS-047",   # Drive-by Compromise via Web-Fetching Tools
    "MCPS-048",   # Sensitive Data Exposure via Tool Configuration
    "MCPS-049",   # Crafted Retrieval Content in MCP Definitions
    "MCPS-050",   # Poisoned Training Data Ingestion via MCP Tools
    "MCPS-051",   # Delimiter Confusion via Special Character Sets
    "MCPS-052",   # MCP Server Chat History Manipulation Capability
    "MCPS-053",   # MCP Tool Facilitating Dynamic AI Command Generation
    "MCPS-054",   # Detection of Unsafe Execution Sinks in Call Chains
    "MCPS-055",   # Phishing via Impersonation and Social Engineering
    "MCPS-056",   # Supply Chain Compromise via Unpinned Dependencies
    "MCPS-057",   # Self-Replicating Prompt Injection in Tool Definitions
    "MCPS-058",   # Unverified Entity Generation Enabling Hallucination Discovery
    "MCPS-059",   # Suspicious System Instruction Keywords in Tool Definitions
    "MCPS-060",   # LLM System Information Discovery via Tool Definitions
    "MCPS-061",   # Chaff Data Spamming via Tool Definitions
    "MCPS-062",   # MCP Tool Attack Verification and Probing
    "MCPS-063",   # System Prompt Exposure in MCP Definitions
    "MCPS-064",   # Detection of Unauthorized AI Service Proxy Endpoints
    "MCPS-065",   # Active Scanning via MCP Tool Definitions
    "MCPS-066",   # Hardcoded Credentials in MCP Server Definition
    "MCPS-067",   # Staged Capabilities via External Registry References
    "MCPS-068",   # Detects Tools Capable of Generating Deepfakes
    "MCPS-069",   # Unbounded Input Schema Enables Resource Exhaustion
    "MCPS-070",   # Deepfake Phishing Facilitation via MCP Tools
    "MCPS-071",   # MCP Server Proxy Model Staging Detection
    "MCPS-072",   # Model Poisoning via Unverified Weights and Data
    "MCPS-073",   # Overly Permissive Local Agent Tool Definitions
    "MCPS-074",   # Unrestricted Process Enumeration Tool
    "MCPS-075",   # Black-Box Transfer via Adversarial Input Crafting
    "MCPS-076",   # Unsafe AI Artifact Loading via Serialization
    "MCPS-077",   # Unrestricted API Querying for Black-Box Optimization
    "MCPS-078",   # Host Escape via Disabled Safety Controls
    "MCPS-079",   # Adversarial Evasion Triggers in MCP Definitions
    "MCPS-080",   # MCP Tool Impersonation via Deceptive Metadata
    "MCPS-081",   # Adversarial Data Crafting via Tool Definitions
    "MCPS-082",   # Embedded Knowledge Leakage in MCP Definitions
    "MCPS-083",   # Sandbox and VM Evasion in Tool Definitions
    "MCPS-084",   # Deceptive Agent Baiting via Tool Metadata
    "MCPS-085",   # Malicious Link Execution in MCP Definitions
    "MCPS-086",   # Reputation Inflation via Fabricated Trust Signals
    "MCPS-087",   # Model Replication via Unrestricted Inference Tools
    "MCPS-088",   # AI Model and Dataset Exfiltration via MCP Tools
    "MCPS-089",   # Unrestricted RAG Database Access via MCP Tools
    "MCPS-090",   # MCP Server Machine Compromise via Tool Execution
    "MCPS-091",   # Model Extraction via Unrestricted Query Tools
    "MCPS-092",   # Exposed Dataset and Model Artifact References
    "MCPS-093",   # LLM Social Engineering via Tool Metadata
    "MCPS-094",   # Model Artifact Exposure in MCP Definitions
    "MCPS-095",   # User Execution via Unsafe MCP Artifacts
    "MCPS-096",   # Exfiltration via Unrestricted AI Inference API
    "MCPS-097",   # Model Inversion via Confidence Score Exposure
    "MCPS-098",   # Malicious Dependency in MCP Server Packages
    "MCPS-099",   # Hardcoded Credentials in MCP Server Definition
    "MCPS-100",   # Untrusted Data Ingestion in Tool Definitions
    "MCPS-101",   # MCP Tool Schema Lacks Adversarial Input Guards
    "MCPS-102",   # Unrestricted Repository Data Access in MCP Tools
    "MCPS-103",   # Backdoor Trigger Injection in Tool Definitions
    "MCPS-104",   # Uncontrolled MCP Tool Activation Triggers
    "MCPS-105",   # Adversarial AI Attack Vector Detection
    "MCPS-106",   # Compromised Model Loading via Untrusted Dependencies
    "MCPS-107",   # Indirect AI Model Access via Third-Party Service
    "MCPS-108",   # MCP Artifact Masquerading via Metadata Spoofing
    "MCPS-109",   # Model Manipulation and Weight Poisoning Detection
    "MCPS-110",   # Adversarial AI Library Dependency Detection
    "MCPS-111",   # Repurposed Software Tools for AI Attacks
    "MCPS-112",   # Adversarial Input Crafting via Unconstrained Tool Schemas
    "MCPS-113",   # Exposure of AI Model Outputs in MCP Definitions
    "MCPS-114",   # RAG Data Source Enumeration via MCP Definitions
    "MCPS-115",   # Data Exfiltration via External Endpoints
    "MCPS-116",   # AI Artifact Collection via MCP Exposure
    "MCPS-117",   # Exposure of Public AI Artifacts in MCP Definitions
    "MCPS-118",   # White-Box Model Access and Input Exposure
    "MCPS-119",   # Poisoned Model Distribution via MCP Server
    "MCPS-120",   # Financial Fraud and Identity Bypass Detection
    "MCPS-121",   # User Data Exfiltration and Harm via MCP Tools
    "MCPS-122",   # Exposed MCP Server Endpoint Without Authentication
    "MCPS-123",   # AI Software Supply Chain Compromise via MCP Packages
    "MCPS-124",   # Unrestricted Tool Invocation & Code Execution
    "MCPS-125",   # MCP Tool Definition Jailbreak Prompt Detection
    "MCPS-126",   # System Prompt Extraction via Tool Definitions
    "MCPS-127",   # Suspicious Generative AI Model Integration
    "MCPS-128",   # Prompt Obfuscation via Encoding and Hidden Characters
    "MCPS-129",   # False RAG Entry Injection via MCP Ingestion Tools
    "MCPS-130",   # AI Agent Context Poisoning via Tool Definitions
    "MCPS-131",   # Persistent Thread Poisoning via Tool Definitions
    "MCPS-132",   # RAG Credential Harvesting via Unfiltered Ingestion
    "MCPS-133",   # Hardcoded Credentials in MCP Configuration
    "MCPS-134",   # Data Exfiltration via Tool Input Parameters
    "MCPS-135",   # Prompt Infiltration via Untrusted Data Ingestion
    "MCPS-136",   # Supply Chain Poisoned MCP Tool Detection
    "MCPS-137",   # Supply Chain Compromise via Poisoned MCP Tool
    "MCPS-138",   # AI Agent Configuration Tampering Detection
    "MCPS-139",   # Exposed AI Agent Configuration and Secrets
    "MCPS-140",   # Agentic Resource Consumption via Tool Directives
    "MCPS-141",   # Persistent Memory Manipulation via MCP Tools
    "MCPS-142",   # Unsecured AI Inference API Exposure in MCP Tools
    "MCPS-143",   # Cost Harvesting via Unbounded Tool Execution
    "MCPS-144",   # MCP Tool Definition Prompt Injection Detection
    "MCPS-145",   # OS Credential Dumping via MCP Tool Definitions
    "MCPS-146",   # MCP Tool Definition Supply Chain Poisoning
    "MCPS-147",   # Triggered Prompt Injection via Event Hooks
    "MCPS-148",   # Data Poisoning via Untrusted Tool Data Sources
    "MCPS-149",   # Direct Prompt Injection via Tool Metadata
    "MCPS-150",   # Indirect Prompt Injection via External Data Ingestion
]

# ---------------------------------------------------------------------------
# Field extractor
# ---------------------------------------------------------------------------

def _extract_values(
    server_def: ServerDefinition,
    field_path: str,
) -> list[tuple[str, Any, Any]]:
    """
    Resolve a target field path to a list of (field_path, value, tool_or_None).

    Returns multiple results when the path refers to a per-tool field
    (e.g. "tool.description" returns one entry per tool in the definition).
    Returns an empty list if the field has no value.

    Args:
        server_def:  Normalized server definition.
        field_path:  Dot-notation field path from the rule's targets block.

    Returns:
        List of (resolved_field_path, value, ToolDefinition_or_None) tuples.
    """
    results: list[tuple[str, Any, Any]] = []

    # ── Tool-level fields ────────────────────────────────────────────────────

    if field_path == "tool.description":
        for tool in server_def.tools:
            if tool.description:
                results.append((field_path, tool.description, tool))

    elif field_path == "tool.name":
        for tool in server_def.tools:
            if tool.name:
                results.append((field_path, tool.name, tool))

    elif field_path == "tool.annotations":
        for tool in server_def.tools:
            if tool.annotations:
                # Convert to string for text-based patterns;
                # dict form is also available if needed for future pattern types.
                results.append((field_path, str(tool.annotations), tool))

    elif field_path == "tool.inputSchema":
        for tool in server_def.tools:
            if tool.input_schema:
                results.append((field_path, tool.input_schema, tool))

    # ── Server-level fields ──────────────────────────────────────────────────

    elif field_path == "server.url":
        if server_def.server_url:
            results.append((field_path, server_def.server_url, None))

    elif field_path == "server.transport":
        if server_def.transport:
            results.append((field_path, server_def.transport, None))

    elif field_path == "server.config":
        if server_def.config:
            results.append((field_path, server_def.config, None))

    elif field_path == "server.env":
        # Scan each environment variable value independently so findings
        # can reference the specific variable key.
        for key, val in server_def.env.items():
            if val:
                results.append((f"server.env.{key}", val, None))

    elif field_path == "server.packages[]":
        # Used by MCPS-005 (provenance); included here for completeness if
        # future generic rules target the packages list.
        for pkg in server_def.packages:
            pkg_dict = {
                "name":      pkg.name,
                "version":   pkg.version or "",
                "integrity": pkg.integrity,
            }
            results.append((f"server.packages[{pkg.name}]", pkg_dict, None))

    # ── Per-tool parameter defaults (from input schema) ──────────────────────

    elif field_path == "tool.inputSchema.properties.*":
        # Expands to each parameter's default value for secret scanning.
        for tool in server_def.tools:
            props = tool.input_schema.get("properties", {}) or {}
            for prop_name, prop_def in props.items():
                if not isinstance(prop_def, dict):
                    continue
                if "default" in prop_def:
                    results.append((
                        f"tool.inputSchema.properties.{prop_name}.default",
                        str(prop_def["default"]),
                        tool,
                    ))
                if "description" in prop_def:
                    results.append((
                        f"tool.inputSchema.properties.{prop_name}.description",
                        str(prop_def["description"]),
                        tool,
                    ))

    return results


# ---------------------------------------------------------------------------
# Generic check function
# ---------------------------------------------------------------------------

def _run_generic(server_def: ServerDefinition, rule: RuleDefinition) -> list[Finding]:
    """
    YAML-driven check dispatcher.

    For each target field declared in the rule, extracts all matching values
    from server_def and runs every detection pattern against each value.
    Produces one Finding per (target_field, tool, pattern) combination that
    matches.
    """
    from mcp_sentinel.engine import _build_active_sources  # avoid circular at module level

    active_sources = _build_active_sources()
    runner = CheckRunner(rule, active_sources)
    findings: list[Finding] = []

    # Resolve target fields from the rule definition.
    # Fall back to tool.description if no targets are declared.
    targets = [t.get("field", "") for t in rule.targets if t.get("field")]
    if not targets:
        targets = ["tool.description"]

    seen: set[tuple[str, str | None]] = set()  # (field_path, tool_name) dedup key

    for target_field in targets:
        field_values = _extract_values(server_def, target_field)

        for field_path, value, tool in field_values:
            for pattern in rule.patterns:
                finding = runner.run_pattern(pattern, value, field_path, tool)
                if finding is None:
                    continue

                # Deduplicate: one finding per (field, tool) per rule run.
                # Multiple patterns can match the same field — keep the first
                # (highest-severity patterns are ordered first in rules.yaml).
                dedup_key = (field_path, tool.name if tool else None)
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)

                findings.append(finding)

    return findings


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------
# Register the generic function for all rule IDs in _GENERIC_RULE_IDS.
# The function uses rule.targets and rule.patterns (loaded from rules.yaml)
# to determine behavior, so no per-rule Python logic is needed.

for _rule_id in _GENERIC_RULE_IDS:
    register(_rule_id)(_run_generic)
