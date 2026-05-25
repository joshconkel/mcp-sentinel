"""
Core data models for mcp-sentinel.

All components (loaders, checks, engine, reporter) share these types.
Nothing in this module has external dependencies beyond the standard library.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    INFO     = "INFO"

    @property
    def score(self) -> int:
        """Points contributed to the overall risk score per finding."""
        return {
            Severity.CRITICAL: 25,
            Severity.HIGH:     10,
            Severity.MEDIUM:    4,
            Severity.LOW:       1,
            Severity.INFO:      0,
        }[self]

    @property
    def color(self) -> str:
        """Rich terminal color for this severity level."""
        return {
            Severity.CRITICAL: "bold red",
            Severity.HIGH:     "red",
            Severity.MEDIUM:   "yellow",
            Severity.LOW:      "cyan",
            Severity.INFO:     "dim",
        }[self]


class RuleStatus(str, Enum):
    ACTIVE       = "active"
    EXPERIMENTAL = "experimental"
    DEPRECATED   = "deprecated"


class DetectionType(str, Enum):
    STATIC  = "static"
    DYNAMIC = "dynamic"
    BOTH    = "both"


# ---------------------------------------------------------------------------
# Server definition models (output of the loader layer)
# ---------------------------------------------------------------------------

@dataclass
class PackageReference:
    """A package dependency declared in the MCP server definition."""
    name:      str
    version:   str | None = None
    integrity: str | None = None   # e.g. sha256-<hash>
    registry:  str | None = None
    raw:       dict[str, Any] = field(default_factory=dict)


@dataclass
class ToolDefinition:
    """A single tool exposed by the MCP server."""
    name:         str
    description:  str                    = ""
    input_schema: dict[str, Any]         = field(default_factory=dict)
    annotations:  dict[str, Any]         = field(default_factory=dict)
    raw:          dict[str, Any]         = field(default_factory=dict)


@dataclass
class ServerDefinition:
    """
    Normalized intermediate representation of any MCP server definition.

    Produced by the loader layer (loaders/schema.py or loaders/live.py)
    and consumed by the rule engine. All checks operate against this model,
    never against raw input directly.
    """
    source_path: str
    server_url:  str | None                = None
    transport:   str | None                = None   # http | https | stdio | websocket
    tools:       list[ToolDefinition]      = field(default_factory=list)
    packages:    list[PackageReference]    = field(default_factory=list)
    env:         dict[str, str]            = field(default_factory=dict)
    config:      dict[str, Any]            = field(default_factory=dict)
    raw:         dict[str, Any]            = field(default_factory=dict)

    # WebSocket-specific (checked by MCPS-004)
    websocket_origins: list[str] | None    = None


# ---------------------------------------------------------------------------
# Finding models (output of the check layer)
# ---------------------------------------------------------------------------

@dataclass
class SourceMapping:
    """
    Maps a finding to a specific entry in a threat intelligence source.
    Resolved by the engine from the rule's `mappings` block + the source registry.
    """
    source_id:   str   # e.g. "owasp-mcp"
    source_name: str   # e.g. "OWASP MCP Top 10"
    entry_id:    str   # e.g. "MCP02"
    entry_name:  str   # e.g. "Insecure Tool & Resource Management"
    entry_url:   str


# dataclasses.field is saved here because the Finding dataclass declares an
# attribute also named 'field: str', which would shadow the factory function
# inside the class body and cause a mypy "str not callable" error on the
# source_mappings default.
_dc_field = field


@dataclass
class Finding:
    """
    A single security finding produced by a check.

    One rule run may produce multiple findings (e.g., multiple tools
    each triggering MCPS-001 with different matched patterns).
    """
    rule_id:        str
    rule_name:      str
    severity:       Severity
    field:          str              # e.g. "tool.description"
    tool_name:      str | None       # None for server-level findings
    match:          str | None       # The matched value or substring
    detail:         str              # Human-readable finding explanation
    source_mappings: list[SourceMapping] = _dc_field(default_factory=list)
    remediation:    str              = ""
    experimental:   bool             = False   # True if rule status is experimental


# ---------------------------------------------------------------------------
# Risk scoring model (output of the engine)
# ---------------------------------------------------------------------------

@dataclass
class RiskScore:
    """
    Aggregated risk score for a scanned server definition.

    overall is capped at 100 and intended for relative comparison and
    dashboard display, not as a definitive risk rating.
    """
    overall:     int
    by_severity: dict[Severity, int]   # count of findings per severity
    by_tool:     dict[str, int]        # count of findings per tool name
    findings:    list[Finding]

    @classmethod
    def from_findings(cls, findings: list[Finding]) -> RiskScore:
        raw_score = sum(f.severity.score for f in findings)
        by_sev: dict[Severity, int] = {s: 0 for s in Severity}
        by_tool: dict[str, int] = {}

        for f in findings:
            by_sev[f.severity] += 1
            key = f.tool_name or "(server)"
            by_tool[key] = by_tool.get(key, 0) + 1

        return cls(
            overall=min(raw_score, 100),
            by_severity=by_sev,
            by_tool=by_tool,
            findings=findings,
        )

    @property
    def risk_label(self) -> str:
        if self.overall >= 75:
            return "CRITICAL"
        if self.overall >= 40:
            return "HIGH"
        if self.overall >= 15:
            return "MEDIUM"
        if self.overall > 0:
            return "LOW"
        return "CLEAN"


# ---------------------------------------------------------------------------
# Rule / source registry models (loaded from YAML)
# ---------------------------------------------------------------------------

@dataclass
class PatternDefinition:
    """A single detection pattern within a rule's detection block."""
    type:             str                 # regex | value_check | schema_analysis | unicode | length
    description:      str                 = ""
    # regex fields
    expression:       str | None          = None
    flags:            list[str]           = field(default_factory=list)
    # value_check fields
    condition:        dict[str, Any]      = field(default_factory=dict)
    # length fields
    threshold_chars:  int | None          = None
    # unicode fields
    flag_codepoints:  list[str]           = field(default_factory=list)
    # optional per-pattern severity override
    severity_override: Severity | None    = None
    applies_to:       str | None          = None
    notes:            str                 = ""


@dataclass
class RuleDefinition:
    """A rule loaded from rules.yaml."""
    id:             str
    name:           str
    status:         RuleStatus
    severity:       Severity
    category:       str
    detection_type: DetectionType
    description:    str
    targets:        list[dict[str, str]]
    patterns:       list[PatternDefinition]
    mappings:       dict[str, dict[str, str]]   # source_id -> {id, name, url, notes?}
    remediation:    str
    references:     list[str]                   = field(default_factory=list)
    tags:           list[str]                   = field(default_factory=list)
    added:          str                         = ""
    updated:        str                         = ""


@dataclass
class SourceDefinition:
    """A threat intelligence source loaded from sources.yaml."""
    id:               str
    name:             str
    description:      str
    url:              str
    version:          str
    entry_prefix:     str
    entry_format:     str
    update_frequency: str
    last_checked:     str
    active:           bool
    github:           str | None = None
