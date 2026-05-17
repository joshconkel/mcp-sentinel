"""
base.py: CheckRunner and pattern type handler implementations.

The CheckRunner dispatches each PatternDefinition to the correct handler
based on its `type` field. All check modules call into this base rather
than implementing pattern matching independently.

Supported pattern types (Phase 1):
    regex           - regex match against a string value
    value_check     - structured condition against a field value
    schema_analysis - JSON Schema structure evaluation
    unicode         - invisible/zero-width character detection
    length          - string length threshold check

Phase 3 will add:
    dynamic         - live server probe (loaders/live.py + checks/dynamic.py)
"""

from __future__ import annotations

import re
import unicodedata
from typing import Any

from mcp_sentinel.models import (
    Finding,
    PatternDefinition,
    RuleDefinition,
    Severity,
    SourceMapping,
    ToolDefinition,
)

# ---------------------------------------------------------------------------
# Invisible / zero-width Unicode codepoints flagged by the unicode check type
# ---------------------------------------------------------------------------
INVISIBLE_CODEPOINTS: set[int] = {
    0x200B,  # ZERO WIDTH SPACE
    0x200C,  # ZERO WIDTH NON-JOINER
    0x200D,  # ZERO WIDTH JOINER
    0xFEFF,  # ZERO WIDTH NO-BREAK SPACE (BOM)
    0x2060,  # WORD JOINER
    0x00AD,  # SOFT HYPHEN
    0x180E,  # MONGOLIAN VOWEL SEPARATOR
    0x2028,  # LINE SEPARATOR
    0x2029,  # PARAGRAPH SEPARATOR
}

# Version strings that indicate an unpinned dependency
UNPINNED_VERSION_PATTERNS = re.compile(
    r"^(\*|latest|x|next|canary|\^[\d]|~[\d]|>=[\d]|>[\d])",
    re.IGNORECASE,
)

# Parameter names that suggest dangerous capabilities requiring constraints
DANGEROUS_PARAM_PATTERN = re.compile(
    r"(command|cmd|shell|exec|query|sql|path|file|url|endpoint|script|eval|code|input|payload)",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

class CheckRunner:
    """
    Dispatches PatternDefinitions to their appropriate handler and builds
    Finding objects with resolved source mappings.
    """

    def __init__(self, rule: RuleDefinition, active_sources: dict[str, Any]) -> None:
        self.rule = rule
        self.active_sources = active_sources

    def run_pattern(
        self,
        pattern: PatternDefinition,
        value: str | dict[str, Any] | None,
        field: str,
        tool: ToolDefinition | None = None,
    ) -> Finding | None:
        """
        Run a single pattern against a value. Returns a Finding or None.
        """
        if value is None:
            return None

        matched: str | None = None

        if pattern.type == "regex":
            matched = self._check_regex(pattern, str(value))
        elif pattern.type == "length":
            matched = self._check_length(pattern, str(value))
        elif pattern.type == "unicode":
            matched = self._check_unicode(str(value))
        elif pattern.type == "value_check":
            matched = self._check_value(pattern, value)
        elif pattern.type == "schema_analysis":
            matched = self._check_schema(pattern, value if isinstance(value, dict) else {})
        else:
            return None

        if matched is None:
            return None

        severity = pattern.severity_override or self.rule.severity

        return Finding(
            rule_id=self.rule.id,
            rule_name=self.rule.name,
            severity=severity,
            field=field,
            tool_name=tool.name if tool else None,
            match=matched[:200] if matched else None,  # cap match length in output
            detail=pattern.description,
            source_mappings=self._resolve_mappings(),
            remediation=self.rule.remediation,
            experimental=(self.rule.status.value == "experimental"),
        )

    # -----------------------------------------------------------------------
    # Pattern type implementations
    # -----------------------------------------------------------------------

    def _check_regex(self, pattern: PatternDefinition, value: str) -> str | None:
        if not pattern.expression:
            return None
        flags = 0
        for f in pattern.flags:
            flags |= getattr(re, f, 0)
        m = re.search(pattern.expression, value, flags)
        if m:
            return m.group(0)
        return None

    def _check_length(self, pattern: PatternDefinition, value: str) -> str | None:
        threshold = pattern.threshold_chars or 0
        if len(value) > threshold:
            return f"length={len(value)} (threshold={threshold})"
        return None

    def _check_unicode(self, value: str) -> str | None:
        found = []
        for ch in value:
            cp = ord(ch)
            if cp in INVISIBLE_CODEPOINTS:
                name = unicodedata.name(ch, f"U+{cp:04X}")
                found.append(f"U+{cp:04X} ({name})")
        if found:
            return ", ".join(found[:5])  # cap at 5 for readability
        return None

    def _check_value(self, pattern: PatternDefinition, value: Any) -> str | None:
        cond = pattern.condition
        if not cond:
            return None

        # value_in: field value must be one of a set
        if "value_in" in cond:
            if str(value) in [str(v) for v in cond["value_in"]]:
                return str(value)

        # missing_fields: a dict must be missing expected keys
        if "missing_fields" in cond and isinstance(value, dict):
            missing = [k for k in cond["missing_fields"] if k not in value]
            if missing:
                return f"missing: {', '.join(missing)}"

        # matches_unpinned: version string matches unpinned patterns
        if cond.get("matches_unpinned") and isinstance(value, str):
            if not value or UNPINNED_VERSION_PATTERNS.match(value):
                return value or "(empty)"

        return None

    def _check_schema(self, pattern: PatternDefinition, schema: dict[str, Any]) -> str | None:
        cond = pattern.condition
        if not cond:
            return None

        properties: dict[str, Any] = schema.get("properties", {})

        # Flag string properties with dangerous names that lack constraints
        if "field_name_matches" in cond and "missing_constraints" in cond:
            name_pattern = cond["field_name_matches"].get("regex", "")
            name_flags = 0
            for f in cond["field_name_matches"].get("flags", []):
                name_flags |= getattr(re, f, 0)
            required_constraints = cond["missing_constraints"]

            for prop_name, prop_def in properties.items():
                if not isinstance(prop_def, dict):
                    continue
                if not re.search(name_pattern, prop_name, name_flags):
                    continue
                if prop_def.get("type") != cond.get("field_type", prop_def.get("type")):
                    continue
                # Check if ALL required constraints are missing
                has_any = any(c in prop_def for c in required_constraints)
                if not has_any:
                    return f"property '{prop_name}' lacks {required_constraints}"

        # Flag schemas where additionalProperties is not set to false
        if cond.get("additionalProperties") == "true_or_missing":
            additional = schema.get("additionalProperties")
            if additional is not False:
                return f"additionalProperties={additional!r} (should be false)"

        return None

    # -----------------------------------------------------------------------
    # Source mapping resolution
    # -----------------------------------------------------------------------

    def _resolve_mappings(self) -> list[SourceMapping]:
        mappings = []
        for source_id, entry in self.rule.mappings.items():
            source = self.active_sources.get(source_id)
            if source is None:
                continue   # source not active; skip mapping silently
            mappings.append(SourceMapping(
                source_id=source_id,
                source_name=source["name"],
                entry_id=entry.get("id", ""),
                entry_name=entry.get("name", ""),
                entry_url=entry.get("url", ""),
            ))
        return mappings
