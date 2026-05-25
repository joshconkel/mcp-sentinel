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

Security notes:
    - Regex patterns are compiled once at CheckRunner construction time
      rather than at every call to run_pattern(). This catches malformed
      patterns early and avoids redundant compilation.
    - Regex flags are validated against an explicit allowlist (_SAFE_RE_FLAGS)
      before use. getattr(re, flag_name) is not used to prevent arbitrary
      attribute access on the re module (e.g., accessing re.purge, which is
      a callable, would cause a TypeError when ORed into an int flags value).
    - Regex execution uses a thread-based timeout (_REGEX_TIMEOUT_SECS) to
      guard against catastrophic backtracking on attacker-controlled input.
      When a pattern times out it is treated as a non-match and a WARNING
      is logged; the scan continues.
    - Pattern length is bounded by _MAX_PATTERN_LEN to provide a first line
      of defence against complex patterns before execution begins.
"""

from __future__ import annotations

import concurrent.futures
import logging
import re
import unicodedata
from typing import Any

from mcp_sentinel.models import (
    Finding,
    PatternDefinition,
    RuleDefinition,
    SourceMapping,
    ToolDefinition,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Security constants
# ---------------------------------------------------------------------------

# Maximum character length allowed for a compiled regex pattern.
# Patterns longer than this are rejected at compile time.
_MAX_PATTERN_LEN: int = 1_000

# Seconds before a running regex match is considered timed out.
# The match thread is abandoned (not killed), but the result is discarded
# and treated as a non-match. Adjust upward if legitimate patterns are slow
# on large inputs.
_REGEX_TIMEOUT_SECS: float = 2.0

# Explicit allowlist of regex flag names permitted in rule definitions.
# Using an allowlist rather than getattr(re, flag_name) prevents:
#   1. Access to callables on the re module (e.g., re.purge) which would
#      raise TypeError when ORed into an integer flags value.
#   2. Access to private or implementation attributes.
_SAFE_RE_FLAGS: dict[str, re.RegexFlag] = {
    "IGNORECASE": re.IGNORECASE,
    "MULTILINE":  re.MULTILINE,
    "DOTALL":     re.DOTALL,
    "VERBOSE":    re.VERBOSE,
    "ASCII":      re.ASCII,
    "UNICODE":    re.UNICODE,
    # Common abbreviations
    "I": re.IGNORECASE,
    "M": re.MULTILINE,
    "S": re.DOTALL,
    "X": re.VERBOSE,
    "A": re.ASCII,
    "U": re.UNICODE,
}

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

# Shared thread-pool executor for timed regex execution.
# Using a module-level executor avoids creating a new pool per match call.
# max_workers=1 keeps resource usage minimal; regex matches are sequential.
_regex_executor = concurrent.futures.ThreadPoolExecutor(
    max_workers=1,
    thread_name_prefix="mcp-sentinel-regex",
)


# ---------------------------------------------------------------------------
# Helper: build integer flags from an allowlisted list of flag name strings
# ---------------------------------------------------------------------------

def _build_re_flags(flag_names: list[str], pattern_desc: str = "") -> int:
    """
    Convert a list of flag name strings into a combined re.RegexFlag integer.

    Only names in _SAFE_RE_FLAGS are accepted. Unrecognised names are logged
    as warnings and skipped rather than raising an exception, so a single
    bad flag does not abort the entire scan.
    """
    flags = 0
    for name in flag_names:
        flag = _SAFE_RE_FLAGS.get(name.upper())
        if flag is None:
            logger.warning(
                "Unrecognised regex flag %r in pattern %r — skipping.",
                name,
                pattern_desc,
            )
            continue
        flags |= flag
    return flags


# ---------------------------------------------------------------------------
# Helper: compile and cache regex patterns
# ---------------------------------------------------------------------------

def _compile_pattern(expression: str, flags: int, description: str = "") -> re.Pattern[str] | None:
    """
    Compile expression into a re.Pattern, returning None on failure.

    Validates pattern length before compilation to reject excessively
    complex patterns that could cause slow compilation or catastrophic
    backtracking.
    """
    if len(expression) > _MAX_PATTERN_LEN:
        logger.warning(
            "Regex pattern for %r exceeds maximum length (%d > %d) — skipping.",
            description,
            len(expression),
            _MAX_PATTERN_LEN,
        )
        return None
    try:
        return re.compile(expression, flags)
    except re.error as exc:
        logger.warning("Invalid regex pattern for %r: %s — skipping.", description, exc)
        return None


# ---------------------------------------------------------------------------
# Helper: execute a compiled regex with a timeout
# ---------------------------------------------------------------------------

def _timed_search(
    compiled: re.Pattern[str],
    value: str,
) -> re.Match[str] | None:
    """
    Run compiled.search(value) in a worker thread with a timeout.

    Returns the Match object on success, or None if no match or if the
    operation times out. Timeouts are logged as warnings.

    The worker thread is not forcibly killed on timeout (Python does not
    support that), but the result is discarded and the scan continues.
    """
    future = _regex_executor.submit(compiled.search, value)
    try:
        return future.result(timeout=_REGEX_TIMEOUT_SECS)
    except concurrent.futures.TimeoutError:
        logger.warning(
            "Regex pattern %r timed out after %.1fs on input of length %d — treating as no-match.",
            compiled.pattern,
            _REGEX_TIMEOUT_SECS,
            len(value),
        )
        return None


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

class CheckRunner:
    """
    Dispatches PatternDefinitions to their appropriate handler and builds
    Finding objects with resolved source mappings.

    All regex patterns are compiled once at construction time. A pattern
    that fails to compile is skipped with a warning rather than aborting
    the scan. Regex execution is subject to _REGEX_TIMEOUT_SECS to guard
    against catastrophic backtracking.
    """

    def __init__(self, rule: RuleDefinition, active_sources: dict[str, Any]) -> None:
        self.rule = rule
        self.active_sources = active_sources
        # Pre-compile all regex patterns; store compiled form keyed by pattern id.
        # Patterns that fail to compile are stored as None and skipped at match time.
        self._compiled: dict[int, re.Pattern[str] | None] = {}
        for pattern in rule.patterns:
            if pattern.type == "regex":
                expression = pattern.expression or ""
                if not expression:
                    self._compiled[id(pattern)] = None
                    continue
                flags = _build_re_flags(pattern.flags, pattern.description)
                self._compiled[id(pattern)] = _compile_pattern(
                    expression, flags, pattern.description
                )
            elif pattern.type == "schema_analysis":
                # schema_analysis patterns store their match regex in
                # condition.field_name_matches.regex, not in pattern.expression.
                # Previously, pattern.expression was always None for these, so
                # _compiled stored None and _check_schema bailed out immediately.
                fnm = (pattern.condition or {}).get("field_name_matches") or {}
                expression = fnm.get("regex", "") if isinstance(fnm, dict) else ""
                if not expression:
                    self._compiled[id(pattern)] = None
                    continue
                flags = _build_re_flags(
                    fnm.get("flags", []) if isinstance(fnm, dict) else [],
                    pattern.description,
                )
                self._compiled[id(pattern)] = _compile_pattern(
                    expression, flags, pattern.description
                )

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
            if isinstance(value, dict):
                return None  # Regex checks are only meaningful on string values
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
        compiled = self._compiled.get(id(pattern))
        if compiled is None:
            return None
        m = _timed_search(compiled, value)
        return m.group(0) if m else None

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
        if "value_in" in cond and str(value) in [str(v) for v in cond["value_in"]]:
            return str(value)

        # missing_fields: a dict must be missing expected keys
        if "missing_fields" in cond and isinstance(value, dict):
            missing = [k for k in cond["missing_fields"] if k not in value]
            if missing:
                return f"missing: {', '.join(missing)}"

        # matches_unpinned: version string matches unpinned patterns
        if (
            cond.get("matches_unpinned")
            and isinstance(value, str)
            and (not value or UNPINNED_VERSION_PATTERNS.match(value))
        ):
            return value or "(empty)"

        return None

    def _check_schema(self, pattern: PatternDefinition, schema: dict[str, Any]) -> str | None:
        cond = pattern.condition
        if not cond:
            return None

        properties: dict[str, Any] = schema.get("properties", {})

        # Flag string properties with dangerous names that lack constraints
        if "field_name_matches" in cond and "missing_constraints" in cond:
            compiled = self._compiled.get(id(pattern))
            if compiled is None:
                return None
            required_constraints = cond["missing_constraints"]

            for prop_name, prop_def in properties.items():
                if not isinstance(prop_def, dict):
                    continue
                m = _timed_search(compiled, prop_name)
                if not m:
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
