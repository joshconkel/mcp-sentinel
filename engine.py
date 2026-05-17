"""
engine.py: The rule engine for mcp-sentinel.

Responsibilities:
  1. Load sources.yaml into a source registry (dict[source_id, SourceDefinition])
  2. Load rules.yaml into a rule set (list[RuleDefinition])
  3. For each active rule, dispatch to its registered check function
  4. Collect all findings and produce a RiskScore

The engine is the only component that knows about both the rule definitions
(YAML) and the check implementations (Python). Loaders and reporters are
independent of the engine.
"""

from __future__ import annotations

import importlib.resources
from pathlib import Path
from typing import Any

import yaml

from mcp_sentinel.models import (
    DetectionType,
    Finding,
    PatternDefinition,
    RiskScore,
    RuleDefinition,
    RuleStatus,
    ServerDefinition,
    Severity,
    SourceDefinition,
)

# ---------------------------------------------------------------------------
# Path resolution: rules/ directory ships inside the package
# ---------------------------------------------------------------------------

def _rules_dir() -> Path:
    """Return the path to the rules/ directory bundled with the package."""
    # When installed: rules/ is alongside the mcp_sentinel/ package directory
    pkg_dir = Path(__file__).parent
    candidates = [
        pkg_dir / "rules",          # development layout
        pkg_dir.parent / "rules",   # installed layout
    ]
    for candidate in candidates:
        if candidate.exists():
            return candidate
    raise FileNotFoundError(
        "Could not locate the rules/ directory. "
        "Ensure the package was installed with `pip install -e .` or that "
        "rules/sources.yaml and rules/rules.yaml are present."
    )


# ---------------------------------------------------------------------------
# Loaders for YAML rule definitions
# ---------------------------------------------------------------------------

def load_sources(path: Path | None = None) -> dict[str, dict[str, Any]]:
    """
    Load sources.yaml and return a dict keyed by source id.
    Only sources with active=true are included.
    """
    sources_path = path or (_rules_dir() / "sources.yaml")
    data = yaml.safe_load(sources_path.read_text(encoding="utf-8"))
    result: dict[str, dict[str, Any]] = {}
    for source in data.get("sources", []):
        if source.get("active", True):
            result[source["id"]] = source
    return result


def load_rules(path: Path | None = None) -> list[RuleDefinition]:
    """
    Load rules.yaml and return a list of RuleDefinition objects.
    Skips rules with status=deprecated.
    """
    rules_path = path or (_rules_dir() / "rules.yaml")
    data = yaml.safe_load(rules_path.read_text(encoding="utf-8"))
    rules: list[RuleDefinition] = []

    for raw in data.get("rules", []):
        status = RuleStatus(raw.get("status", "active"))
        if status == RuleStatus.DEPRECATED:
            continue

        severity = Severity(raw.get("severity", "MEDIUM"))
        detection_type = DetectionType(raw.get("detection_type", "static"))

        patterns = _parse_patterns(raw.get("detection", {}).get("patterns", []))

        rules.append(RuleDefinition(
            id=raw["id"],
            name=raw["name"],
            status=status,
            severity=severity,
            category=raw.get("category", ""),
            detection_type=detection_type,
            description=raw.get("description", ""),
            targets=raw.get("targets", []),
            patterns=patterns,
            mappings=raw.get("mappings", {}),
            remediation=raw.get("remediation", ""),
            references=raw.get("references", []),
            tags=raw.get("tags", []),
            added=str(raw.get("added", "")),
            updated=str(raw.get("updated", "")),
        ))

    return rules


def _parse_patterns(raw_patterns: list[dict[str, Any]]) -> list[PatternDefinition]:
    patterns = []
    for p in raw_patterns:
        severity_override: Severity | None = None
        if "severity_override" in p:
            severity_override = Severity(p["severity_override"])

        patterns.append(PatternDefinition(
            type=p.get("type", ""),
            description=p.get("description", ""),
            expression=p.get("expression"),
            flags=p.get("flags", []),
            condition=p.get("condition", {}),
            threshold_chars=p.get("threshold_chars"),
            flag_codepoints=p.get("flag_codepoints", []),
            severity_override=severity_override,
            applies_to=p.get("applies_to"),
            notes=p.get("notes", ""),
        ))
    return patterns


# ---------------------------------------------------------------------------
# Module-level cache for active sources (used by check modules)
# ---------------------------------------------------------------------------

_active_sources_cache: dict[str, Any] | None = None


def _build_active_sources(path: Path | None = None) -> dict[str, Any]:
    """Return (and cache) the active source registry."""
    global _active_sources_cache
    if _active_sources_cache is None:
        _active_sources_cache = load_sources(path)
    return _active_sources_cache


# ---------------------------------------------------------------------------
# Main engine entry point
# ---------------------------------------------------------------------------

def scan(
    server_def: ServerDefinition,
    rules_path: Path | None = None,
    sources_path: Path | None = None,
) -> RiskScore:
    """
    Run all active rules against server_def and return a RiskScore.

    Args:
        server_def:   Normalized server definition from the loader layer.
        rules_path:   Override path to rules.yaml (defaults to bundled file).
        sources_path: Override path to sources.yaml (defaults to bundled file).

    Returns:
        RiskScore containing all findings and aggregated scores.
    """
    global _active_sources_cache
    _active_sources_cache = load_sources(sources_path)

    rules = load_rules(rules_path)

    # Ensure all check modules are imported so @register decorators fire
    from mcp_sentinel.checks import _ensure_loaded, get_check
    _ensure_loaded()

    all_findings: list[Finding] = []

    for rule in rules:
        check_fn = get_check(rule.id)
        if check_fn is None:
            # Rule defined in YAML but no Python check implementation yet
            # (expected for rules added before their check module is written)
            continue

        try:
            findings = check_fn(server_def, rule)
            all_findings.extend(findings)
        except Exception as exc:
            # A failing check should not abort the entire scan
            # Log and continue; in production this would go to a structured logger
            import sys
            print(f"[WARNING] Check {rule.id} raised an exception: {exc}", file=sys.stderr)

    return RiskScore.from_findings(all_findings)


# ---------------------------------------------------------------------------
# Utility: source staleness check (used by `mcp-sentinel sources check`)
# ---------------------------------------------------------------------------

def check_source_staleness(
    sources_path: Path | None = None,
    warn_after_days: int = 120,
) -> list[dict[str, str]]:
    """
    Return a list of sources whose last_checked date is older than warn_after_days.
    """
    from datetime import date, datetime

    sources = load_sources(sources_path)
    stale = []
    today = date.today()

    for source_id, source in sources.items():
        last_checked_str = source.get("last_checked", "")
        if not last_checked_str:
            stale.append({"id": source_id, "name": source["name"], "reason": "no last_checked date"})
            continue
        try:
            last_checked = datetime.strptime(str(last_checked_str), "%Y-%m-%d").date()
            delta = (today - last_checked).days
            if delta > warn_after_days:
                stale.append({
                    "id": source_id,
                    "name": source["name"],
                    "reason": f"last checked {delta} days ago (threshold: {warn_after_days})",
                })
        except ValueError:
            stale.append({"id": source_id, "name": source["name"], "reason": f"unparseable date: {last_checked_str}"})

    return stale
