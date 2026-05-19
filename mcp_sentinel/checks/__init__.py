"""
Check modules for mcp-sentinel.

Each module implements a `run(server_def, rule) -> list[Finding]` function
that is called by the engine for rules matching that module's rule ID.

The @register decorator maps rule IDs to check functions. The engine
calls get_check(rule_id) without knowing individual module names, so
adding a new check requires only registering it here.

Dedicated modules (MCPS-001 to MCPS-005)
-----------------------------------------
Rules with complex Python-level detection logic that cannot be expressed
purely through the YAML pattern schema have dedicated check modules.

Generic module (MCPS-006 to MCPS-020 and beyond)
--------------------------------------------------
Rules whose detection logic is fully expressed in rules.yaml (targets +
detection patterns) are handled by checks/generic.py. Adding a new rule
in this category requires only an entry in rules.yaml and a line in
generic._GENERIC_RULE_IDS. No new Python file is needed.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from mcp_sentinel.models import Finding, RuleDefinition, ServerDefinition

# Type alias for a check function
CheckFn = Callable[["ServerDefinition", "RuleDefinition"], list["Finding"]]

# Populated by each check module at import time via @register
_REGISTRY: dict[str, CheckFn] = {}


def register(rule_id: str) -> Callable[[CheckFn], CheckFn]:
    """Decorator: register a check function for a specific rule ID."""
    def decorator(fn: CheckFn) -> CheckFn:
        _REGISTRY[rule_id] = fn
        return fn
    return decorator


def get_check(rule_id: str) -> CheckFn | None:
    """Return the registered check function for a rule ID, or None."""
    _ensure_loaded()
    return _REGISTRY.get(rule_id)


def _ensure_loaded() -> None:
    """Import all check modules so their @register decorators fire."""
    if _REGISTRY:
        return
    from mcp_sentinel.checks import (  # noqa: F401
        generic,
        parameters,
        provenance,
        secrets,
        tool_poisoning,
        transport,
    )
