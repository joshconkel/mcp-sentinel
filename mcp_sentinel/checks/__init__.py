"""
Check modules for mcp-sentinel.

Each module implements a `run(server_def, rule) -> list[Finding]` function
that is called by the engine for rules matching that module's rule ID.

The @register decorator maps rule IDs to check functions. The engine
calls get_check(rule_id) without knowing individual module names, so
adding a new check requires only registering it here.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Callable

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
        tool_poisoning,
        secrets,
        parameters,
        transport,
        provenance,
    )
