"""
live.py: Connect to a running MCP server and discover its tool definitions.

Phase 3 placeholder. The interface is defined here so engine.py and cli.py
can reference it without Phase 3 implementation being required.

When implemented, this module will:
  - Connect to an MCP server via SSE or WebSocket
  - Call list_tools to discover available tools
  - Return a ServerDefinition equivalent to what schema.py produces
  - Enable dynamic check types (MCPS-008 through MCPS-011)
"""

from __future__ import annotations

from mcp_sentinel.models import ServerDefinition


class LiveConnectionError(Exception):
    """Raised when a live MCP server cannot be reached or enumerated."""


def load(url: str, timeout: int = 10) -> ServerDefinition:
    """
    Connect to a live MCP server at `url` and return a ServerDefinition
    populated from its tool list response.

    Phase 3: Not yet implemented.
    """
    raise NotImplementedError(
        "Live server probing is planned for Phase 3. "
        "Use --schema to scan a static server definition file."
    )
