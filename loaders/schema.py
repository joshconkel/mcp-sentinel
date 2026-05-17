"""
schema.py: Load and normalize static MCP server definition files.

Accepts JSON or YAML files. Normalizes them into a ServerDefinition so all
downstream checks operate against a consistent model regardless of input format.

Expected input format (JSON or YAML):

    {
      "server": {
        "name": "my-server",
        "url": "https://api.example.com/mcp",
        "transport": "https",
        "packages": [
          { "name": "@company/mcp-tools", "version": "1.2.3", "integrity": "sha256-..." }
        ],
        "env": { "LOG_LEVEL": "info" },
        "websocket": { "origins": ["https://app.example.com"] }
      },
      "tools": [
        {
          "name": "search_files",
          "description": "Search for files matching a pattern.",
          "inputSchema": {
            "type": "object",
            "properties": { "pattern": { "type": "string", "maxLength": 200 } },
            "required": ["pattern"],
            "additionalProperties": false
          }
        }
      ]
    }

The loader is deliberately lenient: missing keys produce None or empty defaults
rather than hard errors. The checks are responsible for flagging structural issues.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml

from mcp_sentinel.models import (
    PackageReference,
    ServerDefinition,
    ToolDefinition,
)


class LoadError(Exception):
    """Raised when a server definition file cannot be parsed."""


def load(path: str | Path) -> ServerDefinition:
    """
    Parse a JSON or YAML MCP server definition file and return a
    normalized ServerDefinition.

    Raises LoadError on parse failure or unsupported file type.
    """
    path = Path(path)
    if not path.exists():
        raise LoadError(f"File not found: {path}")

    raw = _parse_file(path)
    return _normalize(str(path), raw)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _parse_file(path: Path) -> dict[str, Any]:
    suffix = path.suffix.lower()
    text = path.read_text(encoding="utf-8")

    try:
        if suffix in {".yaml", ".yml"}:
            data = yaml.safe_load(text)
        elif suffix == ".json":
            data = json.loads(text)
        else:
            # Try JSON first, then YAML for unknown extensions.
            try:
                data = json.loads(text)
            except json.JSONDecodeError:
                data = yaml.safe_load(text)
    except Exception as exc:
        raise LoadError(f"Failed to parse {path}: {exc}") from exc

    if not isinstance(data, dict):
        raise LoadError(f"Expected a mapping at the top level of {path}, got {type(data).__name__}")

    return data


def _normalize(source_path: str, raw: dict[str, Any]) -> ServerDefinition:
    server_block: dict[str, Any] = raw.get("server", {}) or {}
    tools_block: list[Any]       = raw.get("tools", []) or []

    # --- server-level fields ---
    url       = server_block.get("url") or None
    transport = server_block.get("transport") or None

    # Infer transport from URL scheme if not explicitly set.
    if transport is None and url:
        if url.startswith("https://") or url.startswith("wss://"):
            transport = "https"
        elif url.startswith("http://"):
            transport = "http"
        elif url.startswith("ws://"):
            transport = "websocket"

    env: dict[str, str] = {}
    raw_env = server_block.get("env", {})
    if isinstance(raw_env, dict):
        env = {str(k): str(v) for k, v in raw_env.items()}

    packages = _parse_packages(server_block.get("packages", []) or [])

    ws_block   = server_block.get("websocket", {}) or {}
    ws_origins = ws_block.get("origins") if isinstance(ws_block, dict) else None

    config = {k: v for k, v in server_block.items()
              if k not in {"url", "transport", "packages", "env", "websocket", "name"}}

    # --- tools ---
    tools = [_parse_tool(t) for t in tools_block if isinstance(t, dict)]

    return ServerDefinition(
        source_path=source_path,
        server_url=url,
        transport=transport,
        tools=tools,
        packages=packages,
        env=env,
        config=config,
        websocket_origins=list(ws_origins) if ws_origins else None,
        raw=raw,
    )


def _parse_packages(raw_packages: list[Any]) -> list[PackageReference]:
    result = []
    for pkg in raw_packages:
        if not isinstance(pkg, dict):
            continue
        result.append(PackageReference(
            name=str(pkg.get("name", "")),
            version=pkg.get("version") or None,
            integrity=pkg.get("integrity") or None,
            registry=pkg.get("registry") or None,
            raw=pkg,
        ))
    return result


def _parse_tool(raw_tool: dict[str, Any]) -> ToolDefinition:
    # MCP spec uses "inputSchema"; also accept "input_schema" for flexibility.
    schema = raw_tool.get("inputSchema") or raw_tool.get("input_schema") or {}
    return ToolDefinition(
        name=str(raw_tool.get("name", "")),
        description=str(raw_tool.get("description", "")),
        input_schema=schema if isinstance(schema, dict) else {},
        annotations=raw_tool.get("annotations", {}) if isinstance(raw_tool.get("annotations"), dict) else {},
        raw=raw_tool,
    )
