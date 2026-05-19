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

Security notes:
  - yaml.safe_load is used; yaml.load with arbitrary Loaders is never called.
  - File size is bounded by MAX_FILE_BYTES (default 10 MB) to prevent
    memory exhaustion from deliberately oversized input files.
  - The number of tools in a definition is bounded by MAX_TOOLS to prevent
    quadratic-time scans against pathologically large definitions.
  - The resolved path is verified to be an absolute path (Path.resolve())
    before reading; this surfacing does not prevent access to arbitrary
    filesystem paths for a CLI tool (which is by design), but ensures the
    path is canonical and logged accurately.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

import yaml

from mcp_sentinel.models import (
    PackageReference,
    ServerDefinition,
    ToolDefinition,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Safety limits for untrusted input files
# ---------------------------------------------------------------------------

# Maximum file size accepted. Files larger than this raise LoadError before
# any parsing begins, preventing memory exhaustion from crafted inputs.
MAX_FILE_BYTES: int = 10 * 1024 * 1024   # 10 MB

# Maximum number of tool definitions parsed from a single server definition.
# Additional tools beyond this limit are silently dropped with a warning.
MAX_TOOLS: int = 500


class LoadError(Exception):
    """Raised when a server definition file cannot be parsed."""


def load(path: str | Path) -> ServerDefinition:
    """
    Parse a JSON or YAML MCP server definition file and return a
    normalized ServerDefinition.

    Raises LoadError on parse failure, file-not-found, or if the file
    exceeds safety limits.
    """
    path = Path(path).resolve()

    if not path.exists():
        raise LoadError(f"File not found: {path}")

    if not path.is_file():
        raise LoadError(f"Path is not a regular file: {path}")

    # Guard against memory exhaustion from oversized input files.
    file_size = path.stat().st_size
    if file_size > MAX_FILE_BYTES:
        raise LoadError(
            f"File exceeds maximum allowed size "
            f"({file_size:,} bytes > {MAX_FILE_BYTES:,} bytes): {path}"
        )

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
            # safe_load prevents arbitrary Python object construction.
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
        raise LoadError(
            f"Expected a mapping at the top level of {path}, "
            f"got {type(data).__name__}"
        )

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

    config = {
        k: v for k, v in server_block.items()
        if k not in {"url", "transport", "packages", "env", "websocket", "name"}
    }

    # --- tools (bounded by MAX_TOOLS) ---
    raw_tools = [t for t in tools_block if isinstance(t, dict)]
    if len(raw_tools) > MAX_TOOLS:
        logger.warning(
            "Server definition contains %d tools; only the first %d will be scanned "
            "(MAX_TOOLS=%d). Adjust MAX_TOOLS in loaders/schema.py if needed.",
            len(raw_tools),
            MAX_TOOLS,
            MAX_TOOLS,
        )
        raw_tools = raw_tools[:MAX_TOOLS]

    tools = [_parse_tool(t) for t in raw_tools]

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
        annotations=(
            raw_tool.get("annotations", {})
            if isinstance(raw_tool.get("annotations"), dict)
            else {}
        ),
        raw=raw_tool,
    )
