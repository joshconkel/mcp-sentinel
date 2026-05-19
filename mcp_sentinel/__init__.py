"""
mcp-sentinel: Security auditor for MCP (Model Context Protocol) servers.

Maps findings to OWASP MCP Top 10, OWASP Agentic Top 10, MITRE ATLAS,
and NIST AI RMF via a pluggable, versioned rule engine.

Usage:
    mcp-sentinel scan --schema ./server-definition.json
    mcp-sentinel rules list
    mcp-sentinel sources check
"""

__version__ = "0.1.0"
__author__ = "Josh Conkel"
