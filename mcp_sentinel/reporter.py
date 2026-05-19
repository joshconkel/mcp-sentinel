"""
reporter.py: Output formatters for mcp-sentinel scan results.

Three formatters derive from BaseFormatter:
  TerminalReporter  - Rich-formatted human-readable output (default)
  JsonReporter      - Machine-readable JSON for CI/CD pipelines
  HtmlReporter      - Stakeholder-facing HTML report with Jinja2

Security notes:
  - HtmlReporter uses Jinja2 Environment(autoescape=True) to prevent XSS.
    All template variables are HTML-escaped before rendering.
  - Source mapping URLs are validated to only permit https:// and http://
    schemes before being rendered as href attributes, preventing
    javascript: URI injection.
  - Timestamps use datetime.now(timezone.utc) (utcnow() is deprecated
    in Python 3.12+).

Usage (from engine output):
    score = engine.scan(server_def)
    TerminalReporter().report(score, source_path="my-server.json")
    JsonReporter().report(score, out_path=Path("results.json"))
    HtmlReporter().report(score, out_path=Path("report.html"))
"""

from __future__ import annotations

import json
import logging
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from mcp_sentinel.models import Finding, RiskScore, Severity

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Color / label helpers shared across formatters
# ---------------------------------------------------------------------------

SEVERITY_COLORS: dict[Severity, str] = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH:     "red",
    Severity.MEDIUM:   "yellow",
    Severity.LOW:      "cyan",
    Severity.INFO:     "dim",
}

SEVERITY_HTML_COLORS: dict[str, str] = {
    "CRITICAL": "#dc2626",
    "HIGH":     "#ea580c",
    "MEDIUM":   "#ca8a04",
    "LOW":      "#0891b2",
    "INFO":     "#6b7280",
}

RISK_LABEL_COLORS: dict[str, str] = {
    "CRITICAL": "bold red",
    "HIGH":     "red",
    "MEDIUM":   "yellow",
    "LOW":      "cyan",
    "CLEAN":    "bold green",
}

# URL schemes permitted in href attributes in the HTML report.
# javascript: and data: are explicitly excluded to prevent XSS.
_ALLOWED_URL_SCHEMES: frozenset[str] = frozenset({"https", "http"})


def _sanitize_url(url: str) -> str:
    """
    Return url if its scheme is in _ALLOWED_URL_SCHEMES, otherwise '#'.

    Prevents javascript: and data: URI injection in HTML href attributes.
    The Jinja2 autoescaping handles HTML-entity encoding; this function
    handles scheme-level injection independently.
    """
    if not url:
        return "#"
    try:
        scheme = urlparse(url).scheme.lower()
    except ValueError:
        return "#"
    return url if scheme in _ALLOWED_URL_SCHEMES else "#"


# ---------------------------------------------------------------------------
# Base formatter
# ---------------------------------------------------------------------------

class BaseFormatter(ABC):
    @abstractmethod
    def report(self, score: RiskScore, **kwargs: Any) -> None:
        """Produce output from a RiskScore. kwargs vary by formatter."""


# ---------------------------------------------------------------------------
# Terminal reporter (Rich)
# ---------------------------------------------------------------------------

class TerminalReporter(BaseFormatter):
    """
    Human-readable terminal output using the Rich library.
    Designed to be scannable in 30 seconds by a developer in a CI log.
    """

    def report(
        self,
        score: RiskScore,
        source_path: str = "",
        show_remediation: bool = False,
        **kwargs: Any,
    ) -> None:
        from rich.console import Console
        from rich.rule import Rule
        import mcp_sentinel

        console = Console()

        # Header
        console.print()
        console.print(
            f"[bold]mcp-sentinel[/bold] v{mcp_sentinel.__version__}  "
            f"[dim]|[/dim]  MCP Server Security Auditor"
        )
        if source_path:
            console.print(f"[dim]Scanning:[/dim] {source_path}")
        console.print(Rule(style="dim"))

        if not score.findings:
            console.print("[bold green]No findings. Server definition looks clean.[/bold green]")
            console.print(Rule(style="dim"))
            self._print_summary(console, score)
            return

        # Findings
        for finding in sorted(score.findings, key=lambda f: list(Severity).index(f.severity)):
            self._print_finding(console, finding, show_remediation)

        console.print(Rule(style="dim"))
        self._print_summary(console, score)

    def _print_finding(self, console: Any, f: Finding, show_remediation: bool) -> None:
        sev_color = SEVERITY_COLORS.get(f.severity, "white")
        exp_tag = " [dim](experimental)[/dim]" if f.experimental else ""

        console.print(
            f"\n[{sev_color}][{f.severity.value:8}][/{sev_color}]  "
            f"[bold]{f.rule_id}[/bold]  {f.rule_name}{exp_tag}"
        )
        if f.tool_name:
            console.print(f"{'':12}[dim]Tool:[/dim]   {f.tool_name}")
        console.print(f"{'':12}[dim]Field:[/dim]  {f.field}")
        if f.match:
            match_display = f.match[:80] + "..." if len(f.match) > 80 else f.match
            console.print(f"{'':12}[dim]Match:[/dim]  {match_display}")
        console.print(f"{'':12}[dim]Detail:[/dim] {f.detail}")

        if f.source_mappings:
            mapping_strs = [f"{m.source_name} {m.entry_id}" for m in f.source_mappings]
            console.print(f"{'':12}[dim]Maps to:[/dim] {' · '.join(mapping_strs)}")

        if show_remediation and f.remediation:
            console.print(f"{'':12}[dim]Remediation:[/dim] {f.remediation[:200]}")

    def _print_summary(self, console: Any, score: RiskScore) -> None:
        from rich import box
        from rich.table import Table

        console.print("\n[bold]Risk Summary[/bold]")

        table = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
        table.add_column(style="bold", min_width=10)
        table.add_column(justify="right", min_width=4)
        table.add_column(min_width=20)

        bar_char = "█"
        for sev in Severity:
            count = score.by_severity.get(sev, 0)
            if count == 0 and sev == Severity.INFO:
                continue
            bar_len = min(count * 2, 20)
            bar = bar_char * bar_len + "░" * (20 - bar_len)
            color = SEVERITY_COLORS.get(sev, "white")
            table.add_row(
                f"[{color}]{sev.value}[/{color}]",
                f"[{color}]{count}[/{color}]",
                f"[{color}]{bar[:10]}[/{color}]",
            )

        console.print(table)

        label_color = RISK_LABEL_COLORS.get(score.risk_label, "white")
        console.print(
            f"\n[bold]Overall Risk Score:[/bold]  "
            f"[{label_color}]{score.overall} / 100  [{score.risk_label}][/{label_color}]"
        )
        console.print(
            f"[dim]Findings: {len(score.findings)} "
            f"across {len(score.by_tool)} tool(s)[/dim]\n"
        )


# ---------------------------------------------------------------------------
# JSON reporter
# ---------------------------------------------------------------------------

class JsonReporter(BaseFormatter):
    """
    Machine-readable JSON output for CI/CD pipelines.
    Exit code handling is done in cli.py based on the returned score.
    """

    def report(
        self,
        score: RiskScore,
        out_path: Path | None = None,
        source_path: str = "",
        **kwargs: Any,
    ) -> None:
        output = {
            "meta": {
                "tool": "mcp-sentinel",
                "source": source_path,
                # Fix: datetime.utcnow() is deprecated in Python 3.12+.
                # Use datetime.now(timezone.utc) instead.
                "generated": datetime.now(timezone.utc).isoformat(),
            },
            "score": {
                "overall": score.overall,
                "label": score.risk_label,
                "by_severity": {k.value: v for k, v in score.by_severity.items()},
            },
            "findings": [self._finding_to_dict(f) for f in score.findings],
        }

        text = json.dumps(output, indent=2)
        if out_path:
            out_path.write_text(text, encoding="utf-8")
        else:
            print(text)

    def _finding_to_dict(self, f: Finding) -> dict[str, Any]:
        return {
            "rule_id":      f.rule_id,
            "rule_name":    f.rule_name,
            "severity":     f.severity.value,
            "field":        f.field,
            "tool_name":    f.tool_name,
            "match":        f.match,
            "detail":       f.detail,
            "experimental": f.experimental,
            "mappings": [
                {
                    "source_id":   m.source_id,
                    "source_name": m.source_name,
                    "entry_id":    m.entry_id,
                    "entry_name":  m.entry_name,
                    # Sanitize URLs in JSON output for consistency with HTML output.
                    "entry_url":   _sanitize_url(m.entry_url),
                }
                for m in f.source_mappings
            ],
            "remediation": f.remediation,
        }


# ---------------------------------------------------------------------------
# HTML reporter (Jinja2 with autoescape=True)
# ---------------------------------------------------------------------------

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta http-equiv="Content-Security-Policy"
      content="default-src 'none'; style-src 'unsafe-inline'; script-src 'none';">
<title>mcp-sentinel Report: {{ source_path }}</title>
<style>
  :root {
    --bg: #0f172a; --surface: #1e293b; --border: #334155;
    --text: #e2e8f0; --muted: #94a3b8;
    --critical: #dc2626; --high: #ea580c;
    --medium: #ca8a04; --low: #0891b2; --info: #6b7280;
    --clean: #16a34a;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: var(--bg); color: var(--text); font-family: 'Segoe UI', system-ui, sans-serif;
         font-size: 14px; line-height: 1.6; padding: 2rem; }
  h1 { font-size: 1.5rem; font-weight: 700; margin-bottom: 0.25rem; }
  h2 { font-size: 1rem; font-weight: 600; color: var(--muted); margin: 1.5rem 0 0.75rem; }
  .meta { color: var(--muted); font-size: 0.85rem; margin-bottom: 1.5rem; }
  .score-card { background: var(--surface); border: 1px solid var(--border);
                border-radius: 8px; padding: 1.25rem 1.5rem; display: inline-block;
                margin-bottom: 1.5rem; }
  .score-label { font-size: 2rem; font-weight: 700; }
  .sev-grid { display: flex; gap: 1rem; flex-wrap: wrap; margin-bottom: 1.5rem; }
  .sev-chip { background: var(--surface); border: 1px solid var(--border);
               border-radius: 6px; padding: 0.5rem 1rem; text-align: center; min-width: 80px; }
  .sev-chip .count { font-size: 1.5rem; font-weight: 700; }
  .sev-chip .label { font-size: 0.75rem; color: var(--muted); }
  .finding { background: var(--surface); border: 1px solid var(--border);
              border-radius: 8px; padding: 1rem 1.25rem; margin-bottom: 0.75rem;
              border-left: 4px solid var(--border); }
  .finding-header { display: flex; align-items: baseline; gap: 0.75rem; margin-bottom: 0.5rem; }
  .badge { font-size: 0.7rem; font-weight: 700; padding: 2px 8px; border-radius: 4px;
           background: var(--border); }
  .rule-id { font-weight: 700; font-family: monospace; }
  .rule-name { color: var(--muted); }
  .field { font-family: monospace; font-size: 0.85rem; color: var(--muted); }
  .match-val { font-family: monospace; background: #0f172a; padding: 2px 6px;
               border-radius: 4px; font-size: 0.85rem; word-break: break-all; }
  .mappings { margin-top: 0.5rem; display: flex; flex-wrap: wrap; gap: 0.4rem; }
  .mapping-tag { background: #1e3a5f; color: #93c5fd; font-size: 0.75rem;
                 padding: 1px 8px; border-radius: 12px; }
  .remediation { margin-top: 0.75rem; padding: 0.75rem; background: #0f172a;
                 border-radius: 6px; color: var(--muted); font-size: 0.85rem;
                 border-left: 3px solid var(--border); }
  .clean { color: var(--clean); font-size: 1.1rem; font-weight: 600; }
  footer { margin-top: 2rem; color: var(--muted); font-size: 0.8rem;
           border-top: 1px solid var(--border); padding-top: 1rem; }
</style>
</head>
<body>
<h1>mcp-sentinel Security Report</h1>
<div class="meta">
  Source: <strong>{{ source_path }}</strong> &nbsp;|&nbsp;
  Generated: {{ generated }} &nbsp;|&nbsp;
  mcp-sentinel v{{ version }}
</div>

<div class="score-card">
  <div class="score-label" style="color: {{ score_color }}">
    {{ score.overall }} / 100 &nbsp; [{{ score.risk_label }}]
  </div>
  <div style="color: var(--muted); font-size: 0.85rem; margin-top: 0.25rem;">
    {{ findings|length }} finding(s) across {{ by_tool|length }} tool(s)
  </div>
</div>

<div class="sev-grid">
{% for sev, count in by_severity.items() %}
  <div class="sev-chip">
    <div class="count" style="color: {{ sev_colors[sev] }}">{{ count }}</div>
    <div class="label">{{ sev }}</div>
  </div>
{% endfor %}
</div>

{% if findings %}
<h2>Findings</h2>
{% for f in findings %}
<div class="finding" style="border-left-color: {{ sev_colors[f.severity] }}">
  <div class="finding-header">
    <span class="badge" style="color: {{ sev_colors[f.severity] }}">{{ f.severity }}</span>
    <span class="rule-id">{{ f.rule_id }}</span>
    <span class="rule-name">{{ f.rule_name }}</span>
    {% if f.experimental %}<span class="badge" style="color: var(--muted)">experimental</span>{% endif %}
  </div>
  {% if f.tool_name %}<div><span style="color:var(--muted)">Tool:</span> {{ f.tool_name }}</div>{% endif %}
  <div><span style="color:var(--muted)">Field:</span> <span class="field">{{ f.field }}</span></div>
  {% if f.match %}<div style="margin-top:0.25rem"><span style="color:var(--muted)">Match:</span>
    <span class="match-val">{{ f.match[:120] }}{% if f.match|length > 120 %}...{% endif %}</span>
  </div>{% endif %}
  <div style="margin-top:0.25rem; color:var(--muted)">{{ f.detail }}</div>
  {% if f.source_mappings %}
  <div class="mappings">
    {% for m in f.source_mappings %}
    {# safe_url is pre-validated in Python to only permit https/http schemes. #}
    <a href="{{ m.safe_url }}" class="mapping-tag" target="_blank" rel="noopener noreferrer">
      {{- m.source_name }} {{ m.entry_id -}}
    </a>
    {% endfor %}
  </div>
  {% endif %}
  {% if f.remediation %}
  <div class="remediation"><strong>Remediation:</strong>
    {{ f.remediation[:400] }}{% if f.remediation|length > 400 %}... (see THREAT-MODEL.md for full guidance){% endif %}
  </div>
  {% endif %}
</div>
{% endfor %}
{% else %}
<p class="clean">No findings detected. Server definition looks clean.</p>
{% endif %}

<footer>
  Generated by
  <a href="https://github.com/joshconkel/mcp-sentinel" style="color: #60a5fa"
     rel="noopener noreferrer">mcp-sentinel</a>.
  Findings mapped to OWASP MCP Top 10, OWASP Agentic Top 10 2026, MITRE ATLAS, and NIST AI RMF.
</footer>
</body>
</html>"""


class _FindingView:
    """
    Wraps a Finding for safe template rendering.

    Exposes all Finding attributes plus pre-sanitized source mapping URLs.
    Used by HtmlReporter to avoid passing raw Finding objects directly into
    the Jinja2 context, which would expose unsanitized entry_url values.
    """
    __slots__ = (
        "rule_id", "rule_name", "severity", "field", "tool_name",
        "match", "detail", "experimental", "remediation", "source_mappings",
    )

    def __init__(self, finding: Finding) -> None:
        self.rule_id        = finding.rule_id
        self.rule_name      = finding.rule_name
        self.severity       = finding.severity.value
        self.field          = finding.field
        self.tool_name      = finding.tool_name
        self.match          = finding.match
        self.detail         = finding.detail
        self.experimental   = finding.experimental
        self.remediation    = finding.remediation
        # Pre-sanitize URLs so the template never receives a javascript: href.
        self.source_mappings = [
            _MappingView(m) for m in finding.source_mappings
        ]


class _MappingView:
    """Wraps a SourceMapping with a pre-validated safe_url attribute."""

    __slots__ = ("source_id", "source_name", "entry_id", "entry_name", "safe_url")

    def __init__(self, mapping: Any) -> None:
        self.source_id   = mapping.source_id
        self.source_name = mapping.source_name
        self.entry_id    = mapping.entry_id
        self.entry_name  = mapping.entry_name
        # Validate scheme before exposing as href. Blocks javascript:/data: URIs.
        self.safe_url    = _sanitize_url(mapping.entry_url)


class HtmlReporter(BaseFormatter):
    """
    Jinja2-rendered HTML report for stakeholder distribution.

    Security hardening:
      - Environment(autoescape=True) escapes all {{ }} interpolations as HTML
        entities, preventing XSS from untrusted finding content.
      - Source mapping URLs are validated to https/http schemes only via
        _FindingView / _MappingView before being passed to the template.
      - A Content-Security-Policy meta tag in the template blocks inline
        scripts and disallows external resource loads.
    """

    def report(
        self,
        score: RiskScore,
        out_path: Path | None = None,
        source_path: str = "",
        **kwargs: Any,
    ) -> None:
        # Fix: Use Environment(autoescape=True) instead of Template() directly.
        # Template() uses autoescape=False by default (Semgrep rule:
        # python.jinja2.security.audit.autoescape-disabled).
        from jinja2 import BaseLoader, Environment
        import mcp_sentinel

        env = Environment(autoescape=True, loader=BaseLoader())
        template = env.from_string(HTML_TEMPLATE)

        score_color = SEVERITY_HTML_COLORS.get(score.risk_label, "#6b7280")
        if score.risk_label == "CLEAN":
            score_color = "#16a34a"

        html = template.render(
            source_path=source_path,
            # Fix: datetime.utcnow() deprecated in Python 3.12+.
            generated=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
            version=mcp_sentinel.__version__,
            score=score,
            # Use _FindingView wrappers so template receives pre-sanitized URLs.
            findings=[_FindingView(f) for f in score.findings],
            by_severity={k.value: v for k, v in score.by_severity.items()},
            by_tool=score.by_tool,
            sev_colors=SEVERITY_HTML_COLORS,
            score_color=score_color,
        )

        if out_path:
            out_path.write_text(html, encoding="utf-8")
            logger.info("HTML report written to: %s", out_path)
        else:
            print(html)


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------

def get_reporter(fmt: str) -> BaseFormatter:
    """Return the appropriate reporter for a format string."""
    fmt = fmt.lower()
    if fmt == "json":
        return JsonReporter()
    if fmt == "html":
        return HtmlReporter()
    return TerminalReporter()
