"""
cli.py: Command-line interface for mcp-sentinel.

Commands:
    scan            Scan a static MCP server definition file
    rules list      Show all active rules with source mappings
    rules validate  Validate rules.yaml against the schema
    sources check   Flag threat sources that may be out of date
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Optional

import typer
from rich.console import Console
from rich.table import Table
from rich import box

app = typer.Typer(
    name="mcp-sentinel",
    help="Security auditor for MCP (Model Context Protocol) servers.",
    add_completion=False,
    rich_markup_mode="rich",
)

rules_app = typer.Typer(help="Manage and inspect rule definitions.")
app.add_typer(rules_app, name="rules")

console = Console()


# ---------------------------------------------------------------------------
# scan command
# ---------------------------------------------------------------------------

@app.command()
def scan(
    schema: Path = typer.Option(
        ...,
        "--schema", "-s",
        help="Path to MCP server definition file (JSON or YAML).",
        exists=True,
        readable=True,
    ),
    report: str = typer.Option(
        "terminal",
        "--report", "-r",
        help="Output format: terminal | json | html",
    ),
    out: Optional[Path] = typer.Option(
        None,
        "--out", "-o",
        help="Write report to this file (required for json/html output to disk).",
    ),
    fail_on: str = typer.Option(
        "CRITICAL",
        "--fail-on",
        help="Exit with code 1 if any finding at or above this severity is found. "
             "Values: CRITICAL | HIGH | MEDIUM | LOW | INFO | NONE",
    ),
    show_remediation: bool = typer.Option(
        False,
        "--remediation",
        help="Include remediation text in terminal output.",
    ),
    rules_path: Optional[Path] = typer.Option(
        None, "--rules", help="Override path to rules.yaml."
    ),
    sources_path: Optional[Path] = typer.Option(
        None, "--sources", help="Override path to sources.yaml."
    ),
) -> None:
    """
    Scan a static MCP server definition file for security issues.

    Examples:

        mcp-sentinel scan --schema ./my-server.json

        mcp-sentinel scan --schema ./my-server.json --report html --out ./report.html

        mcp-sentinel scan --schema ./my-server.json --report json --fail-on HIGH
    """
    from mcp_sentinel.loaders.schema import load, LoadError
    from mcp_sentinel.engine import scan as engine_scan
    from mcp_sentinel.reporter import get_reporter
    from mcp_sentinel.models import Severity

    # Load server definition
    try:
        server_def = load(schema)
    except LoadError as exc:
        console.print(f"[red]Error loading schema:[/red] {exc}")
        raise typer.Exit(2) from None

    # Run the scan
    score = engine_scan(server_def, rules_path=rules_path, sources_path=sources_path)

    # Produce report
    reporter = get_reporter(report)
    reporter_kwargs: dict[str, Any] = {
        "source_path": str(schema),
        "show_remediation": show_remediation,
    }
    if out:
        reporter_kwargs["out_path"] = out

    reporter.report(score, **reporter_kwargs)

    # Exit code logic
    if fail_on.upper() == "NONE":
        raise typer.Exit(0)

    try:
        threshold = Severity(fail_on.upper())
    except ValueError:
        console.print(f"[red]Unknown --fail-on value:[/red] {fail_on}")
        raise typer.Exit(2) from None

    severity_order = list(Severity)
    threshold_idx = severity_order.index(threshold)

    for finding in score.findings:
        if severity_order.index(finding.severity) <= threshold_idx:
            raise typer.Exit(1)

    raise typer.Exit(0)


# ---------------------------------------------------------------------------
# rules list command
# ---------------------------------------------------------------------------

@rules_app.command("list")
def rules_list(
    rules_path: Optional[Path] = typer.Option(
        None, "--rules", help="Override path to rules.yaml."
    ),
    sources_path: Optional[Path] = typer.Option(
        None, "--sources", help="Override path to sources.yaml."
    ),
    show_tags: bool = typer.Option(False, "--tags", help="Show rule tags."),
) -> None:
    """List all active rules with their severity and source mappings."""
    from mcp_sentinel.engine import load_rules, load_sources

    rules = load_rules(rules_path)
    active_sources = load_sources(sources_path)

    table = Table(
        title="mcp-sentinel Active Rules",
        box=box.SIMPLE_HEAVY,
        show_header=True,
        header_style="bold",
    )
    table.add_column("ID",        style="bold", min_width=10)
    table.add_column("Severity",  min_width=9)
    table.add_column("Status",    min_width=12)
    table.add_column("Name",      min_width=35)
    table.add_column("Mappings",  min_width=30)

    from mcp_sentinel.models import Severity
    severity_colors = {
        Severity.CRITICAL: "bold red",
        Severity.HIGH:     "red",
        Severity.MEDIUM:   "yellow",
        Severity.LOW:      "cyan",
        Severity.INFO:     "dim",
    }

    for rule in rules:
        mapping_strs = []
        for source_id, entry in rule.mappings.items():
            if source_id in active_sources:
                src_short = active_sources[source_id]["name"].split()[0]
                mapping_strs.append(f"{src_short} {entry.get('id', '?')}")

        sev_color = severity_colors.get(rule.severity, "white")
        status_style = "dim" if rule.status.value == "experimental" else ""
        table.add_row(
            rule.id,
            f"[{sev_color}]{rule.severity.value}[/{sev_color}]",
            f"[{status_style}]{rule.status.value}[/{status_style}]",
            rule.name,
            " · ".join(mapping_strs) or "[dim](no active mappings)[/dim]",
        )

    console.print()
    console.print(table)
    console.print(f"\n[dim]{len(rules)} rule(s) loaded.[/dim]")


# ---------------------------------------------------------------------------
# rules validate command
# ---------------------------------------------------------------------------

@rules_app.command("validate")
def rules_validate(
    rules_path: Optional[Path] = typer.Option(None, "--rules"),
    sources_path: Optional[Path] = typer.Option(None, "--sources"),
) -> None:
    """Validate rules.yaml structure and source mapping references."""
    from mcp_sentinel.engine import load_rules, load_sources

    errors: list[str] = []

    try:
        active_sources = load_sources(sources_path)
    except Exception as exc:
        console.print(f"[red]Failed to load sources.yaml:[/red] {exc}")
        raise typer.Exit(1) from None

    try:
        rules = load_rules(rules_path)
    except Exception as exc:
        console.print(f"[red]Failed to load rules.yaml:[/red] {exc}")
        raise typer.Exit(1) from None

    seen_ids: set[str] = set()
    for rule in rules:
        # Duplicate IDs
        if rule.id in seen_ids:
            errors.append(f"{rule.id}: duplicate rule ID")
        seen_ids.add(rule.id)

        # Must have at least one active source mapping
        active_mappings = [sid for sid in rule.mappings if sid in active_sources]
        if not active_mappings:
            errors.append(f"{rule.id}: no mappings to any active source")

        # Must have at least one detection pattern
        if not rule.patterns:
            errors.append(f"{rule.id}: no detection patterns defined")

    if errors:
        console.print(f"\n[red]Validation failed — {len(errors)} error(s):[/red]")
        for err in errors:
            console.print(f"  [red]•[/red] {err}")
        raise typer.Exit(1)
    else:
        console.print(f"\n[green]Validation passed.[/green] {len(rules)} rule(s) OK.")


# ---------------------------------------------------------------------------
# sources check command
# ---------------------------------------------------------------------------

@app.command("sources")
def sources_check(
    sources_path: Optional[Path] = typer.Option(None, "--sources"),
    warn_after: int = typer.Option(
        120, "--warn-after", help="Days since last_checked before flagging as stale."
    ),
) -> None:
    """Check threat source definitions for staleness."""
    from mcp_sentinel.engine import check_source_staleness, load_sources

    active_sources = load_sources(sources_path)
    stale = check_source_staleness(sources_path, warn_after_days=warn_after)

    console.print(f"\n[bold]Threat Sources[/bold]  ({len(active_sources)} active)\n")

    for source_id, source in active_sources.items():
        is_stale = any(s["id"] == source_id for s in stale)
        status_icon = "[yellow]⚠[/yellow]" if is_stale else "[green]✓[/green]"
        stale_detail = next((s["reason"] for s in stale if s["id"] == source_id), "")
        console.print(
            f"  {status_icon}  [bold]{source['name']}[/bold]  "
            f"[dim]v{source.get('version', '?')}"
            f" \u2014 last checked: {source.get('last_checked', 'unknown')}[/dim]"
            + (f"\n       [yellow]{stale_detail}[/yellow]" if stale_detail else "")
        )

    if stale:
        console.print(
            f"\n[yellow]{len(stale)} source(s) may be out of date.[/yellow] "
            "Update last_checked in sources.yaml after reviewing changes."
        )
    else:
        console.print("\n[green]All sources are current.[/green]")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    app()


if __name__ == "__main__":
    main()
