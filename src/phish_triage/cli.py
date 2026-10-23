"""Command-line entry point: phish-triage analyze email.eml

Plain-text output for Phase 1. Phase 5 replaces render_text() with rich terminal output.
"""

from collections.abc import Callable
from pathlib import Path
from typing import Annotated

import typer

from phish_triage.config import ConfigError, load_brands
from phish_triage.defang import defang
from phish_triage.headers import (
    analyze_received,
    check_auth,
    check_received,
    check_sender,
    hop_source,
    parse_authentication_results,
)
from phish_triage.models import Finding, ParsedEmail, Severity
from phish_triage.parser import parse_file

# src/phish_triage/cli.py -> the repo root. Works for the editable install; shipping the
# config inside the package for a regular pip install is a Phase 7 task.
DEFAULT_BRANDS = Path(__file__).resolve().parents[2] / "config" / "brands.yaml"

_SEVERITY_ORDER = [Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
_AUTH_METHODS = {"spf", "dkim", "dmarc"}

app = typer.Typer(help="Triage suspicious .eml files. Never opens links or attachments.")


@app.callback()
def main() -> None:
    """Triage suspicious .eml files. Never opens links or attachments."""
    # This callback keeps "analyze" a named subcommand. With one command and no
    # callback, Typer drops the name: "phish-triage email.eml" would work but
    # "phish-triage analyze email.eml" wouldn't.


@app.command()
def analyze(
    path: Annotated[
        Path,
        typer.Argument(exists=True, dir_okay=False, readable=True, help="The .eml file."),
    ],
    brands_file: Annotated[
        Path, typer.Option("--brands", help="Brand list for display-name checks.")
    ] = DEFAULT_BRANDS,
    defang_output: Annotated[
        bool, typer.Option("--defang/--no-defang", help="Make domains, IPs and URLs unclickable.")
    ] = True,
) -> None:
    """Analyze one email's headers and print what looks wrong."""
    try:
        brands = load_brands(brands_file)
    except (ConfigError, OSError) as exc:
        typer.echo(f"error: can't load brands: {exc}", err=True)
        raise typer.Exit(1) from exc
    try:
        parsed = parse_file(path)
    except OSError as exc:  # e.g. deleted between Typer's check and the read
        typer.echo(f"error: can't read {path}: {exc}", err=True)
        raise typer.Exit(1) from exc

    findings = [
        *parsed.findings,
        *check_sender(parsed, brands),
        *check_auth(parsed),
        *check_received(parsed),
    ]
    typer.echo(render_text(path.name, parsed, findings, defang_output=defang_output))


def render_text(
    name: str, parsed: ParsedEmail, findings: list[Finding], *, defang_output: bool = True
) -> str:
    """The plain-text report. Values from the email are defanged; our own labels aren't."""
    safe: Callable[[str], str] = defang if defang_output else _unchanged
    from_values = parsed.get_headers("From")
    lines = [
        f"phish-triage: {name}",
        f"Subject: {safe(parsed.subject) if parsed.subject else '(none)'}",
        f"From:    {safe(from_values[0]) if from_values else '(none)'}",
        "",
        "Path (oldest first):",
    ]

    chain = analyze_received(parsed)
    if not chain.hops:
        lines.append("  (no Received headers)")
    for number, hop in enumerate(chain.hops, start=1):
        when = hop.timestamp.strftime("%Y-%m-%d %H:%M:%S %z") if hop.timestamp else None
        details = "  ".join(part for part in (hop.protocol, when) if part)
        lines.append(f"  {number}. {safe(hop_source(hop))}  {details}".rstrip())
    origin_ip = chain.origin.from_ip if chain.origin else None
    lines += [f"Origin: {safe(origin_ip) if origin_ip else 'unknown'}", ""]

    lines += [_auth_line(parsed, safe), ""]

    # sorted() is stable, so findings of equal severity keep their check order
    ordered = sorted(findings, key=lambda finding: _SEVERITY_ORDER.index(finding.severity))
    if not ordered:
        lines.append("Findings: none")
        return "\n".join(lines)
    lines.append(f"Findings ({len(ordered)}), most severe first:")
    width = max(len(finding.id) for finding in ordered)
    for finding in ordered:
        label = f"[{finding.severity.name}]"
        lines.append(f"  {label:<9} {finding.id:<{width}}  {finding.description}")
        if finding.evidence:
            lines.append(f"  {'':<9} evidence: {safe(finding.evidence)}")
    return "\n".join(lines)


def _auth_line(parsed: ParsedEmail, safe: Callable[[str], str]) -> str:
    """One-line summary of the topmost Authentication-Results, the only one we trust."""
    values = parsed.get_headers("Authentication-Results")
    if not values:
        return "Authentication: no Authentication-Results header"
    top = parse_authentication_results(values[0])
    if top is None:
        return "Authentication: the topmost header couldn't be read"
    shown = [f"{r.method}={r.result}" for r in top.results if r.method in _AUTH_METHODS]
    server = safe(top.authserv_id) if top.authserv_id else "unknown server"
    return f"Authentication ({server}): {'  '.join(shown) or 'no SPF/DKIM/DMARC results'}"


def _unchanged(text: str) -> str:
    return text
