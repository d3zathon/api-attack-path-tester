from __future__ import annotations

import sys
from pathlib import Path
from typing import List, Optional

import typer
from rich.console import Console
from rich.table import Table

from .checks import ALL_CHECKS
from .config.loader import load_scan_config
from .engine.runner import run_scan
from .reporting.report import result_to_dict, write_html, write_json, write_markdown
from .spec_parser import parse_spec, summarize

app = typer.Typer(
    name="apiattack",
    help=(
        "API Attack-Path & Authorization Tester - authorized security testing for BOLA/IDOR, "
        "BFLA, privilege escalation, parameter tampering, and business-logic flaws."
    ),
    add_completion=False,
)
console = Console()


@app.command()
def scan(
    spec: str = typer.Option(..., "--spec", "-s", help="Path or URL to an OpenAPI spec (JSON/YAML)."),
    config: str = typer.Option(..., "--config", "-c", help="Path to roles/scan config YAML."),
    checks: Optional[str] = typer.Option(
        None, "--checks", help=f"Comma-separated subset of checks to run: {','.join(ALL_CHECKS)}"
    ),
    out_dir: str = typer.Option("./apiattack-report", "--out", "-o", help="Output directory for reports."),
    formats: str = typer.Option("md,html,json", "--formats", help="Comma-separated: md,html,json"),
    yes_i_am_authorized: bool = typer.Option(
        False,
        "--yes-i-am-authorized",
        help="Required flag confirming you have explicit authorization to test this target.",
    ),
):
    """Run a full authorization-focused scan against a target described by an OpenAPI spec."""
    if not yes_i_am_authorized:
        console.print(
            "[bold red]Refusing to run.[/bold red] Pass [bold]--yes-i-am-authorized[/bold] to "
            "confirm you have explicit, documented authorization to test this target. "
            "This tool is for authorized security testing only."
        )
        raise typer.Exit(code=1)

    try:
        scan_config = load_scan_config(config)
    except Exception as exc:  # noqa: BLE001
        console.print(f"[bold red]Config error:[/bold red] {exc}")
        raise typer.Exit(code=1)

    check_names = [c.strip() for c in checks.split(",")] if checks else None
    if check_names:
        unknown = [c for c in check_names if c not in ALL_CHECKS]
        if unknown:
            console.print(f"[bold red]Unknown check(s):[/bold red] {unknown}. Valid: {list(ALL_CHECKS)}")
            raise typer.Exit(code=1)

    console.print(f"[bold]Target:[/bold] {scan_config.base_url}")
    console.print(f"[bold]Roles:[/bold] {[r.name for r in scan_config.roles]}")

    def progress(msg: str):
        console.print(f"[dim]... {msg}[/dim]")

    result = run_scan(spec, scan_config, check_names=check_names, progress_cb=progress)

    Path(out_dir).mkdir(parents=True, exist_ok=True)
    fmt_list = [f.strip() for f in formats.split(",")]
    if "json" in fmt_list:
        write_json(result, str(Path(out_dir) / "report.json"))
    if "md" in fmt_list:
        write_markdown(result, str(Path(out_dir) / "report.md"))
    if "html" in fmt_list:
        write_html(result, str(Path(out_dir) / "report.html"))

    _print_summary(result)
    console.print(f"\n[bold green]Reports written to {out_dir}/[/bold green]")


@app.command("list-checks")
def list_checks():
    """List available check modules."""
    table = Table(title="Available checks")
    table.add_column("Name")
    table.add_column("Class")
    for name, cls in ALL_CHECKS.items():
        table.add_row(name, cls.vuln_class if isinstance(cls.vuln_class, str) else cls.vuln_class.value)
    console.print(table)


@app.command("inspect-spec")
def inspect_spec(spec: str = typer.Option(..., "--spec", "-s")):
    """Parse an OpenAPI spec and print a quick inventory (no requests are made)."""
    endpoints = parse_spec(spec)
    info = summarize(endpoints)
    table = Table(title=f"Spec inventory: {spec}")
    table.add_column("Metric")
    table.add_column("Value")
    for k, v in info.items():
        table.add_row(k, str(v))
    console.print(table)

    ep_table = Table(title="Endpoints")
    ep_table.add_column("Method")
    ep_table.add_column("Path")
    ep_table.add_column("ID-bearing?")
    for e in endpoints:
        ep_table.add_row(e.method, e.path, "yes" if e.is_id_bearing else "")
    console.print(ep_table)


@app.command("init-config")
def init_config(
    out: str = typer.Option("roles.yaml", "--out", "-o", help="Where to write the scaffold config."),
):
    """Write a starter roles/scan config YAML to fill in for your target."""
    template = """\
base_url: "http://localhost:8000"

roles:
  - name: attacker_low_priv
    privilege_rank: 0
    auth_header:
      Authorization: "Bearer <low-priv-token>"
    owned_resources:
      user_id: ["2"]
      order_id: ["ord_2"]
    metadata:
      identity_markers: ["attacker@example.com"]

  - name: victim_user
    privilege_rank: 1
    auth_header:
      Authorization: "Bearer <victim-token>"
    owned_resources:
      user_id: ["1"]
      order_id: ["ord_1"]
    metadata:
      identity_markers: ["victim@example.com"]

  - name: admin
    privilege_rank: 9
    auth_header:
      Authorization: "Bearer <admin-token>"
    owned_resources: {}

endpoint_role_requirements:
  "GET /admin/users": ["admin"]
  "GET /admin/reports": ["admin"]

sensitive_fields:
  - price
  - balance
  - status
  - discount

rate_limit_delay_ms: 150

workflows:
  - name: checkout
    description: "Cart checkout should require a completed payment step first."
    steps:
      - name: create_cart
        method: POST
        path: /cart
        body: {}
      - name: pay
        method: POST
        path: /cart/1/payment
        body: {"amount": 10}
      - name: checkout
        method: POST
        path: /cart/1/checkout
        body: {}
    skip_step_test: pay

  - name: coupon_redeem
    description: "A coupon should only be redeemable once."
    steps:
      - name: redeem
        method: POST
        path: /coupons/apply
        body: {"code": "WELCOME10"}
    replay_step_test: redeem
"""
    Path(out).write_text(template, encoding="utf-8")
    console.print(f"[bold green]Wrote starter config to {out}[/bold green] - edit roles/tokens/resources before scanning.")


def _print_summary(result):
    table = Table(title="Scan summary")
    table.add_column("Metric")
    table.add_column("Value")
    table.add_row("Endpoints discovered", str(result.endpoints_discovered))
    table.add_row("Endpoints tested", str(result.endpoints_tested))
    table.add_row("Candidate findings", str(result.raw_candidate_count))
    table.add_row("Confirmed findings", str(len(result.confirmed_findings)))
    table.add_row("Unverified (kept, not confirmed)", str(len(result.findings) - len(result.confirmed_findings)))
    table.add_row("Attack paths", str(len(result.attack_paths)))
    console.print(table)

    if result.confirmed_findings:
        f_table = Table(title="Confirmed findings")
        f_table.add_column("Severity")
        f_table.add_column("Class")
        f_table.add_column("Endpoint")
        f_table.add_column("Title")
        for f in result.confirmed_findings:
            f_table.add_row(f.severity.value, f.vuln_class.value, f.endpoint, f.title)
        console.print(f_table)


def main():
    app()


if __name__ == "__main__":
    main()
