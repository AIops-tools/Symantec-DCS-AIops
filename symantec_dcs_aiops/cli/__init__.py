"""CLI commands delegate to governed DCS MCP tools."""

from __future__ import annotations

import json

import typer

from symantec_dcs_aiops.governance import BudgetExceeded
from symantec_dcs_aiops.mcp_server.tools import dcs

app = typer.Typer(name="symantec-dcs-aiops", no_args_is_help=True)


def governed(result: dict) -> dict:
    if result.get("outcomeUnknown"):
        typer.echo(json.dumps(result, ensure_ascii=False), err=True)
        raise typer.Exit(2)
    if result.get("error"):
        typer.echo(json.dumps(result, ensure_ascii=False), err=True)
        raise typer.Exit(1)
    return result


def _emit(result: dict) -> None:
    typer.echo(json.dumps(governed(result), ensure_ascii=False, indent=2))


@app.command("status")
def status(component: str) -> None:
    _emit(dcs.dcs_status(component))


@app.command("assets")
def assets(sort: str, offset: int = 0, limit: int = 100, filter_text: str = "") -> None:
    _emit(dcs.dcs_assets(sort, offset, limit, filter_text))


@app.command("asset-errors")
def asset_errors(asset_id: int) -> None:
    _emit(dcs.dcs_asset_errors(asset_id))


@app.command("asset-stats")
def asset_stats() -> None:
    _emit(dcs.dcs_asset_stats())


@app.command("alerts")
def alerts(sort: str, offset: int = 0, limit: int = 100, filter_text: str = "") -> None:
    _emit(dcs.dcs_alerts(sort, offset, limit, filter_text))


@app.command("alert-rules")
def alert_rules(sort: str, offset: int = 0, limit: int = 100, filter_text: str = "") -> None:
    _emit(dcs.dcs_alert_rules(sort, offset, limit, filter_text))


@app.command("alert-stats")
def alert_stats() -> None:
    _emit(dcs.dcs_alert_stats())


@app.command("events")
def events(sort: str, offset: int = 0, limit: int = 100, filter_text: str = "") -> None:
    _emit(dcs.dcs_events(sort, offset, limit, filter_text))


@app.command("event-stats")
def event_stats(filter_text: str = "") -> None:
    _emit(dcs.dcs_event_stats(filter_text))


@app.command("policies")
def policies(filter_text: str = "", limit: int = 100) -> None:
    _emit(dcs.dcs_policies(filter_text, limit))


@app.command("policy")
def policy(policy_id: int) -> None:
    _emit(dcs.dcs_policy(policy_id))


@app.command("policy-violations")
def policy_violations(policy_id: int) -> None:
    _emit(dcs.dcs_policy_violations(policy_id))


def main() -> None:
    try:
        app()
    except BudgetExceeded as exc:
        typer.echo(f"Budget stopped the operation: {exc}", err=True)
        raise typer.Exit(1) from exc
