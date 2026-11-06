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
def asset_errors(asset_id: int, limit: int = 100) -> None:
    _emit(dcs.dcs_asset_errors(asset_id, limit))


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
def policy_violations(policy_id: int, limit: int = 100) -> None:
    _emit(dcs.dcs_policy_violations(policy_id, limit))


def main() -> None:
    try:
        app()
    except BudgetExceeded as exc:
        typer.echo(f"Budget stopped the operation: {exc}", err=True)
        raise typer.Exit(1) from exc


@app.command("asset")
def asset(asset_id: int) -> None:
    _emit(dcs.dcs_asset(asset_id))


@app.command("asset-tags")
def asset_tags(asset_id: int, limit: int = 100) -> None:
    _emit(dcs.dcs_asset_tags(asset_id, limit))


@app.command("asset-policies")
def asset_policies(asset_id: int, limit: int = 100) -> None:
    _emit(dcs.dcs_asset_policies(asset_id, limit))


@app.command("asset-history")
def asset_history(asset_id: int, limit: int = 100) -> None:
    _emit(dcs.dcs_asset_history(asset_id, limit))


@app.command("licenses")
def licenses(limit: int = 100) -> None:
    _emit(dcs.dcs_licenses(limit))


@app.command("reports")
def reports(limit: int = 100) -> None:
    _emit(dcs.dcs_reports(limit))


@app.command("report-stats")
def report_stats() -> None:
    _emit(dcs.dcs_report_stats())


@app.command("report-jobs")
def report_jobs(limit: int = 100) -> None:
    _emit(dcs.dcs_report_jobs(limit))


@app.command("report-job")
def report_job(job_id: int) -> None:
    _emit(dcs.dcs_report_job(job_id))


@app.command("roles")
def roles(limit: int = 100) -> None:
    _emit(dcs.dcs_roles(limit))


@app.command("role")
def role(role_id: int) -> None:
    _emit(dcs.dcs_role(role_id))


@app.command("role-users")
def role_users(role_id: int, limit: int = 100) -> None:
    _emit(dcs.dcs_role_users(role_id, limit))


@app.command("security-groups")
def security_groups(limit: int = 100) -> None:
    _emit(dcs.dcs_security_groups(limit))


@app.command("security-group")
def security_group(group_id: int) -> None:
    _emit(dcs.dcs_security_group(group_id))


@app.command("security-group-stats")
def security_group_stats() -> None:
    _emit(dcs.dcs_security_group_stats())


@app.command("tags")
def tags(limit: int = 100) -> None:
    _emit(dcs.dcs_tags(limit))


@app.command("syslogs")
def syslogs(limit: int = 100) -> None:
    _emit(dcs.dcs_syslogs(limit))


@app.command("server-registry")
def server_registry(limit: int = 100) -> None:
    _emit(dcs.dcs_server_registry(limit))


@app.command("policy-settings")
def policy_settings(policy_id: int) -> None:
    _emit(dcs.dcs_policy_settings(policy_id))


@app.command("policy-library")
def policy_library(limit: int = 100) -> None:
    _emit(dcs.dcs_policy_library(limit))


@app.command("alert-details")
def alert_details(alert_id: int) -> None:
    _emit(dcs.dcs_alert_details(alert_id))


@app.command("alert-notifications")
def alert_notifications(limit: int = 100) -> None:
    _emit(dcs.dcs_alert_notifications(limit))


@app.command("users")
def users(limit: int = 100) -> None:
    _emit(dcs.dcs_users(limit))
