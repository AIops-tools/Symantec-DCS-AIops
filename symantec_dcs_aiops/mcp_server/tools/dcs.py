"""Governed Symantec DCS read tools."""

from symantec_dcs_aiops import ops
from symantec_dcs_aiops.connection import get_connection
from symantec_dcs_aiops.governance import governed_tool
from symantec_dcs_aiops.mcp_server._shared import mcp, tool_errors


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors()
def dcs_status(component: str) -> dict:
    """[READ] Read a DCS service status component."""
    return ops.status(get_connection(), component)


@mcp.tool()
@governed_tool(risk_level="low", sensitive_params=["filter_text"])
@tool_errors()
def dcs_assets(sort: str, offset: int = 0, limit: int = 100, filter_text: str = "") -> dict:
    """[READ] List a bounded page of assets."""
    return ops.assets(get_connection(), sort, offset, limit, filter_text)


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors()
def dcs_asset_errors(asset_id: int, limit: int = 100) -> dict:
    """[READ] Read recent asset error events."""
    return ops.asset_errors(get_connection(), asset_id, limit)


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors()
def dcs_asset_stats() -> dict:
    """[READ] Read asset totals and offline counts."""
    return ops.asset_stats(get_connection())


@mcp.tool()
@governed_tool(risk_level="low", sensitive_params=["filter_text"])
@tool_errors()
def dcs_alerts(sort: str, offset: int = 0, limit: int = 100, filter_text: str = "") -> dict:
    """[READ] List a bounded page of alerts."""
    return ops.alerts(get_connection(), sort, offset, limit, filter_text)


@mcp.tool()
@governed_tool(risk_level="low", sensitive_params=["filter_text"])
@tool_errors()
def dcs_alert_rules(sort: str, offset: int = 0, limit: int = 100, filter_text: str = "") -> dict:
    """[READ] List a bounded page of alert rules."""
    return ops.alert_rules(get_connection(), sort, offset, limit, filter_text)


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors()
def dcs_alert_stats() -> dict:
    """[READ] Read alert rule totals."""
    return ops.alert_stats(get_connection())


@mcp.tool()
@governed_tool(risk_level="low", sensitive_params=["filter_text"])
@tool_errors()
def dcs_events(sort: str, offset: int = 0, limit: int = 100, filter_text: str = "") -> dict:
    """[READ] List a bounded page of security events."""
    return ops.events(get_connection(), sort, offset, limit, filter_text)


@mcp.tool()
@governed_tool(risk_level="low", sensitive_params=["filter_text"])
@tool_errors()
def dcs_event_stats(filter_text: str = "") -> dict:
    """[READ] Read event counts."""
    return ops.event_stats(get_connection(), filter_text)


@mcp.tool()
@governed_tool(risk_level="low", sensitive_params=["filter_text"])
@tool_errors()
def dcs_policies(filter_text: str = "", limit: int = 100) -> dict:
    """[READ] List DCS policies with an explicit output cap."""
    return ops.policies(get_connection(), filter_text, limit)


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors()
def dcs_policy(policy_id: int) -> dict:
    """[READ] Read one DCS policy."""
    return ops.policy(get_connection(), policy_id)


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors()
def dcs_policy_violations(policy_id: int, limit: int = 100) -> dict:
    """[READ] Read policy violations."""
    return ops.policy_violations(get_connection(), policy_id, limit)


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors()
def dcs_asset(asset_id: int) -> dict:
    """[READ] Read one managed asset."""
    return ops.asset(get_connection(), asset_id)


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors()
def dcs_asset_tags(asset_id: int, limit: int = 100) -> dict:
    """[READ] Read asset tags."""
    return ops.asset_tags(get_connection(), asset_id, limit)


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors()
def dcs_asset_policies(asset_id: int, limit: int = 100) -> dict:
    """[READ] List policies assigned to an asset."""
    return ops.asset_policies(get_connection(), asset_id, limit)


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors()
def dcs_asset_history(asset_id: int, limit: int = 100) -> dict:
    """[READ] Read asset change history."""
    return ops.asset_history(get_connection(), asset_id, limit)


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors()
def dcs_licenses(limit: int = 100) -> dict:
    """[READ] List license inventory."""
    return ops.licenses(get_connection(), limit)


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors()
def dcs_reports(limit: int = 100) -> dict:
    """[READ] List report definitions."""
    return ops.reports(get_connection(), limit)


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors()
def dcs_report_stats() -> dict:
    """[READ] Read report counts."""
    return ops.report_stats(get_connection())


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors()
def dcs_report_jobs(limit: int = 100) -> dict:
    """[READ] List report job states."""
    return ops.report_jobs(get_connection(), limit)


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors()
def dcs_report_job(job_id: int) -> dict:
    """[READ] Read one report job state."""
    return ops.report_job(get_connection(), job_id)


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors()
def dcs_roles(limit: int = 100) -> dict:
    """[READ] List RBAC roles."""
    return ops.roles(get_connection(), limit)


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors()
def dcs_role(role_id: int) -> dict:
    """[READ] Read one RBAC role."""
    return ops.role(get_connection(), role_id)


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors()
def dcs_role_users(role_id: int, limit: int = 100) -> dict:
    """[READ] List users assigned to a role."""
    return ops.role_users(get_connection(), role_id, limit)


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors()
def dcs_security_groups(limit: int = 100) -> dict:
    """[READ] List security groups."""
    return ops.security_groups(get_connection(), limit)


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors()
def dcs_security_group(group_id: int) -> dict:
    """[READ] Read one security group."""
    return ops.security_group(get_connection(), group_id)


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors()
def dcs_security_group_stats() -> dict:
    """[READ] Read security group counts."""
    return ops.security_group_stats(get_connection())


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors()
def dcs_tags(limit: int = 100) -> dict:
    """[READ] List policy and asset tags."""
    return ops.tags(get_connection(), limit)


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors()
def dcs_syslogs(limit: int = 100) -> dict:
    """[READ] List syslog destinations."""
    return ops.syslogs(get_connection(), limit)


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors()
def dcs_server_registry(limit: int = 100) -> dict:
    """[READ] List registered servers."""
    return ops.server_registry(get_connection(), limit)


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors()
def dcs_policy_settings(policy_id: int) -> dict:
    """[READ] Read policy settings."""
    return ops.policy_settings(get_connection(), policy_id)


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors()
def dcs_policy_library(limit: int = 100) -> dict:
    """[READ] List library policies."""
    return ops.policy_library(get_connection(), limit)


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors()
def dcs_alert_details(alert_id: int) -> dict:
    """[READ] Read alert rule details."""
    return ops.alert_details(get_connection(), alert_id)


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors()
def dcs_alert_notifications(limit: int = 100) -> dict:
    """[READ] List recent alert notifications."""
    return ops.alert_notifications(get_connection(), limit)


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors()
def dcs_users(limit: int = 100) -> dict:
    """[READ] List management users."""
    return ops.users(get_connection(), limit)
