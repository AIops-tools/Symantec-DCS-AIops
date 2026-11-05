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
def dcs_asset_errors(asset_id: int) -> dict:
    """[READ] Read recent asset error events."""
    return ops.asset_errors(get_connection(), asset_id)


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
def dcs_policy_violations(policy_id: int) -> dict:
    """[READ] Read policy violations."""
    return ops.policy_violations(get_connection(), policy_id)
