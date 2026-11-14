"""Governed Symantec DCS read tools."""

from typing import Annotated

from pydantic import Field

from symantec_dcs_aiops import ops
from symantec_dcs_aiops.connection import get_connection
from symantec_dcs_aiops.governance import governed_tool
from symantec_dcs_aiops.mcp_server._shared import mcp, tool_errors


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors()
def dcs_status(
    component: Annotated[
        str, Field(description=("DCS status component: server, product, machine, event, or db."))
    ],
) -> dict:
    """[READ] Read a DCS service status component.

    Use for one management-service component; use dcs_asset_stats for managed-asset totals.

    Result: structured data or an explicit, sanitized operation error.
    """
    return ops.status(get_connection(), component)


@mcp.tool()
@governed_tool(risk_level="low", sensitive_params=["filter_text"])
@tool_errors()
def dcs_assets(
    sort: Annotated[
        str, Field(description=("Required upstream sort expression, at most 100 characters."))
    ],
    offset: Annotated[int, Field(description="Zero-based page offset; must not be negative.")] = 0,
    limit: Annotated[
        int,
        Field(
            description=(
                "Maximum rows to return (1–100); inspect truncated and continuation metadata."
            )
        ),
    ] = 100,
    filter_text: Annotated[
        str, Field(description=("Optional upstream filter expression; bounded by the operation."))
    ] = "",
) -> dict:
    """[READ] List a bounded page of assets.

    Use to discover IDs before calling dcs_asset for a single resource.

    Result: items, returned, limit and measured truncated; offset pages also expose nextOffset.
    """
    return ops.assets(get_connection(), sort, offset, limit, filter_text)


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors()
def dcs_asset_errors(
    asset_id: Annotated[
        int, Field(description="Positive managed-asset ID from the asset listing.")
    ],
    limit: Annotated[
        int,
        Field(
            description=(
                "Maximum rows to return (1–100); inspect truncated and continuation metadata."
            )
        ),
    ] = 100,
) -> dict:
    """[READ] Read recent asset error events.

    Result: items, returned, limit and measured truncated; offset pages also expose nextOffset.
    """
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
def dcs_alerts(
    sort: Annotated[
        str, Field(description=("Required upstream sort expression, at most 100 characters."))
    ],
    offset: Annotated[int, Field(description="Zero-based page offset; must not be negative.")] = 0,
    limit: Annotated[
        int,
        Field(
            description=(
                "Maximum rows to return (1–100); inspect truncated and continuation metadata."
            )
        ),
    ] = 100,
    filter_text: Annotated[
        str, Field(description=("Optional upstream filter expression; bounded by the operation."))
    ] = "",
) -> dict:
    """[READ] List a bounded page of alerts.

    Result: items, returned, limit and measured truncated; offset pages also expose nextOffset.
    """
    return ops.alerts(get_connection(), sort, offset, limit, filter_text)


@mcp.tool()
@governed_tool(risk_level="low", sensitive_params=["filter_text"])
@tool_errors()
def dcs_alert_rules(
    sort: Annotated[
        str, Field(description=("Required upstream sort expression, at most 100 characters."))
    ],
    offset: Annotated[int, Field(description="Zero-based page offset; must not be negative.")] = 0,
    limit: Annotated[
        int,
        Field(
            description=(
                "Maximum rows to return (1–100); inspect truncated and continuation metadata."
            )
        ),
    ] = 100,
    filter_text: Annotated[
        str, Field(description=("Optional upstream filter expression; bounded by the operation."))
    ] = "",
) -> dict:
    """[READ] List a bounded page of alert rules.

    Result: items, returned, limit and measured truncated; offset pages also expose nextOffset.
    """
    return ops.alert_rules(get_connection(), sort, offset, limit, filter_text)


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors()
def dcs_alert_stats() -> dict:
    """[READ] Read alert rule totals.

    Use for aggregate counts; use dcs_alerts or dcs_alert_rules for records.
    Result: data containing the upstream statistics, or an explicit operation error.
    """
    return ops.alert_stats(get_connection())


@mcp.tool()
@governed_tool(risk_level="low", sensitive_params=["filter_text"])
@tool_errors()
def dcs_events(
    sort: Annotated[
        str, Field(description=("Required upstream sort expression, at most 100 characters."))
    ],
    offset: Annotated[int, Field(description="Zero-based page offset; must not be negative.")] = 0,
    limit: Annotated[
        int,
        Field(
            description=(
                "Maximum rows to return (1–100); inspect truncated and continuation metadata."
            )
        ),
    ] = 100,
    filter_text: Annotated[
        str, Field(description=("Optional upstream filter expression; bounded by the operation."))
    ] = "",
) -> dict:
    """[READ] List a bounded page of security events.

    Result: items, returned, limit and measured truncated; offset pages also expose nextOffset.
    """
    return ops.events(get_connection(), sort, offset, limit, filter_text)


@mcp.tool()
@governed_tool(risk_level="low", sensitive_params=["filter_text"])
@tool_errors()
def dcs_event_stats(
    filter_text: Annotated[
        str, Field(description=("Optional upstream filter expression; bounded by the operation."))
    ] = "",
) -> dict:
    """[READ] Read event counts.

    Result: structured data or an explicit, sanitized operation error.
    """
    return ops.event_stats(get_connection(), filter_text)


@mcp.tool()
@governed_tool(risk_level="low", sensitive_params=["filter_text"])
@tool_errors()
def dcs_policies(
    filter_text: Annotated[
        str, Field(description=("Optional upstream filter expression; bounded by the operation."))
    ] = "",
    limit: Annotated[
        int,
        Field(
            description=(
                "Maximum rows to return (1–100); inspect truncated and continuation metadata."
            )
        ),
    ] = 100,
) -> dict:
    """[READ] List DCS policies with an explicit output cap.

    Result: items, returned, limit and measured truncated; offset pages also expose nextOffset.
    """
    return ops.policies(get_connection(), filter_text, limit)


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors()
def dcs_policy(
    policy_id: Annotated[int, Field(description="Positive DCS policy ID from dcs_policies.")],
) -> dict:
    """[READ] Read one DCS policy.

    Result: structured data or an explicit, sanitized operation error.
    """
    return ops.policy(get_connection(), policy_id)


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors()
def dcs_policy_violations(
    policy_id: Annotated[int, Field(description="Positive DCS policy ID from dcs_policies.")],
    limit: Annotated[
        int,
        Field(
            description=(
                "Maximum rows to return (1–100); inspect truncated and continuation metadata."
            )
        ),
    ] = 100,
) -> dict:
    """[READ] Read policy violations.

    Use for violations of one policy; use dcs_asset_policies to inspect assignments on one
    asset.

    Result: items, returned, limit and measured truncated; offset pages also expose nextOffset.
    """
    return ops.policy_violations(get_connection(), policy_id, limit)


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors()
def dcs_asset(
    asset_id: Annotated[
        int, Field(description="Positive managed-asset ID from the asset listing.")
    ],
) -> dict:
    """[READ] Read one managed asset.

    Use for one known resource; call dcs_assets to discover IDs.

    Result: structured data or an explicit, sanitized operation error.
    """
    return ops.asset(get_connection(), asset_id)


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors()
def dcs_asset_tags(
    asset_id: Annotated[
        int, Field(description="Positive managed-asset ID from the asset listing.")
    ],
    limit: Annotated[
        int,
        Field(
            description=(
                "Maximum rows to return (1–100); inspect truncated and continuation metadata."
            )
        ),
    ] = 100,
) -> dict:
    """[READ] Read asset tags.

    Result: items, returned, limit and measured truncated; offset pages also expose nextOffset.
    """
    return ops.asset_tags(get_connection(), asset_id, limit)


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors()
def dcs_asset_policies(
    asset_id: Annotated[
        int, Field(description="Positive managed-asset ID from the asset listing.")
    ],
    limit: Annotated[
        int,
        Field(
            description=(
                "Maximum rows to return (1–100); inspect truncated and continuation metadata."
            )
        ),
    ] = 100,
) -> dict:
    """[READ] List policies assigned to an asset.

    Result: items, returned, limit and measured truncated; offset pages also expose nextOffset.
    """
    return ops.asset_policies(get_connection(), asset_id, limit)


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors()
def dcs_asset_history(
    asset_id: Annotated[
        int, Field(description="Positive managed-asset ID from the asset listing.")
    ],
    limit: Annotated[
        int,
        Field(
            description=(
                "Maximum rows to return (1–100); inspect truncated and continuation metadata."
            )
        ),
    ] = 100,
) -> dict:
    """[READ] Read asset change history.

    Result: items, returned, limit and measured truncated; offset pages also expose nextOffset.
    """
    return ops.asset_history(get_connection(), asset_id, limit)


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors()
def dcs_licenses(
    limit: Annotated[
        int,
        Field(
            description=(
                "Maximum rows to return (1–100); inspect truncated and continuation metadata."
            )
        ),
    ] = 100,
) -> dict:
    """[READ] List license inventory.

    Result: items, returned, limit and measured truncated; offset pages also expose nextOffset.
    """
    return ops.licenses(get_connection(), limit)


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors()
def dcs_reports(
    limit: Annotated[
        int,
        Field(
            description=(
                "Maximum rows to return (1–100); inspect truncated and continuation metadata."
            )
        ),
    ] = 100,
) -> dict:
    """[READ] List report definitions.

    Result: items, returned, limit and measured truncated; offset pages also expose nextOffset.
    """
    return ops.reports(get_connection(), limit)


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors()
def dcs_report_stats() -> dict:
    """[READ] Read report counts.

    Use for aggregate report counts; use dcs_reports for definitions.
    Result: data containing the upstream statistics, or an explicit operation error.
    """
    return ops.report_stats(get_connection())


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors()
def dcs_report_jobs(
    limit: Annotated[
        int,
        Field(
            description=(
                "Maximum rows to return (1–100); inspect truncated and continuation metadata."
            )
        ),
    ] = 100,
) -> dict:
    """[READ] List report job states.

    Use to discover IDs before calling dcs_report_job for a single resource.

    Result: items, returned, limit and measured truncated; offset pages also expose nextOffset.
    """
    return ops.report_jobs(get_connection(), limit)


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors()
def dcs_report_job(
    job_id: Annotated[int, Field(description="Positive report-job ID from the job listing.")],
) -> dict:
    """[READ] Read one report job state.

    Use for one known resource; call dcs_report_jobs to discover IDs.

    Result: structured data or an explicit, sanitized operation error.
    """
    return ops.report_job(get_connection(), job_id)


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors()
def dcs_roles(
    limit: Annotated[
        int,
        Field(
            description=(
                "Maximum rows to return (1–100); inspect truncated and continuation metadata."
            )
        ),
    ] = 100,
) -> dict:
    """[READ] List RBAC roles.

    Use to discover IDs before calling dcs_role for a single resource.

    Result: items, returned, limit and measured truncated; offset pages also expose nextOffset.
    """
    return ops.roles(get_connection(), limit)


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors()
def dcs_role(
    role_id: Annotated[int, Field(description="Positive RBAC role ID from the role listing.")],
) -> dict:
    """[READ] Read one RBAC role.

    Use for one known resource; call dcs_roles to discover IDs.

    Result: structured data or an explicit, sanitized operation error.
    """
    return ops.role(get_connection(), role_id)


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors()
def dcs_role_users(
    role_id: Annotated[int, Field(description="Positive RBAC role ID from the role listing.")],
    limit: Annotated[
        int,
        Field(
            description=(
                "Maximum rows to return (1–100); inspect truncated and continuation metadata."
            )
        ),
    ] = 100,
) -> dict:
    """[READ] List users assigned to a role.

    Result: items, returned, limit and measured truncated; offset pages also expose nextOffset.
    """
    return ops.role_users(get_connection(), role_id, limit)


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors()
def dcs_security_groups(
    limit: Annotated[
        int,
        Field(
            description=(
                "Maximum rows to return (1–100); inspect truncated and continuation metadata."
            )
        ),
    ] = 100,
) -> dict:
    """[READ] List security groups.

    Use to discover IDs before calling dcs_security_group for a single resource.

    Result: items, returned, limit and measured truncated; offset pages also expose nextOffset.
    """
    return ops.security_groups(get_connection(), limit)


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors()
def dcs_security_group(
    group_id: Annotated[int, Field(description="Group ID from the corresponding listing.")],
) -> dict:
    """[READ] Read one security group.

    Use for one known resource; call dcs_security_groups to discover IDs.

    Result: structured data or an explicit, sanitized operation error.
    """
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
def dcs_tags(
    limit: Annotated[
        int,
        Field(
            description=(
                "Maximum rows to return (1–100); inspect truncated and continuation metadata."
            )
        ),
    ] = 100,
) -> dict:
    """[READ] List policy and asset tags.

    Result: items, returned, limit and measured truncated; offset pages also expose nextOffset.
    """
    return ops.tags(get_connection(), limit)


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors()
def dcs_syslogs(
    limit: Annotated[
        int,
        Field(
            description=(
                "Maximum rows to return (1–100); inspect truncated and continuation metadata."
            )
        ),
    ] = 100,
) -> dict:
    """[READ] List syslog destinations.

    Result: items, returned, limit and measured truncated; offset pages also expose nextOffset.
    """
    return ops.syslogs(get_connection(), limit)


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors()
def dcs_server_registry(
    limit: Annotated[
        int,
        Field(
            description=(
                "Maximum rows to return (1–100); inspect truncated and continuation metadata."
            )
        ),
    ] = 100,
) -> dict:
    """[READ] List registered servers.

    Result: items, returned, limit and measured truncated; offset pages also expose nextOffset.
    """
    return ops.server_registry(get_connection(), limit)


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors()
def dcs_policy_settings(
    policy_id: Annotated[int, Field(description="Positive DCS policy ID from dcs_policies.")],
) -> dict:
    """[READ] Read policy settings.

    Result: structured data or an explicit, sanitized operation error.
    """
    return ops.policy_settings(get_connection(), policy_id)


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors()
def dcs_policy_library(
    limit: Annotated[
        int,
        Field(
            description=(
                "Maximum rows to return (1–100); inspect truncated and continuation metadata."
            )
        ),
    ] = 100,
) -> dict:
    """[READ] List library policies.

    Result: items, returned, limit and measured truncated; offset pages also expose nextOffset.
    """
    return ops.policy_library(get_connection(), limit)


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors()
def dcs_alert_details(
    alert_id: Annotated[int, Field(description="Positive alert ID from the alert listing.")],
) -> dict:
    """[READ] Read alert rule details.

    Use for one alert rule; use dcs_alerts for alert occurrences and dcs_alert_rules for rule
    inventory.

    Result: structured data or an explicit, sanitized operation error.
    """
    return ops.alert_details(get_connection(), alert_id)


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors()
def dcs_alert_notifications(
    limit: Annotated[
        int,
        Field(
            description=(
                "Maximum rows to return (1–100); inspect truncated and continuation metadata."
            )
        ),
    ] = 100,
) -> dict:
    """[READ] List recent alert notifications.

    Use for delivered alert notifications, not the underlying alert-rule definitions.

    Result: items, returned, limit and measured truncated; offset pages also expose nextOffset.
    """
    return ops.alert_notifications(get_connection(), limit)


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors()
def dcs_users(
    limit: Annotated[
        int,
        Field(
            description=(
                "Maximum rows to return (1–100); inspect truncated and continuation metadata."
            )
        ),
    ] = 100,
) -> dict:
    """[READ] List management users.

    Result: items, returned, limit and measured truncated; offset pages also expose nextOffset.
    """
    return ops.users(get_connection(), limit)
