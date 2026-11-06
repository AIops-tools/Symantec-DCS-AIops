"""Documented read-only Symantec DCS management operations."""

from __future__ import annotations

from symantec_dcs_aiops.connection import DcsConnection, DcsError


def _id(value: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ValueError("resource ID must be a positive integer")
    return value


def _object(conn: DcsConnection, path: str, params: dict | None = None) -> dict:
    data = conn.get(path, params=params)
    if not isinstance(data, dict) or not data:
        raise DcsError(f"DCS returned an unexpected object for {path}")
    return {"data": data}


def _list(conn: DcsConnection, path: str, limit: int = 100) -> dict:
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 100:
        raise ValueError("limit must be 1–100")
    data = conn.get(path)
    if not isinstance(data, list) or any(not isinstance(row, dict) for row in data):
        raise DcsError(f"DCS returned an unexpected list for {path}")
    return {
        "items": data[:limit],
        "returned": min(len(data), limit),
        "limit": limit,
        "truncated": len(data) > limit,
        "paginationKnown": False,
    }


def _page(
    conn: DcsConnection,
    path: str,
    sort: str,
    offset: int = 0,
    limit: int = 100,
    filter_text: str = "",
) -> dict:
    if not sort or len(sort) > 100 or len(filter_text) > 200:
        raise ValueError("sort is required; sort/filter must be bounded")
    if isinstance(offset, bool) or not isinstance(offset, int) or offset < 0:
        raise ValueError("offset must be zero or greater")
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 100:
        raise ValueError("limit must be 1–100")
    params = {"sort": sort, "offset": offset, "limit": limit + 1}
    if filter_text:
        params["filter"] = filter_text
    data = conn.get(path, params=params)
    if not isinstance(data, list) or any(not isinstance(row, dict) for row in data):
        raise DcsError(f"DCS returned an unexpected page for {path}")
    if len(data) > limit + 1:
        raise DcsError(f"DCS ignored the requested limit for {path}")
    truncated = len(data) > limit
    return {
        "items": data[:limit],
        "returned": min(len(data), limit),
        "limit": limit,
        "offset": offset,
        "truncated": truncated,
        "nextOffset": offset + limit if truncated else None,
    }


def status(conn: DcsConnection, component: str) -> dict:
    if component not in {"server", "product", "machine", "event", "db"}:
        raise ValueError("Unknown DCS status component")
    return _object(conn, f"/sis-ui/api/v2/status/{component}")


def assets(
    conn: DcsConnection, sort: str, offset: int = 0, limit: int = 100, filter_text: str = ""
) -> dict:
    return _page(conn, "/sis-ui/api/v2/assets", sort, offset, limit, filter_text)


def asset_errors(conn: DcsConnection, asset_id: int, limit: int = 100) -> dict:
    return _list(conn, f"/sis-ui/api/v2/assets/{_id(asset_id)}/errors", limit)


def asset_stats(conn: DcsConnection) -> dict:
    return _object(conn, "/sis-ui/api/v1/sa/assets/statistics")


def alerts(
    conn: DcsConnection, sort: str, offset: int = 0, limit: int = 100, filter_text: str = ""
) -> dict:
    return _page(conn, "/sis-ui/api/v2/alerts", sort, offset, limit, filter_text)


def alert_rules(
    conn: DcsConnection, sort: str, offset: int = 0, limit: int = 100, filter_text: str = ""
) -> dict:
    return _page(conn, "/sis-ui/api/v2/alertrules", sort, offset, limit, filter_text)


def alert_stats(conn: DcsConnection) -> dict:
    return _object(conn, "/sis-ui/api/v1/alerts/statistics")


def events(
    conn: DcsConnection, sort: str, offset: int = 0, limit: int = 100, filter_text: str = ""
) -> dict:
    return _page(conn, "/sis-ui/api/v2/events", sort, offset, limit, filter_text)


def event_stats(conn: DcsConnection, filter_text: str = "") -> dict:
    if len(filter_text) > 200:
        raise ValueError("filter_text must be at most 200 characters")
    params = {"filter": filter_text} if filter_text else None
    return _object(conn, "/sis-ui/api/v1/events/statistics", params)


def policies(conn: DcsConnection, filter_text: str = "", limit: int = 100) -> dict:
    if len(filter_text) > 200 or not 1 <= limit <= 100:
        raise ValueError("filter_text must be bounded and limit 1–100")
    params = {"filter": filter_text} if filter_text else None
    data = conn.get("/sis-ui/api/v2/policies", params=params)
    if not isinstance(data, list) or any(not isinstance(row, dict) for row in data):
        raise DcsError("DCS returned an unexpected policy list")
    return {
        "items": data[:limit],
        "returned": min(len(data), limit),
        "limit": limit,
        "truncated": len(data) > limit,
        "totalFetched": len(data),
    }


def policy(conn: DcsConnection, policy_id: int) -> dict:
    return _object(conn, f"/sis-ui/api/v2/policies/{_id(policy_id)}")


def policy_violations(conn: DcsConnection, policy_id: int, limit: int = 100) -> dict:
    return _list(conn, f"/sis-ui/api/v2/policies/{_id(policy_id)}/violations", limit)


def asset(conn: DcsConnection, asset_id: int) -> dict:
    """Read one managed asset."""
    return _object(conn, f"/sis-ui/api/v1/sa/assets/{_id(asset_id)}")


def asset_tags(conn: DcsConnection, asset_id: int, limit: int = 100) -> dict:
    """Read asset tags."""
    return _list(conn, f"/sis-ui/api/v2/assets/{_id(asset_id)}/tags", limit)


def asset_policies(conn: DcsConnection, asset_id: int, limit: int = 100) -> dict:
    """List policies assigned to an asset."""
    return _list(conn, f"/sis-ui/api/v1/sa/assets/{_id(asset_id)}/policies", limit)


def asset_history(conn: DcsConnection, asset_id: int, limit: int = 100) -> dict:
    """Read asset change history."""
    return _list(conn, f"/sis-ui/api/v1/sa/assets/{_id(asset_id)}/history", limit)


def licenses(conn: DcsConnection, limit: int = 100) -> dict:
    """List license inventory."""
    return _list(conn, "/sis-ui/api/v2/licenses", limit)


def reports(conn: DcsConnection, limit: int = 100) -> dict:
    """List report definitions."""
    return _list(conn, "/sis-ui/api/v1/reports/list", limit)


def report_stats(conn: DcsConnection) -> dict:
    """Read report counts."""
    return _object(conn, "/sis-ui/api/v1/reports/statistics")


def report_jobs(conn: DcsConnection, limit: int = 100) -> dict:
    """List report job states."""
    return _list(conn, "/sis-ui/api/v2/reports/jobs", limit)


def report_job(conn: DcsConnection, job_id: int) -> dict:
    """Read one report job state."""
    return _object(conn, f"/sis-ui/api/v2/reports/jobs/{_id(job_id)}")


def roles(conn: DcsConnection, limit: int = 100) -> dict:
    """List RBAC roles."""
    return _list(conn, "/sis-ui/api/v2/roles", limit)


def role(conn: DcsConnection, role_id: int) -> dict:
    """Read one RBAC role."""
    return _object(conn, f"/sis-ui/api/v2/roles/{_id(role_id)}")


def role_users(conn: DcsConnection, role_id: int, limit: int = 100) -> dict:
    """List users assigned to a role."""
    return _list(conn, f"/sis-ui/api/v2/roles/{_id(role_id)}/users", limit)


def security_groups(conn: DcsConnection, limit: int = 100) -> dict:
    """List security groups."""
    return _list(conn, "/sis-ui/api/v2/securitygroups", limit)


def security_group(conn: DcsConnection, group_id: int) -> dict:
    """Read one security group."""
    return _object(conn, f"/sis-ui/api/v1/sa/securitygroups/{_id(group_id)}")


def security_group_stats(conn: DcsConnection) -> dict:
    """Read security group counts."""
    return _object(conn, "/sis-ui/api/v1/sa/securitygroups/statistics")


def tags(conn: DcsConnection, limit: int = 100) -> dict:
    """List policy and asset tags."""
    return _list(conn, "/sis-ui/api/v2/tags", limit)


def syslogs(conn: DcsConnection, limit: int = 100) -> dict:
    """List syslog destinations."""
    return _list(conn, "/sis-ui/api/v2/settings/syslogs", limit)


def server_registry(conn: DcsConnection, limit: int = 100) -> dict:
    """List registered servers."""
    return _list(conn, "/sis-ui/api/v2/server/registry", limit)


def policy_settings(conn: DcsConnection, policy_id: int) -> dict:
    """Read policy settings."""
    return _object(conn, f"/sis-ui/api/v2/policies/{_id(policy_id)}/settings")


def policy_library(conn: DcsConnection, limit: int = 100) -> dict:
    """List library policies."""
    return _list(conn, "/sis-ui/api/v2/policies/library", limit)


def alert_details(conn: DcsConnection, alert_id: int) -> dict:
    """Read alert rule details."""
    return _object(conn, f"/sis-ui/api/v1/alerts/{_id(alert_id)}/details")


def alert_notifications(conn: DcsConnection, limit: int = 100) -> dict:
    """List recent alert notifications."""
    return _list(conn, "/sis-ui/api/v1/alerts/notifications", limit)


def users(conn: DcsConnection, limit: int = 100) -> dict:
    """List management users."""
    return _list(conn, "/sis-ui/api/v2/users", limit)
