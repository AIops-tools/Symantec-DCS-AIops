"""Documented read-only Symantec DCS management operations."""

from __future__ import annotations

from symantec_dcs_aiops.connection import DcsConnection, DcsError


def _id(value: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ValueError("resource ID must be a positive integer")
    return value


def _object(conn: DcsConnection, path: str) -> dict:
    data = conn.get(path)
    if not isinstance(data, dict) or not data:
        raise DcsError(f"DCS returned an unexpected object for {path}")
    return {"data": data}


def _list(conn: DcsConnection, path: str, params: dict | None = None) -> dict:
    data = conn.get(path, params=params)
    if not isinstance(data, list) or any(not isinstance(row, dict) for row in data):
        raise DcsError(f"DCS returned an unexpected list for {path}")
    return {"items": data, "returned": len(data), "paginationKnown": False}


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


def asset_errors(conn: DcsConnection, asset_id: int) -> dict:
    return _list(conn, f"/sis-ui/api/v2/assets/{_id(asset_id)}/errors")


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
    return (
        _object(conn, "/sis-ui/api/v1/events/statistics")
        if not filter_text
        else {"data": conn.get("/sis-ui/api/v1/events/statistics", params={"filter": filter_text})}
    )


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


def policy_violations(conn: DcsConnection, policy_id: int) -> dict:
    return _list(conn, f"/sis-ui/api/v2/policies/{_id(policy_id)}/violations")
