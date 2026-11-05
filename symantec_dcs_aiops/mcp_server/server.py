"""Symantec DCS AIops MCP server over stdio."""

from symantec_dcs_aiops.mcp_server._annotations import apply_risk_annotations
from symantec_dcs_aiops.mcp_server._shared import mcp
from symantec_dcs_aiops.mcp_server.tools import dcs  # noqa: F401

apply_risk_annotations(mcp)


def main() -> None:
    mcp.run(transport="stdio")
