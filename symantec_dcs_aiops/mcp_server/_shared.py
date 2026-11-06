"""Shared MCP registration and sanitized DCS errors."""

from __future__ import annotations

import functools
import logging
from collections.abc import Callable
from typing import Any

from mcp.server import MCPServer

from symantec_dcs_aiops import __version__
from symantec_dcs_aiops.connection import DcsError
from symantec_dcs_aiops.governance import sanitize

logger = logging.getLogger(__name__)
_ERROR_MAX = 800


def tool_errors() -> Callable:
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            try:
                return func(*args, **kwargs)
            except (DcsError, ValueError) as exc:
                logger.warning("Tool %s failed: %s", func.__name__, type(exc).__name__)
                return {"error": sanitize(str(exc), _ERROR_MAX)}
            except Exception:
                logger.exception("Tool %s failed", func.__name__)
                return {"error": "Unexpected DCS operation failure; check server logs."}

        return wrapper

    return decorator


mcp = MCPServer(
    "symantec-dcs-aiops",
    version=__version__,
    instructions=(
        "Audited DCS service, asset, event, policy, report and role read tools. "
        "No state-changing tools in this preview."
    ),
)
