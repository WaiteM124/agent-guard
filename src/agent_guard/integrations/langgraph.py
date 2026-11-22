"""LangGraph adapter.

A guarded write can be proposed from a graph. It is not executed. The pending
decision is returned as an interrupt payload. Pass :func:`langgraph_interrupt`
as ``on_pending`` inside a graph node to pause on LangGraph's own interrupt.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any

from agent_guard.errors import ConfigurationError
from agent_guard.guard import Guard


def invoke(
    guard: Guard,
    tool: str,
    arguments: Mapping[str, Any],
    *,
    actor: str,
    on_pending: Callable[[dict[str, Any]], Any] | None = None,
) -> Any:
    """Call ``tool`` through ``guard``.

    An approval-required call does not run the tool. It returns the interrupt
    payload, or whatever ``on_pending`` returns when that payload is passed to it.
    An allowed call returns the tool output. Anything else returns a status dict.
    """

    result = guard.call(tool, arguments, actor=actor)
    if result.status == "pending":
        payload = {
            "kind": "agent_guard.approval_required",
            "action_id": result.action_id,
            "tool": tool,
            "reason": result.reason,
        }
        if on_pending is not None:
            return on_pending(payload)
        return payload
    if result.status == "executed":
        return result.output
    return {
        "status": result.status,
        "reason": result.reason,
        "action_id": result.action_id,
        "output": result.output,
    }


def langgraph_interrupt(payload: dict[str, Any]) -> Any:
    """Pause a LangGraph run. Requires the ``langgraph`` extra."""

    try:
        from langgraph.types import interrupt  # type: ignore[import-not-found]
    except ImportError as exc:
        raise ConfigurationError(
            "LangGraph is not installed. Install agent-guard[langgraph] to pause on approval."
        ) from exc
    return interrupt(payload)
