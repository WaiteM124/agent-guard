"""MCP adapter. Handlers are registered on the guard before they can be called."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from typing import Any, NamedTuple

from pydantic import BaseModel

from agent_guard.guard import Guard


class ToolSpec(NamedTuple):
    """One MCP tool: public name, implementation, and strict argument schema."""

    name: str
    handler: Callable[..., Any]
    schema: type[BaseModel]


def wrap_handler(
    guard: Guard,
    handler: Callable[..., Any],
    schema: type[BaseModel],
    *,
    actor: str,
    name: str | None = None,
) -> Callable[..., Any]:
    """Return a handler that checks policy before calling ``handler``.

    Executed calls return the tool output. Pending and denied calls return a dict
    the model can read. The underlying function does not run in those cases.
    """

    tool_name = name or handler.__name__
    guard.register(tool_name, handler, schema)

    def wrapped(**arguments: Any) -> Any:
        result = guard.call(tool_name, arguments, actor=actor)
        if result.status == "executed":
            return result.output
        if result.status == "pending":
            return {
                "status": "pending",
                "action_id": result.action_id,
                "message": "Approval required before this tool can run.",
                "reason": result.reason,
            }
        return {"status": result.status, "reason": result.reason, "action_id": result.action_id}

    wrapped.__name__ = tool_name
    wrapped.__doc__ = handler.__doc__
    return wrapped


def register_fastmcp(server: Any, guard: Guard, specs: Sequence[ToolSpec], *, actor: str) -> None:
    """Register guarded tools on a server that exposes ``server.tool(name=...)(fn)``."""

    for spec in specs:
        handler = wrap_handler(guard, spec.handler, spec.schema, actor=actor, name=spec.name)
        server.tool(name=spec.name)(handler)
