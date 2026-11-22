"""Optional adapters. The core library does not import LangGraph or MCP."""

from agent_guard.integrations.langgraph import invoke, langgraph_interrupt
from agent_guard.integrations.mcp import ToolSpec, register_fastmcp, wrap_handler

__all__ = [
    "ToolSpec",
    "invoke",
    "langgraph_interrupt",
    "register_fastmcp",
    "wrap_handler",
]
