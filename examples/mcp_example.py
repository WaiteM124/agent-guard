"""Wrap tool handlers the way an MCP server would expose them.

Runs without the MCP SDK. ``register_fastmcp`` targets a server with
``server.tool(name=...)(fn)``, which FastMCP provides.
"""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict

from agent_guard import Guard, JsonlAuditSink
from agent_guard.integrations.mcp import ToolSpec, register_fastmcp
from agent_guard.policy import Policy


class MakePayment(BaseModel):
    """Payment arguments."""

    model_config = ConfigDict(extra="forbid")
    supplier_id: str
    amount: int
    currency: str


class Server:
    """Stand-in for the ``tool`` decorator on an MCP server."""

    def __init__(self) -> None:
        self.tools: dict[str, Any] = {}

    def tool(self, name: str) -> Any:
        def decorate(fn: Any) -> Any:
            self.tools[name] = fn
            return fn

        return decorate


def main(argv: list[str] | None = None) -> int:
    """Show a pending payment and a denied unlisted call through wrapped handlers."""

    parser = argparse.ArgumentParser(description="MCP-shaped agent-guard example")
    parser.add_argument("--workdir", type=Path, default=Path(__file__).resolve().parent / "runtime")
    args = parser.parse_args(argv)
    workdir: Path = args.workdir
    workdir.mkdir(parents=True, exist_ok=True)
    ran: list[str] = []
    policy = Policy.loads(
        """
        version: 1
        default: deny
        approval_ttl: 30m
        tools:
          make_payment:
            effect: require_approval
            conditions:
              - when: "amount > 1000"
                effect: deny
                reason: above 1000
        """,
        source="mcp-example",
    )
    guard = Guard(policy, audit=JsonlAuditSink(workdir / "mcp-audit.jsonl"))

    def make_payment(supplier_id: str, amount: int, currency: str) -> dict[str, object]:
        ran.append(f"{supplier_id}:{amount}:{currency}")
        return {"supplier_id": supplier_id, "amount": amount, "currency": currency}

    server = Server()
    register_fastmcp(
        server,
        guard,
        [ToolSpec("make_payment", make_payment, MakePayment)],
        actor="mcp-client",
    )
    pending = server.tools["make_payment"](supplier_id="acme", amount=80, currency="GBP")
    print(f"pending status={pending['status']}")
    print(f"registered={','.join(sorted(server.tools))}")
    print(f"ran={len(ran)}")
    return 0 if pending["status"] == "pending" and ran == [] else 1


if __name__ == "__main__":
    raise SystemExit(main())
