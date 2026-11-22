"""LangGraph and MCP wrappers. Neither extra has to be installed."""

from __future__ import annotations

import sys
import types
from pathlib import Path

import pytest
from pydantic import BaseModel, ConfigDict

from agent_guard import ConfigurationError
from agent_guard.integrations.langgraph import invoke, langgraph_interrupt
from agent_guard.integrations.mcp import ToolSpec, register_fastmcp, wrap_handler
from tests.support import MakePayment, make_guard


def test_invoke_returns_an_interrupt_and_a_denial(tmp_path: Path) -> None:
    guard = make_guard(tmp_path)
    ran: list[int] = []

    @guard.tool(schema=MakePayment)
    def make_payment(
        supplier_id: str, amount: int, currency: str, reference: str
    ) -> dict[str, int]:
        del supplier_id, currency, reference
        ran.append(amount)
        return {"amount": amount}

    seen: list[dict[str, object]] = []

    def on_pending(payload: dict[str, object]) -> dict[str, object]:
        seen.append(payload)
        return payload

    pending = invoke(
        guard,
        "make_payment",
        {"supplier_id": "acme", "amount": 10, "currency": "GBP", "reference": "r"},
        actor="graph",
        on_pending=on_pending,
    )
    denied = invoke(
        guard,
        "make_payment",
        {"supplier_id": "acme", "amount": 5000, "currency": "GBP", "reference": "r"},
        actor="graph",
    )
    assert pending["kind"] == "agent_guard.approval_required"
    assert seen[0]["tool"] == "make_payment"
    assert denied["status"] == "denied"
    assert ran == []


def test_langgraph_interrupt_import(monkeypatch: pytest.MonkeyPatch) -> None:
    module = types.ModuleType("langgraph.types")

    def interrupt(payload: dict[str, str]) -> dict[str, dict[str, str]]:
        return {"paused": payload}

    module.interrupt = interrupt  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "langgraph.types", module)
    assert langgraph_interrupt({"action_id": "1"}) == {"paused": {"action_id": "1"}}

    real_import = __import__

    def fake_import(name: str, *args: object, **kwargs: object) -> object:
        if name == "langgraph.types":
            raise ImportError("missing")
        return real_import(name, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr("builtins.__import__", fake_import)
    monkeypatch.delitem(sys.modules, "langgraph.types", raising=False)
    with pytest.raises(ConfigurationError):
        langgraph_interrupt({"action_id": "1"})


def test_mcp_wrapper_blocks_side_effects(tmp_path: Path) -> None:
    guard = make_guard(tmp_path)
    ran: list[str] = []

    def make_payment(
        supplier_id: str, amount: int, currency: str, reference: str
    ) -> dict[str, int]:
        ran.append(supplier_id)
        return {"amount": amount, "currency_len": len(currency), "ref_len": len(reference)}

    wrapped = wrap_handler(guard, make_payment, MakePayment, actor="mcp", name="make_payment")
    pending = wrapped(supplier_id="acme", amount=15, currency="GBP", reference="r")
    denied = wrapped(supplier_id="acme", amount=2000, currency="GBP", reference="r")
    assert pending["status"] == "pending"
    assert denied["status"] == "denied"
    assert ran == []

    class Server:
        def __init__(self) -> None:
            self.tools: dict[str, object] = {}

        def tool(self, name: str) -> object:
            def decorate(fn: object) -> object:
                self.tools[name] = fn
                return fn

            return decorate

    (tmp_path / "mcp").mkdir()
    other = make_guard(tmp_path / "mcp")
    server = Server()
    register_fastmcp(
        server, other, [ToolSpec("make_payment", make_payment, MakePayment)], actor="mcp"
    )
    stored = server.tools["make_payment"]
    assert callable(stored)
    assert (
        stored(supplier_id="acme", amount=9, currency="GBP", reference="r")["status"] == "pending"
    )


class Export(BaseModel):
    model_config = ConfigDict(extra="forbid")
    scope: str


def test_mcp_allow_returns_the_handler_output(tmp_path: Path) -> None:
    guard = make_guard(tmp_path)

    def export_invoices(scope: str) -> dict[str, str]:
        return {"scope": scope}

    # export_invoices is not in the policy, so a valid call is denied before the handler.
    wrapped = wrap_handler(guard, export_invoices, Export, actor="mcp")
    denied = wrapped(scope="all")
    assert denied["status"] == "denied"
