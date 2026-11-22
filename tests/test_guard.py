"""Guard call path: schema, policy, approval, idempotency, and direct calls."""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import BaseModel, ConfigDict

from agent_guard import (
    ConfigurationError,
    Guard,
    PolicyError,
    SchemaError,
    SelfApprovalError,
    ToolBlocked,
)
from agent_guard.audit import JsonlAuditSink
from tests.support import (
    CreateSupplier,
    MakePayment,
    ManualClock,
    ReadInvoice,
    make_guard,
)


class Loose(BaseModel):
    model_config = ConfigDict(extra="ignore")
    amount: int


def _register(guard: Guard, sink: list[str]) -> None:
    @guard.tool(schema=ReadInvoice)
    def read_invoice(invoice_id: str) -> dict[str, str]:
        sink.append(f"read:{invoice_id}")
        return {"invoice_id": invoice_id}

    @guard.tool(schema=CreateSupplier)
    def create_supplier(name: str, vat: str, bank_account: str) -> dict[str, str]:
        sink.append(f"supplier:{name}")
        return {"name": name, "vat": vat, "bank_account": bank_account}

    @guard.tool(schema=MakePayment)
    def make_payment(
        supplier_id: str, amount: int, currency: str, reference: str
    ) -> dict[str, int]:
        sink.append(f"pay:{supplier_id}:{amount}")
        return {"amount": amount}


def _pay(amount: int, supplier: str = "acme") -> dict[str, object]:
    return {"supplier_id": supplier, "amount": amount, "currency": "GBP", "reference": "inv"}


def test_allow_deny_invalid_and_unknown(tmp_path: Path) -> None:
    sink: list[str] = []
    guard = make_guard(tmp_path)
    _register(guard, sink)
    allowed = guard.call("read_invoice", {"invoice_id": "inv-1"}, actor="ap-agent")
    assert allowed.status == "executed"
    assert allowed.executed is True
    assert allowed.output == {"invoice_id": "inv-1"}
    denied = guard.call("make_payment", _pay(1500), actor="ap-agent")
    invalid = guard.call("make_payment", {**_pay(99999), "approved": True}, actor="ap-agent")
    unknown = guard.call("wire_funds", {"amount": 1}, actor="ap-agent")
    assert denied.status == "denied"
    assert invalid.status == "invalid"
    assert any(issue.loc == "approved" for issue in invalid.issues)
    assert unknown.status == "denied"
    assert sink == ["read:inv-1"]
    assert JsonlAuditSink(tmp_path / "audit.jsonl").verify().ok is True
    with pytest.raises(ValueError):
        guard.call("read_invoice", {"invoice_id": "x"}, actor="  ")
    assert guard.call("read_invoice", ["nope"], actor="ap-agent").status == "invalid"  # type: ignore[arg-type]
    assert guard.call("read_invoice", {1: "x"}, actor="ap-agent").status == "invalid"  # type: ignore[dict-item]


def test_approval_flow_is_idempotent_and_four_eyes(tmp_path: Path) -> None:
    sink: list[str] = []
    clock = ManualClock()
    guard = make_guard(tmp_path, clock)
    _register(guard, sink)
    first = guard.call("make_payment", _pay(500), actor="ap-agent")
    second = guard.call("make_payment", _pay(500), actor="ap-agent")
    assert first.status == "pending"
    assert second.action_id == first.action_id
    assert sink == []
    waiting = guard.pending()
    assert len(waiting) == 1
    assert waiting[0].arguments["amount"] == 500
    assert first.action_id is not None
    with pytest.raises(SelfApprovalError):
        guard.approve(first.action_id, approver="ap-agent")
    assert guard.pending()[0].action_id == first.action_id
    approved = guard.approve(first.action_id, approver="controller", reason="ok")
    assert approved.status == "approved"
    ran = guard.call("make_payment", _pay(500), actor="ap-agent")
    assert ran.status == "executed"
    assert ran.decision == "executed"
    replay = guard.execute(first.action_id)
    assert replay.decision == "replay"
    assert replay.executed is False
    assert sink == ["pay:acme:500"]
    zero = guard.call("make_payment", _pay(0), actor="ap-agent")
    assert zero.status == "denied"


def test_reject_releases_the_key_and_expiry_blocks_then_allows_a_new_proposal(
    tmp_path: Path,
) -> None:
    sink: list[str] = []
    clock = ManualClock()
    guard = make_guard(tmp_path, clock)
    _register(guard, sink)
    created = guard.call(
        "create_supplier", {"name": "Acme", "vat": "GB1", "bank_account": "1"}, actor="ap-agent"
    )
    assert created.action_id is not None
    rejected = guard.reject(created.action_id, approver="ap-agent", reason="withdraw")
    assert rejected.status == "rejected"
    again = guard.call(
        "create_supplier", {"name": "Acme", "vat": "GB1", "bank_account": "1"}, actor="ap-agent"
    )
    assert again.action_id != created.action_id
    clock.advance(minutes=30)
    assert again.action_id is not None
    expired = guard.approve(again.action_id, approver="controller")
    assert expired.status == "expired"
    renewed = guard.call(
        "create_supplier", {"name": "Acme", "vat": "GB1", "bank_account": "1"}, actor="ap-agent"
    )
    assert renewed.action_id not in {created.action_id, again.action_id}
    assert sink == []


def test_failed_allow_and_failed_approval_retry(tmp_path: Path) -> None:
    sink: list[str] = []
    guard = make_guard(tmp_path)

    @guard.tool(schema=ReadInvoice)
    def read_invoice(invoice_id: str) -> dict[str, str]:
        sink.append(invoice_id)
        raise RuntimeError("disk")

    failed = guard.call("read_invoice", {"invoice_id": "inv"}, actor="ap-agent")
    assert failed.status == "failed"
    assert "disk" in failed.reason
    guard.call("read_invoice", {"invoice_id": "inv"}, actor="ap-agent")
    assert sink == ["inv", "inv"]

    calls = {"n": 0}

    @guard.tool(schema=MakePayment, name="make_payment")
    def make_payment(
        supplier_id: str, amount: int, currency: str, reference: str
    ) -> dict[str, str]:
        del supplier_id, currency, reference
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("downstream down")
        return {"status": "paid", "amount": str(amount)}

    pending = guard.call("make_payment", _pay(20), actor="ap-agent")
    assert pending.action_id is not None
    guard.approve(pending.action_id, approver="controller")
    first = guard.execute(pending.action_id)
    assert first.status == "failed"
    second = guard.execute(pending.action_id)
    assert second.status == "executed"
    assert calls["n"] == 2
    third = guard.call("make_payment", _pay(20), actor="ap-agent")
    assert third.decision == "replay"
    assert calls["n"] == 2


def test_registration_rules_and_wrap(tmp_path: Path) -> None:
    sink: list[str] = []
    guard = make_guard(tmp_path)
    _register(guard, sink)
    with pytest.raises(SchemaError):
        guard.tool(schema=ReadInvoice)(lambda invoice_id: invoice_id)
    with pytest.raises(SchemaError):
        guard.register("export_invoices", lambda: None, Loose)  # type: ignore[arg-type]
    with pytest.raises(PolicyError):
        Guard.from_policy(tmp_path / "nope.yaml", audit=tmp_path / "other.jsonl")
    with pytest.raises(SchemaError):
        guard.register("read_invoice", lambda invoice_id: invoice_id, ReadInvoice)

    def plain(invoice_id: str) -> dict[str, str]:
        return {"invoice_id": invoice_id}

    wrapped_dir = tmp_path / "wrap"
    wrapped_dir.mkdir()
    other = make_guard(wrapped_dir)
    wrapped = other.wrap(plain, ReadInvoice, actor="ap-agent", name="read_invoice")
    assert wrapped(invoice_id="inv-9").status == "executed"


def test_decorator_executes_allowed_work_and_blocks_pending(tmp_path: Path) -> None:
    guard = make_guard(tmp_path)
    seen: list[str] = []

    @guard.tool(schema=ReadInvoice)
    def read_invoice(invoice_id: str) -> dict[str, str]:
        seen.append(invoice_id)
        return {"invoice_id": invoice_id}

    with pytest.raises(ConfigurationError):
        read_invoice(invoice_id="inv-1")
    assert seen == []
    with guard.acting_as("ap-agent"):
        assert read_invoice("inv-1") == {"invoice_id": "inv-1"}
    assert seen == ["inv-1"]

    @guard.tool(schema=MakePayment)
    def make_payment(
        supplier_id: str, amount: int, currency: str, reference: str
    ) -> dict[str, int]:
        del supplier_id, currency, reference
        return {"amount": amount}

    with guard.acting_as("ap-agent"), pytest.raises(ToolBlocked) as caught:
        make_payment(supplier_id="acme", amount=10, currency="GBP", reference="r")
    assert caught.value.result.status == "pending"  # type: ignore[attr-defined]


def test_unregistered_policy_tool_and_tool_outside_policy(tmp_path: Path) -> None:
    guard = make_guard(tmp_path)
    with pytest.raises(ConfigurationError):
        guard.call("read_invoice", {"invoice_id": "1"}, actor="ap-agent")

    class Export(BaseModel):
        model_config = ConfigDict(extra="forbid")
        scope: str

    def export_invoices(scope: str) -> dict[str, str]:
        return {"scope": scope}

    guard.register("export_invoices", export_invoices, Export)
    denied = guard.call("export_invoices", {"scope": "all"}, actor="ap-agent")
    invalid = guard.call("export_invoices", {"scope": "all", "extra": True}, actor="ap-agent")
    assert denied.status == "denied"
    assert invalid.status == "invalid"


def test_policy_field_must_exist_on_the_schema(tmp_path: Path) -> None:
    text = """
    version: 1
    default: deny
    tools:
      pay:
        effect: deny
        conditions:
          - when: "totally_unknown > 1"
            effect: allow
    """
    guard = make_guard(tmp_path, text=text)

    class Pay(BaseModel):
        model_config = ConfigDict(extra="forbid")
        amount: int

    with pytest.raises(PolicyError):
        guard.register("pay", lambda amount: amount, Pay)


def test_non_json_result_and_execute_of_unknown_action(tmp_path: Path) -> None:
    guard = make_guard(tmp_path)

    class Thing:
        pass

    @guard.tool(schema=ReadInvoice)
    def read_invoice(invoice_id: str) -> Thing:
        del invoice_id
        return Thing()

    result = guard.call("read_invoice", {"invoice_id": "1"}, actor="ap-agent")
    assert isinstance(result.output, dict)
    assert "_repr" in result.output
    with pytest.raises(Exception, match="No action"):
        guard.execute("missing")
    with pytest.raises(ConfigurationError):
        guard.call(
            "make_payment",
            {"supplier_id": "acme", "amount": 10, "currency": "GBP", "reference": "r"},
            actor="ap-agent",
        )
