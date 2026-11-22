"""CLI approve, reject, list, and audit verification."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from agent_guard.cli import execute, main
from tests.support import CreateSupplier, MakePayment, make_guard


def _pay(amount: int = 40) -> dict[str, object]:
    return {"supplier_id": "acme", "amount": amount, "currency": "GBP", "reference": "inv"}


def test_cli_approves_and_verifies(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    store = tmp_path / "approvals.json"
    audit = tmp_path / "audit.jsonl"
    guard = make_guard(tmp_path, store=store)
    sink: list[int] = []

    @guard.tool(schema=MakePayment)
    def make_payment(
        supplier_id: str, amount: int, currency: str, reference: str
    ) -> dict[str, int]:
        del supplier_id, currency, reference
        sink.append(amount)
        return {"amount": amount}

    @guard.tool(schema=CreateSupplier)
    def create_supplier(name: str, vat: str, bank_account: str) -> dict[str, str]:
        del vat, bank_account
        return {"name": name}

    payment = guard.call("make_payment", _pay(), actor="ap-agent")
    supplier = guard.call(
        "create_supplier",
        {"name": "Acme", "vat": "GB1", "bank_account": "1"},
        actor="ap-agent",
    )
    assert payment.action_id is not None
    assert supplier.action_id is not None
    assert execute(["list", "--store", str(store), "--audit", str(audit)]) == 0
    listed = capsys.readouterr().out
    assert "2 action(s)" in listed
    assert payment.action_id in listed
    assert (
        execute(
            [
                "approve",
                payment.action_id,
                "--by",
                "controller",
                "--store",
                str(store),
                "--audit",
                str(audit),
            ]
        )
        == 0
    )
    assert capsys.readouterr().out.strip() == "approved"
    assert (
        execute(
            [
                "reject",
                supplier.action_id,
                "--by",
                "controller",
                "--store",
                str(store),
                "--audit",
                str(audit),
                "--reason",
                "duplicate",
            ]
        )
        == 0
    )
    assert capsys.readouterr().out.strip() == "rejected"
    assert sink == []
    executed = guard.execute(payment.action_id)
    assert executed.status == "executed"
    assert sink == [40]
    assert execute(["audit", "verify", str(audit)]) == 0
    verified = capsys.readouterr().out.strip()
    assert verified.startswith("ok ")
    head = verified.split()[-1]
    assert execute(["audit", "head", str(audit)]) == 0
    assert capsys.readouterr().out.strip() == head
    assert execute(["audit", "verify", str(audit), "--expect", "0" * 64]) == 1


def test_cli_errors(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    store = tmp_path / "approvals.json"
    audit = tmp_path / "audit.jsonl"
    guard = make_guard(tmp_path, store=store)

    @guard.tool(schema=MakePayment)
    def make_payment(
        supplier_id: str, amount: int, currency: str, reference: str
    ) -> dict[str, int]:
        del supplier_id, currency, reference
        return {"amount": amount}

    pending = guard.call("make_payment", _pay(), actor="ap-agent")
    assert pending.action_id is not None
    assert (
        execute(
            [
                "approve",
                pending.action_id,
                "--by",
                "ap-agent",
                "--store",
                str(store),
                "--audit",
                str(audit),
            ]
        )
        == 2
    )
    assert "cannot approve" in capsys.readouterr().err
    assert (
        execute(
            [
                "approve",
                "missing",
                "--by",
                "controller",
                "--store",
                str(store),
                "--audit",
                str(audit),
            ]
        )
        == 2
    )
    guard.approve(pending.action_id, approver="controller")
    assert (
        execute(
            [
                "approve",
                pending.action_id,
                "--by",
                "controller",
                "--store",
                str(store),
                "--audit",
                str(audit),
            ]
        )
        == 2
    )
    assert execute(["list", "--store", str(store), "--audit", str(audit), "--state", "nope"]) == 2
    assert execute(["audit", "verify", str(tmp_path / "missing.jsonl")]) == 1
    with pytest.raises(SystemExit) as exc:
        main(["list"])
    assert exc.value.code == 2


def test_module_entrypoint_verifies_a_log(tmp_path: Path) -> None:
    audit = tmp_path / "audit.jsonl"
    guard = make_guard(tmp_path)

    @guard.tool(schema=MakePayment)
    def make_payment(
        supplier_id: str, amount: int, currency: str, reference: str
    ) -> dict[str, int]:
        del supplier_id, currency, reference
        return {"amount": amount}

    guard.call("make_payment", _pay(5000), actor="ap-agent")
    completed = subprocess.run(
        [sys.executable, "-m", "agent_guard", "audit", "verify", str(audit)],
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.startswith("ok ")
