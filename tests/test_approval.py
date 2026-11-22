"""Approval state machine, idempotency, and the file-backed store."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from agent_guard import (
    ActionNotFoundError,
    ApprovalError,
    ApprovalGateway,
    ApprovalState,
    ConfigurationError,
    InvalidTransitionError,
    JsonFileApprovalBackend,
    MemoryApprovalBackend,
    PayloadError,
    SelfApprovalError,
)
from agent_guard.approval import ProposedAction, compute_idempotency_key, hash_arguments
from agent_guard.canonical import canonical_json
from tests.support import ManualClock


def _gateway(tmp_path: Path, kind: str, clock: ManualClock) -> ApprovalGateway:
    if kind == "memory":
        backend = MemoryApprovalBackend()
    else:
        backend = JsonFileApprovalBackend(tmp_path / f"{kind}.json")
    return ApprovalGateway(backend, approval_ttl=timedelta(minutes=30), clock=clock)


@pytest.fixture(params=["memory", "file"])
def box(request: pytest.FixtureRequest, tmp_path: Path) -> tuple[ApprovalGateway, ManualClock]:
    clock = ManualClock()
    return _gateway(tmp_path, str(request.param), clock), clock


def test_idempotency_key_ignores_object_key_order() -> None:
    left = compute_idempotency_key("actor", "pay", {"b": 1, "a": 2})
    right = compute_idempotency_key("actor", "pay", {"a": 2, "b": 1})
    assert left == right
    assert compute_idempotency_key("other", "pay", {"a": 2, "b": 1}) != left
    assert canonical_json({"b": 1, "a": 2}) == canonical_json({"a": 2, "b": 1})
    assert len(hash_arguments({"amount": 1})) == 64
    assert len(hash_arguments({1, 2})) == 64
    with pytest.raises(PayloadError):
        canonical_json({1, 2})


def test_propose_is_idempotent_until_the_key_is_released(
    box: tuple[ApprovalGateway, ManualClock],
) -> None:
    gateway, _clock = box
    first = gateway.propose("agent", "pay", {"amount": 10, "currency": "GBP"})
    second = gateway.propose("agent", "pay", {"currency": "GBP", "amount": 10})
    assert first.created is True
    assert second.created is False
    assert first.action.action_id == second.action.action_id
    assert first.action.state is ApprovalState.AWAITING_APPROVAL
    expires = first.action.approval_expires_at
    assert expires == second.action.approval_expires_at

    rejected = gateway.resolve(
        first.action.action_id, approved=False, resolved_by="agent", reason="withdraw"
    )
    assert rejected.state is ApprovalState.REJECTED
    third = gateway.propose("agent", "pay", {"amount": 10, "currency": "GBP"})
    assert third.created is True
    assert third.action.action_id != first.action.action_id


def test_four_eyes_and_expiry(box: tuple[ApprovalGateway, ManualClock]) -> None:
    gateway, clock = box
    proposed = gateway.propose("agent", "pay", {"amount": 10})
    action_id = proposed.action.action_id
    with pytest.raises(SelfApprovalError):
        gateway.resolve(action_id, approved=True, resolved_by=" agent ", reason="me")
    assert gateway.get(action_id).state is ApprovalState.AWAITING_APPROVAL

    approved = gateway.resolve(action_id, approved=True, resolved_by="controller", reason="ok")
    assert approved.state is ApprovalState.APPROVED
    assert approved.resolved_by == "controller"
    clock.advance(hours=5)
    assert gateway.expire_stale() == []

    def runner(_action: ProposedAction) -> dict[str, bool]:
        return {"ok": True}

    done = gateway.execute_if_ready(action_id, runner)
    assert done.invoked is True
    assert done.action.state is ApprovalState.EXECUTED
    again = gateway.execute_if_ready(action_id, runner)
    assert again.invoked is False
    assert again.action.result == {"ok": True}


def test_expiry_releases_the_key_and_blocks_execution(
    box: tuple[ApprovalGateway, ManualClock],
) -> None:
    gateway, clock = box
    proposed = gateway.propose("agent", "pay", {"amount": 10})
    action_id = proposed.action.action_id
    clock.advance(minutes=30)
    expired = gateway.resolve(action_id, approved=True, resolved_by="agent")
    assert expired.state is ApprovalState.EXPIRED
    with pytest.raises(InvalidTransitionError):
        gateway.execute_if_ready(action_id, lambda _action: {"ok": True})
    fresh = gateway.propose("agent", "pay", {"amount": 10})
    assert fresh.action.action_id != action_id
    assert fresh.action.state is ApprovalState.AWAITING_APPROVAL


def test_failed_is_retryable_and_keeps_the_key(box: tuple[ApprovalGateway, ManualClock]) -> None:
    gateway, _clock = box
    action_id = gateway.propose("agent", "pay", {"amount": 10}).action.action_id
    gateway.resolve(action_id, approved=True, resolved_by="controller")

    def boom(_action: ProposedAction) -> dict[str, bool]:
        raise RuntimeError("downstream down")

    failed = gateway.execute_if_ready(action_id, boom)
    assert failed.invoked is True
    assert failed.action.state is ApprovalState.FAILED
    assert "downstream down" in (failed.action.failure_reason or "")
    replay = gateway.propose("agent", "pay", {"amount": 10})
    assert replay.action.action_id == action_id
    recovered = gateway.execute_if_ready(action_id, lambda _action: {"ok": True})
    assert recovered.action.state is ApprovalState.EXECUTED


def test_sweep_only_expires_waiting_actions(box: tuple[ApprovalGateway, ManualClock]) -> None:
    gateway, clock = box
    waiting = gateway.propose("agent", "pay", {"amount": 1}).action.action_id
    held = gateway.propose("agent", "pay", {"amount": 2}).action.action_id
    gateway.resolve(held, approved=True, resolved_by="controller")
    clock.advance(minutes=31)
    expired = gateway.expire_stale()
    assert [item.action_id for item in expired] == [waiting]
    assert gateway.get(held).state is ApprovalState.APPROVED
    assert gateway.list_actions(ApprovalState.AWAITING_APPROVAL) == []


def test_illegal_transitions_name_the_allowed_states() -> None:
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    action = ProposedAction(
        action_id="a",
        actor_id="actor",
        tool="pay",
        payload={"amount": 1},
        args_hash="h",
        idempotency_key="k",
        created_at=now,
    )
    with pytest.raises(InvalidTransitionError, match="allowed"):
        action.transition(ApprovalState.EXECUTED, now=now)
    action.state = ApprovalState.FAILED
    action.transition(ApprovalState.FAILED, now=now, reason="still down")
    assert action.state is ApprovalState.FAILED
    action.transition(ApprovalState.EXECUTED, now=now, reason="executed")
    assert action.executed_at == now
    with pytest.raises(InvalidTransitionError):
        action.transition(ApprovalState.APPROVED, now=now)


def test_gateway_rejects_bad_inputs(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        ApprovalGateway(approval_ttl=timedelta(0))
    gateway = ApprovalGateway(clock=lambda: datetime(2026, 1, 1))
    with pytest.raises(ValueError):
        gateway.propose("actor", "pay", {})
    gateway = ApprovalGateway()
    with pytest.raises(ValueError):
        gateway.propose("  ", "pay", {})
    with pytest.raises(PayloadError):
        gateway.propose("actor", "pay", {"bad": {1}})
    with pytest.raises(ActionNotFoundError):
        gateway.get("missing")
    backend = MemoryApprovalBackend()
    with pytest.raises(ConfigurationError):
        backend.get("x")
    file_backend = JsonFileApprovalBackend(tmp_path / "approvals.json")
    with pytest.raises(ConfigurationError):
        file_backend.all()


def test_file_store_round_trip_and_corrupt_files(tmp_path: Path) -> None:
    path = tmp_path / "approvals.json"
    clock = ManualClock()
    first = ApprovalGateway(
        JsonFileApprovalBackend(path), approval_ttl=timedelta(minutes=5), clock=clock
    )
    action_id = first.propose("agent", "pay", {"amount": 3}).action.action_id
    second = ApprovalGateway(
        JsonFileApprovalBackend(path), approval_ttl=timedelta(minutes=5), clock=clock
    )
    assert second.get(action_id).tool == "pay"
    path.write_text("{", encoding="utf-8")
    broken = ApprovalGateway(JsonFileApprovalBackend(path), clock=clock)
    with pytest.raises(ApprovalError):
        broken.propose("agent", "pay", {"amount": 3})
    path.write_text(
        '{"version": 1, "actions": [{"state": "nope"}]}',
        encoding="utf-8",
    )
    with pytest.raises(ApprovalError):
        ApprovalGateway(JsonFileApprovalBackend(path), clock=clock).list_actions()
