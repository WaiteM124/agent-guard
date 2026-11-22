"""Shared fixtures for the agent-guard tests."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

from pydantic import BaseModel, ConfigDict

from agent_guard import Guard

AP_POLICY = """
version: 1
default: deny
approval_ttl: 30m
tools:
  read_invoice:
    effect: allow
    reason: read is safe
  create_supplier:
    effect: require_approval
    reason: new supplier
  make_payment:
    effect: require_approval
    reason: payment needs a person
    conditions:
      - when: "amount > 1000"
        effect: deny
        reason: above 1000
      - when: "amount <= 0"
        effect: deny
        reason: amount must be positive
"""


class ManualClock:
    """Mutable clock so tests can step up to an expiry boundary."""

    def __init__(self) -> None:
        self.now = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)

    def __call__(self) -> datetime:
        return self.now

    def advance(self, **kwargs: float) -> None:
        self.now = self.now + timedelta(**kwargs)


class ReadInvoice(BaseModel):
    model_config = ConfigDict(extra="forbid")
    invoice_id: str


class CreateSupplier(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str
    vat: str
    bank_account: str


class MakePayment(BaseModel):
    model_config = ConfigDict(extra="forbid")
    supplier_id: str
    amount: int
    currency: str
    reference: str


def write_policy(tmp_path: Path, text: str = AP_POLICY) -> Path:
    path = tmp_path / "policy.yaml"
    path.write_text(text, encoding="utf-8")
    return path


def make_guard(
    tmp_path: Path,
    clock: ManualClock | None = None,
    store: Path | None = None,
    *,
    text: str = AP_POLICY,
) -> Guard:
    audit: Path = tmp_path / "audit.jsonl"
    return Guard.from_policy(write_policy(tmp_path, text), audit=audit, store=store, clock=clock)
