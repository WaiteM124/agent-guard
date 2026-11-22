"""Show a guarded tool call surfacing as an interrupt payload.

Runs without LangGraph installed. Inside a graph node, pass ``on_pending=langgraph_interrupt``
so LangGraph pauses until a person resumes the run. Install ``agent-guard[langgraph]`` for that.
"""

from __future__ import annotations

import argparse
from pathlib import Path

from pydantic import BaseModel, ConfigDict

from agent_guard import Guard, JsonlAuditSink
from agent_guard.integrations.langgraph import invoke
from agent_guard.policy import Policy


class MakePayment(BaseModel):
    """Payment arguments."""

    model_config = ConfigDict(extra="forbid")
    supplier_id: str
    amount: int
    currency: str


def main(argv: list[str] | None = None) -> int:
    """Propose a payment and deny one above the limit. Prints the interrupt payload."""

    parser = argparse.ArgumentParser(description="LangGraph-shaped agent-guard example")
    parser.add_argument("--workdir", type=Path, default=Path(__file__).resolve().parent / "runtime")
    args = parser.parse_args(argv)
    workdir: Path = args.workdir
    workdir.mkdir(parents=True, exist_ok=True)
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
        source="langgraph-example",
    )
    guard = Guard(policy, audit=JsonlAuditSink(workdir / "langgraph-audit.jsonl"))

    @guard.tool(schema=MakePayment)
    def make_payment(supplier_id: str, amount: int, currency: str) -> dict[str, object]:
        return {"supplier_id": supplier_id, "amount": amount, "currency": currency}

    pending = invoke(
        guard,
        "make_payment",
        {"supplier_id": "acme", "amount": 40, "currency": "GBP"},
        actor="graph",
    )
    print(f"interrupt kind={pending['kind']} tool={pending['tool']}")
    denied = invoke(
        guard,
        "make_payment",
        {"supplier_id": "acme", "amount": 5000, "currency": "GBP"},
        actor="graph",
    )
    print(f"denied status={denied['status']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
