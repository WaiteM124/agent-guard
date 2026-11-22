"""Command line approver and audit verifier.

``agent-guard approve`` changes approval state. It does not run the tool. The
process that registered the tool does that, with :meth:`agent_guard.Guard.execute`
or a later :meth:`agent_guard.Guard.call` of the same arguments.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from agent_guard.approval import (
    ApprovalGateway,
    ApprovalState,
    JsonFileApprovalBackend,
    ProposedAction,
    hash_arguments,
)
from agent_guard.audit import AuditEvent, head_path, open_audit, verify_path
from agent_guard.errors import (
    ActionNotFoundError,
    ApprovalError,
    AuditError,
    InvalidTransitionError,
    SelfApprovalError,
)


def execute(argv: list[str] | None = None) -> int:
    """Run the CLI. Returns a process exit code and does not call ``sys.exit``."""

    parser = _parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        code = exc.code
        if code is None:
            return 0
        if isinstance(code, int):
            return code
        return 2
    try:
        if args.command == "approve":
            return _decide(args, approved=True)
        if args.command == "reject":
            return _decide(args, approved=False)
        if args.command == "list":
            return _list(args)
        if args.command == "audit" and args.audit_command == "verify":
            return _verify(args)
        if args.command == "audit" and args.audit_command == "head":
            return _head(args)
    except (ApprovalError, AuditError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        if isinstance(exc, AuditError):
            return 1
        return 2
    print("unknown command", file=sys.stderr)
    return 2


def main(argv: list[str] | None = None) -> None:
    """Console-script entry point."""

    raise SystemExit(execute(argv))


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="agent-guard")
    sub = parser.add_subparsers(dest="command", required=True)

    approve = sub.add_parser("approve", help="approve a pending action")
    _decision_args(approve)
    reject = sub.add_parser("reject", help="reject a pending action")
    _decision_args(reject)

    listing = sub.add_parser("list", help="list actions and expire stale ones")
    listing.add_argument("--store", required=True, type=Path)
    listing.add_argument("--audit", required=True, type=Path)
    listing.add_argument("--state", default=None)

    audit = sub.add_parser("audit", help="inspect the hash-chained audit log")
    audit_sub = audit.add_subparsers(dest="audit_command", required=True)
    verify = audit_sub.add_parser("verify", help="recompute the hash chain")
    verify.add_argument("path", type=Path)
    verify.add_argument("--expect", default=None, help="fail unless the head hash is this value")
    head = audit_sub.add_parser("head", help="print the latest record hash")
    head.add_argument("path", type=Path)
    return parser


def _decision_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("action_id")
    parser.add_argument("--by", required=True, help="id of the person deciding")
    parser.add_argument("--store", required=True, type=Path)
    parser.add_argument("--audit", required=True, type=Path)
    parser.add_argument("--reason", default=None)


def _gateway(path: Path) -> ApprovalGateway:
    return ApprovalGateway(JsonFileApprovalBackend(path))


def _decide(args: argparse.Namespace, *, approved: bool) -> int:
    gateway = _gateway(args.store)
    try:
        action = gateway.resolve(
            args.action_id,
            approved=approved,
            resolved_by=args.by,
            reason=args.reason,
        )
    except SelfApprovalError as exc:
        _audit_known(args, exc.action_id, "self_approval", str(exc), "blocked")
        print(str(exc), file=sys.stderr)
        return 2
    except ActionNotFoundError as exc:
        _audit_missing(args, str(exc))
        print(str(exc), file=sys.stderr)
        return 2
    except InvalidTransitionError as exc:
        _audit_known(args, args.action_id, "invalid_transition", str(exc), "error")
        print(str(exc), file=sys.stderr)
        return 2

    if action.state == ApprovalState.APPROVED:
        label = "approved"
        code = 0
    elif action.state == ApprovalState.REJECTED:
        label = "rejected"
        code = 0
    elif action.state == ApprovalState.EXPIRED:
        label = "expired"
        code = 3
    else:
        print(action.state.value, file=sys.stderr)
        return 2
    reason = action.resolution_reason or label
    _write(args.audit, action, decision=label, decided_by=args.by, reason=reason, outcome=label)
    print(action.state.value)
    return code


def _list(args: argparse.Namespace) -> int:
    state: ApprovalState | None
    if args.state is None:
        state = None
    else:
        try:
            state = ApprovalState(args.state)
        except ValueError:
            print(f"unknown state {args.state}", file=sys.stderr)
            return 2
    gateway = _gateway(args.store)
    expired = gateway.expire_stale()
    for action in expired:
        _write(
            args.audit,
            action,
            decision="expired",
            decided_by="ttl",
            reason="approval window elapsed",
            outcome="expired",
        )
    actions = gateway.list_actions(state)
    print(f"{len(actions)} action(s)")
    for action in actions:
        expires = (
            "-" if action.approval_expires_at is None else action.approval_expires_at.isoformat()
        )
        print(f"{action.action_id} {action.state.value} {action.tool} {action.actor_id} {expires}")
    return 0


def _verify(args: argparse.Namespace) -> int:
    result = verify_path(args.path)
    if not result.ok:
        print(f"tampered at {result.index}: {result.reason}", file=sys.stderr)
        return 1
    if args.expect is not None and args.expect != result.head:
        print("head hash mismatch", file=sys.stderr)
        return 1
    print(f"ok {result.count} {result.head}")
    return 0


def _head(args: argparse.Namespace) -> int:
    print(head_path(args.path))
    return 0


def _write(
    path: Path,
    action: ProposedAction,
    *,
    decision: str,
    decided_by: str,
    reason: str,
    outcome: str,
) -> None:
    open_audit(path).append(
        AuditEvent(
            action_id=action.action_id,
            actor=action.actor_id,
            tool=action.tool,
            args_hash=action.args_hash,
            decision=decision,
            decided_by=decided_by,
            reason=reason,
            outcome=outcome,
        )
    )


def _audit_known(
    args: argparse.Namespace, action_id: str, decision: str, reason: str, outcome: str
) -> None:
    gateway = _gateway(args.store)
    try:
        action = gateway.get(action_id)
    except ActionNotFoundError:
        _audit_missing(args, reason)
        return
    _write(
        args.audit, action, decision=decision, decided_by=args.by, reason=reason, outcome=outcome
    )


def _audit_missing(args: argparse.Namespace, reason: str) -> None:
    open_audit(args.audit).append(
        AuditEvent(
            action_id=args.action_id,
            actor=args.by,
            tool="",
            args_hash=hash_arguments({}),
            decision="missing",
            decided_by=args.by,
            reason=reason,
            outcome="error",
        )
    )
