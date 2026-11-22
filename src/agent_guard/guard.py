"""The object an agent calls instead of calling a tool directly."""

from __future__ import annotations

import inspect
import json
import logging
import re
import uuid
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, TypeVar, cast

from pydantic import BaseModel, ValidationError

from agent_guard.approval import (
    ApprovalBackend,
    ApprovalGateway,
    ApprovalState,
    Clock,
    JsonFileApprovalBackend,
    MemoryApprovalBackend,
    ProposeResult,
    hash_arguments,
    isoformat,
)
from agent_guard.audit import AuditEvent, AuditSink, open_audit
from agent_guard.canonical import canonical_json, json_safe
from agent_guard.errors import (
    ActionNotFoundError,
    ConfigurationError,
    InvalidTransitionError,
    PolicyError,
    SchemaError,
    SelfApprovalError,
    ToolBlocked,
)
from agent_guard.policy import Effect, Policy, PolicyDecision, load_policy

logger = logging.getLogger("agent_guard")

_current_actor: ContextVar[str | None] = ContextVar("agent_guard_actor", default=None)
_TOOL_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
F = TypeVar("F", bound=Callable[..., Any])


def _require_text(value: str, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field_name} is required")
    return value.strip()


@dataclass(frozen=True)
class ValidationIssue:
    """One schema failure, safe to show back to an agent."""

    loc: str
    message: str


@dataclass(frozen=True)
class GuardResult:
    """What happened to one tool call or one human decision.

    ``status`` is ``executed``, ``pending``, ``denied``, ``invalid``, ``approved``,
    ``rejected``, ``expired``, or ``failed``. ``decision`` is the audit label.
    ``output`` is set only when a tool function ran and returned.
    """

    status: str
    action_id: str | None
    output: Any
    reason: str
    decision: str
    state: str | None = None
    issues: tuple[ValidationIssue, ...] = ()

    @property
    def executed(self) -> bool:
        """True when the tool function ran on this call."""

        return self.status == "executed" and self.decision != "replay"


@dataclass(frozen=True)
class PendingAction:
    """An approval a person can still answer."""

    action_id: str
    actor: str
    tool: str
    arguments: dict[str, Any]
    state: str
    created_at: str
    expires_at: str | None
    idempotency_key: str


@dataclass(frozen=True)
class _Tool:
    name: str
    fn: Callable[..., Any]
    schema: type[BaseModel]


class Guard:
    """Policy, schema check, approval, and audit in front of tool functions.

    Register each tool with :meth:`tool` or :meth:`register`. Invoke it with
    :meth:`call` or :meth:`wrap`. A decorated function called directly goes through
    the same checks, and it needs :meth:`acting_as` so the actor id does not come
    from the model.
    """

    def __init__(
        self,
        policy: Policy,
        *,
        audit: AuditSink,
        approvals: ApprovalBackend | None = None,
        clock: Clock | None = None,
    ) -> None:
        self.policy = policy
        self._audit = audit
        self._clock = clock or (lambda: datetime.now().astimezone())
        self._gateway = ApprovalGateway(
            approvals,
            approval_ttl=policy.approval_ttl,
            clock=self._clock,
        )
        self._tools: dict[str, _Tool] = {}

    @classmethod
    def from_policy(
        cls,
        path: str | Path,
        *,
        audit: str | Path | AuditSink = "audit.jsonl",
        store: str | Path | ApprovalBackend | None = None,
        clock: Clock | None = None,
    ) -> Guard:
        """Load ``path``, open an audit sink, and choose the approval store.

        ``audit`` is a JSONL path unless the suffix is ``.db``, ``.sqlite``, or
        ``.sqlite3``. ``store`` defaults to an in-memory backend. Pass a path to
        share approvals with ``agent-guard approve``.
        """

        policy = load_policy(path)
        sink = audit if isinstance(audit, AuditSink) else open_audit(audit, clock=clock)
        if store is None:
            backend: ApprovalBackend = MemoryApprovalBackend()
        elif isinstance(store, (str, Path)):
            backend = JsonFileApprovalBackend(store)
        else:
            backend = store
        return cls(policy, audit=sink, approvals=backend, clock=clock)

    def register(self, name: str, fn: Callable[..., Any], schema: type[BaseModel]) -> None:
        """Bind ``fn`` to ``name``. The schema must set ``extra='forbid'``."""

        if not isinstance(name, str) or _TOOL_NAME.fullmatch(name) is None:
            raise SchemaError(f"invalid tool name {name!r}")
        if name in self._tools:
            raise SchemaError(f"tool {name} is already registered")
        if not isinstance(schema, type) or not issubclass(schema, BaseModel):
            raise SchemaError("schema must be a pydantic BaseModel subclass")
        extra = schema.model_config.get("extra")
        if extra != "forbid":
            raise SchemaError(f"{schema.__name__} must set extra='forbid'")
        missing = sorted(self.policy.referenced_fields(name) - set(schema.model_fields))
        if missing:
            fields = ", ".join(missing)
            raise PolicyError(f"policy for {name} references fields not on the schema: {fields}")
        self._tools[name] = _Tool(name=name, fn=fn, schema=schema)

    def tool(self, schema: type[BaseModel], *, name: str | None = None) -> Callable[[F], F]:
        """Decorator that registers ``fn`` and routes later calls through the guard.

        Direct calls raise :class:`ToolBlocked` unless the guard executes the tool.
        They must run inside :meth:`acting_as`. Prefer :meth:`call` when the agent
        needs the pending/denied result instead of an exception.
        """

        def decorate(fn: F) -> F:
            tool_name = name or fn.__name__
            self.register(tool_name, fn, schema)

            def wrapped(*args: Any, **kwargs: Any) -> Any:
                actor = _current_actor.get()
                if actor is None:
                    raise ConfigurationError(
                        f"Call {tool_name} inside `with guard.acting_as(...)`, or use guard.call"
                    )
                arguments = _bind(tool_name, fn, args, kwargs)
                result = self.call(tool_name, arguments, actor=actor)
                if result.status == "executed":
                    return result.output
                raise ToolBlocked(result)

            wrapped.__name__ = tool_name
            wrapped.__doc__ = fn.__doc__
            return cast(F, wrapped)

        return decorate

    def wrap(
        self,
        fn: Callable[..., Any],
        schema: type[BaseModel],
        *,
        actor: str,
        name: str | None = None,
    ) -> Callable[..., GuardResult]:
        """Return a callable with ``actor`` bound. Keyword arguments are the tool arguments."""

        tool_name = name or fn.__name__
        self.register(tool_name, fn, schema)

        def wrapped(**arguments: Any) -> GuardResult:
            return self.call(tool_name, arguments, actor=actor)

        wrapped.__name__ = tool_name
        wrapped.__doc__ = fn.__doc__
        return wrapped

    @contextmanager
    def acting_as(self, actor_id: str) -> Iterator[None]:
        """Bind the actor id for direct calls of decorated tools."""

        token = _current_actor.set(_require_text(actor_id, "actor"))
        try:
            yield
        finally:
            _current_actor.reset(token)

    def call(self, tool: str, arguments: Mapping[str, Any], *, actor: str) -> GuardResult:
        """Validate, authorise, and maybe run ``tool``. This method does not raise for a denial.

        Approval-required calls return ``pending`` until a different person approves.
        A later ``call`` with the same actor, tool, and arguments runs the tool once
        approval is recorded, and returns the stored result after that without running
        it again. ``failed`` retries the same action.
        """

        actor = _require_text(actor, "actor")
        tool = _require_text(tool, "tool")
        self._sweep()
        if not isinstance(arguments, Mapping):
            return self._invalid(tool, arguments, actor, "Tool arguments must be an object", ())

        materialised: dict[str, Any] = {}
        for key, value in arguments.items():
            if not isinstance(key, str):
                return self._invalid(
                    tool, arguments, actor, "Tool argument names must be strings", ()
                )
            materialised[key] = value

        registered = self._tools.get(tool)
        if registered is None:
            if tool not in self.policy.tools:
                return self._decision_result(
                    tool=tool,
                    arguments=materialised,
                    actor=actor,
                    action_id=str(uuid.uuid4()),
                    status="denied",
                    decision="deny",
                    reason=f"unknown tool {tool}",
                    decided_by="policy",
                    outcome="blocked",
                    output=None,
                    state=None,
                )
            raise ConfigurationError(f"tool {tool} is in the policy but is not registered")

        try:
            validated = registered.schema.model_validate(materialised)
        except ValidationError as exc:
            issues = _issues(exc)
            return self._invalid(tool, materialised, actor, _format_issues(issues), issues)

        payload = _json_payload(validated)
        decision = self.policy.decide(tool, payload)
        if decision.effect == Effect.DENY:
            return self._decision_result(
                tool=tool,
                arguments=payload,
                actor=actor,
                action_id=str(uuid.uuid4()),
                status="denied",
                decision="deny",
                reason=decision.reason,
                decided_by="policy",
                outcome="blocked",
                output=None,
                state=None,
            )
        if decision.effect == Effect.ALLOW:
            return self._execute_allowed(registered, validated, actor, decision)
        proposed = self._gateway.propose(actor, tool, payload)
        return self._after_propose(proposed, decision)

    def approve(self, action_id: str, *, approver: str, reason: str | None = None) -> GuardResult:
        """Record approval. The proposer cannot approve their own action."""

        return self._resolve(action_id, approved=True, approver=approver, reason=reason)

    def reject(self, action_id: str, *, approver: str, reason: str | None = None) -> GuardResult:
        """Record rejection. The proposer may reject their own action to withdraw it."""

        return self._resolve(action_id, approved=False, approver=approver, reason=reason)

    def execute(self, action_id: str) -> GuardResult:
        """Run an approved action, or retry a failed one. A second success does not run again."""

        self._sweep()
        snapshot = self._gateway.get(action_id)
        registered = self._tools.get(snapshot.tool)
        if registered is None:
            raise ConfigurationError(
                f"tool {snapshot.tool} is not registered; cannot execute {action_id}"
            )

        def runner(action: Any) -> Any:
            validated = registered.schema.model_validate(action.payload)
            output = registered.fn(**validated.model_dump(mode="python"))
            return json_safe(output)

        try:
            outcome = self._gateway.execute_if_ready(action_id, runner)
        except InvalidTransitionError as exc:
            self._append(
                action_id=snapshot.action_id,
                actor=snapshot.actor_id,
                tool=snapshot.tool,
                args_hash=snapshot.args_hash,
                decision="invalid_transition",
                decided_by="executor",
                reason=str(exc),
                outcome="error",
            )
            raise
        action = outcome.action
        if action.state == ApprovalState.FAILED:
            reason = action.failure_reason or "execution failed"
            self._append(
                action_id=action.action_id,
                actor=action.actor_id,
                tool=action.tool,
                args_hash=action.args_hash,
                decision="failed",
                decided_by="executor",
                reason=reason,
                outcome="failed",
            )
            return _result(
                status="failed",
                action_id=action.action_id,
                output=None,
                reason=reason,
                decision="failed",
                state=action.state.value,
            )
        if not outcome.invoked:
            self._append(
                action_id=action.action_id,
                actor=action.actor_id,
                tool=action.tool,
                args_hash=action.args_hash,
                decision="replay",
                decided_by="executor",
                reason="idempotent replay",
                outcome="replayed",
            )
            return _result(
                status="executed",
                action_id=action.action_id,
                output=action.result,
                reason="idempotent replay",
                decision="replay",
                state=action.state.value,
            )
        self._append(
            action_id=action.action_id,
            actor=action.actor_id,
            tool=action.tool,
            args_hash=action.args_hash,
            decision="executed",
            decided_by="executor",
            reason="executed",
            outcome="executed",
        )
        return _result(
            status="executed",
            action_id=action.action_id,
            output=action.result,
            reason="executed",
            decision="executed",
            state=action.state.value,
        )

    def pending(self) -> list[PendingAction]:
        """Expire stale approvals, audit those expiries, and return what is still waiting."""

        self._sweep()
        waiting = self._gateway.list_actions(ApprovalState.AWAITING_APPROVAL)
        views: list[PendingAction] = []
        for action in waiting:
            arguments = _copy_payload(action.payload)
            expires = (
                None
                if action.approval_expires_at is None
                else isoformat(action.approval_expires_at)
            )
            views.append(
                PendingAction(
                    action_id=action.action_id,
                    actor=action.actor_id,
                    tool=action.tool,
                    arguments=arguments,
                    state=action.state.value,
                    created_at=isoformat(action.created_at),
                    expires_at=expires,
                    idempotency_key=action.idempotency_key,
                )
            )
        return views

    def _resolve(
        self, action_id: str, *, approved: bool, approver: str, reason: str | None
    ) -> GuardResult:
        approver = _require_text(approver, "approver")
        try:
            action = self._gateway.resolve(
                action_id, approved=approved, resolved_by=approver, reason=reason
            )
        except SelfApprovalError as exc:
            self._audit_known(action_id, approver, "self_approval", str(exc), "blocked")
            raise
        except ActionNotFoundError as exc:
            self._append(
                action_id=action_id,
                actor=approver,
                tool="",
                args_hash=hash_arguments({}),
                decision="missing",
                decided_by=approver,
                reason=str(exc),
                outcome="error",
            )
            raise
        except InvalidTransitionError as exc:
            self._audit_known(action_id, approver, "invalid_transition", str(exc), "error")
            raise
        if action.state == ApprovalState.EXPIRED:
            recorded = action.resolution_reason or "approval window elapsed"
            self._append(
                action_id=action.action_id,
                actor=action.actor_id,
                tool=action.tool,
                args_hash=action.args_hash,
                decision="expired",
                decided_by=approver,
                reason=recorded,
                outcome="expired",
            )
            return _result(
                status="expired",
                action_id=action.action_id,
                output=None,
                reason=recorded,
                decision="expired",
                state=action.state.value,
            )
        decision = "approved" if action.state == ApprovalState.APPROVED else "rejected"
        recorded_reason = action.resolution_reason or decision
        self._append(
            action_id=action.action_id,
            actor=action.actor_id,
            tool=action.tool,
            args_hash=action.args_hash,
            decision=decision,
            decided_by=approver,
            reason=recorded_reason,
            outcome=decision,
        )
        return _result(
            status=decision,
            action_id=action.action_id,
            output=None,
            reason=recorded_reason,
            decision=decision,
            state=action.state.value,
        )

    def _audit_known(
        self, action_id: str, decided_by: str, decision: str, reason: str, outcome: str
    ) -> None:
        try:
            action = self._gateway.get(action_id)
        except ActionNotFoundError:
            self._append(
                action_id=action_id,
                actor=decided_by,
                tool="",
                args_hash=hash_arguments({}),
                decision=decision,
                decided_by=decided_by,
                reason=reason,
                outcome=outcome,
            )
            return
        self._append(
            action_id=action.action_id,
            actor=action.actor_id,
            tool=action.tool,
            args_hash=action.args_hash,
            decision=decision,
            decided_by=decided_by,
            reason=reason,
            outcome=outcome,
        )

    def _after_propose(self, proposed: ProposeResult, decision: PolicyDecision) -> GuardResult:
        action = proposed.action
        if action.state == ApprovalState.AWAITING_APPROVAL:
            reason = decision.reason if proposed.created else "idempotent replay"
            self._append(
                action_id=action.action_id,
                actor=action.actor_id,
                tool=action.tool,
                args_hash=action.args_hash,
                decision="require_approval",
                decided_by="policy",
                reason=reason,
                outcome="pending",
            )
            return _result(
                status="pending",
                action_id=action.action_id,
                output=None,
                reason=reason,
                decision="require_approval",
                state=action.state.value,
            )
        if action.state == ApprovalState.EXECUTED:
            self._append(
                action_id=action.action_id,
                actor=action.actor_id,
                tool=action.tool,
                args_hash=action.args_hash,
                decision="replay",
                decided_by="executor",
                reason="idempotent replay",
                outcome="replayed",
            )
            return _result(
                status="executed",
                action_id=action.action_id,
                output=action.result,
                reason="idempotent replay",
                decision="replay",
                state=action.state.value,
            )
        if action.state in {ApprovalState.APPROVED, ApprovalState.FAILED}:
            return self.execute(action.action_id)
        raise ConfigurationError(f"unexpected state {action.state.value} for {action.action_id}")

    def _execute_allowed(
        self,
        registered: _Tool,
        validated: BaseModel,
        actor: str,
        decision: PolicyDecision,
    ) -> GuardResult:
        action_id = str(uuid.uuid4())
        payload = _json_payload(validated)
        try:
            output = json_safe(registered.fn(**validated.model_dump(mode="python")))
        except Exception as exc:
            reason = f"{type(exc).__name__}: {exc}"
            self._append(
                action_id=action_id,
                actor=actor,
                tool=registered.name,
                args_hash=hash_arguments(payload),
                decision="allow",
                decided_by="policy",
                reason=reason,
                outcome="failed",
            )
            return _result(
                status="failed",
                action_id=action_id,
                output=None,
                reason=reason,
                decision="allow",
                state=None,
            )
        self._append(
            action_id=action_id,
            actor=actor,
            tool=registered.name,
            args_hash=hash_arguments(payload),
            decision="allow",
            decided_by="policy",
            reason=decision.reason,
            outcome="executed",
        )
        return _result(
            status="executed",
            action_id=action_id,
            output=output,
            reason=decision.reason,
            decision="allow",
            state=None,
        )

    def _invalid(
        self,
        tool: str,
        arguments: Any,
        actor: str,
        reason: str,
        issues: tuple[ValidationIssue, ...],
    ) -> GuardResult:
        return self._decision_result(
            tool=tool,
            arguments=arguments,
            actor=actor,
            action_id=str(uuid.uuid4()),
            status="invalid",
            decision="invalid",
            reason=reason,
            decided_by="schema",
            outcome="blocked",
            output=None,
            state=None,
            issues=issues,
        )

    def _decision_result(
        self,
        *,
        tool: str,
        arguments: Any,
        actor: str,
        action_id: str,
        status: str,
        decision: str,
        reason: str,
        decided_by: str,
        outcome: str,
        output: Any,
        state: str | None,
        issues: tuple[ValidationIssue, ...] = (),
    ) -> GuardResult:
        self._append(
            action_id=action_id,
            actor=actor,
            tool=tool,
            args_hash=hash_arguments(arguments),
            decision=decision,
            decided_by=decided_by,
            reason=reason,
            outcome=outcome,
        )
        return _result(
            status=status,
            action_id=action_id,
            output=output,
            reason=reason,
            decision=decision,
            state=state,
            issues=issues,
        )

    def _sweep(self) -> None:
        for action in self._gateway.expire_stale():
            self._append(
                action_id=action.action_id,
                actor=action.actor_id,
                tool=action.tool,
                args_hash=action.args_hash,
                decision="expired",
                decided_by="ttl",
                reason="approval window elapsed",
                outcome="expired",
            )

    def _append(
        self,
        *,
        action_id: str,
        actor: str,
        tool: str,
        args_hash: str,
        decision: str,
        decided_by: str,
        reason: str,
        outcome: str,
    ) -> None:
        self._audit.append(
            AuditEvent(
                action_id=action_id,
                actor=actor,
                tool=tool,
                args_hash=args_hash,
                decision=decision,
                decided_by=decided_by,
                reason=reason,
                outcome=outcome,
            )
        )
        logger.info(
            "tool=%s decision=%s outcome=%s action=%s actor=%s",
            tool,
            decision,
            outcome,
            action_id,
            actor,
        )


def _result(
    *,
    status: str,
    action_id: str | None,
    output: Any,
    reason: str,
    decision: str,
    state: str | None,
    issues: tuple[ValidationIssue, ...] = (),
) -> GuardResult:
    return GuardResult(
        status=status,
        action_id=action_id,
        output=output,
        reason=reason,
        decision=decision,
        state=state,
        issues=issues,
    )


def _bind(
    tool_name: str, fn: Callable[..., Any], args: tuple[Any, ...], kwargs: dict[str, Any]
) -> dict[str, Any]:
    try:
        bound = inspect.signature(fn).bind(*args, **kwargs)
    except TypeError as exc:
        raise ConfigurationError(f"could not bind arguments for {tool_name}: {exc}") from exc
    bound.apply_defaults()
    return dict(bound.arguments)


def _issues(exc: ValidationError) -> tuple[ValidationIssue, ...]:
    found: list[ValidationIssue] = []
    for error in exc.errors():
        loc = ".".join(str(part) for part in error["loc"])
        found.append(ValidationIssue(loc=loc, message=str(error["msg"])))
    return tuple(found)


def _format_issues(issues: tuple[ValidationIssue, ...]) -> str:
    if not issues:
        return "invalid arguments"
    parts = [f"{issue.loc or '<root>'}: {issue.message}" for issue in issues]
    return "; ".join(parts)


def _json_payload(model: BaseModel) -> dict[str, Any]:
    loaded: Any = json.loads(model.model_dump_json())
    if not isinstance(loaded, dict):
        raise ConfigurationError("tool arguments did not serialise to an object")
    payload: dict[str, Any] = {}
    for key, value in loaded.items():
        if not isinstance(key, str):
            raise ConfigurationError("tool arguments did not serialise to string keys")
        payload[key] = value
    return payload


def _copy_payload(payload: dict[str, Any]) -> dict[str, Any]:
    loaded: Any = json.loads(canonical_json(payload))
    if not isinstance(loaded, dict):
        return {}
    copied: dict[str, Any] = {}
    for key, value in loaded.items():
        if isinstance(key, str):
            copied[key] = value
    return copied
