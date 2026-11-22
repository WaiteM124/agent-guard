"""Approval state machine with a pluggable store.

Adapted from the governed-agent-toolkit gate: the same legal transitions, the same
idempotency key (actor + tool + canonical arguments), and the same rule that an
expired or rejected proposal releases that key. This version adds ``failed``, which
keeps the key so a retry is the same action rather than a second side effect.
"""

from __future__ import annotations

import threading
import uuid
from collections.abc import Callable, Iterator, Mapping
from contextlib import AbstractContextManager, contextmanager, suppress
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Any

from agent_guard.canonical import canonical_json, sha256_text
from agent_guard.errors import (
    ActionNotFoundError,
    ApprovalError,
    ConfigurationError,
    InvalidTransitionError,
    PayloadError,
    SelfApprovalError,
)

Clock = Callable[[], datetime]

_KEY_HOLDING = frozenset(
    {
        "proposed",
        "awaiting_approval",
        "approved",
        "executed",
        "failed",
    }
)


class ApprovalState(str, Enum):
    """Lifecycle of one proposed tool call. Terminal states do not leave, except ``failed``."""

    PROPOSED = "proposed"
    AWAITING_APPROVAL = "awaiting_approval"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"
    EXECUTED = "executed"
    FAILED = "failed"


_ALLOWED: dict[ApprovalState, set[ApprovalState]] = {
    ApprovalState.PROPOSED: {ApprovalState.AWAITING_APPROVAL},
    ApprovalState.AWAITING_APPROVAL: {
        ApprovalState.APPROVED,
        ApprovalState.REJECTED,
        ApprovalState.EXPIRED,
    },
    ApprovalState.APPROVED: {ApprovalState.EXECUTED, ApprovalState.FAILED},
    ApprovalState.FAILED: {ApprovalState.EXECUTED, ApprovalState.FAILED},
    ApprovalState.REJECTED: set(),
    ApprovalState.EXPIRED: set(),
    ApprovalState.EXECUTED: set(),
}


def _require_text(value: str, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field_name} is required")
    return value.strip()


def _aware(moment: datetime, *, field_name: str) -> datetime:
    if moment.tzinfo is None:
        raise ApprovalError(f"{field_name} must be timezone-aware")
    return moment.astimezone(timezone.utc)


def isoformat(moment: datetime) -> str:
    """UTC ISO-8601 with an explicit offset."""

    return _aware(moment, field_name="timestamp").isoformat(timespec="microseconds")


def parse_iso(value: str) -> datetime:
    """Parse an ISO-8601 timestamp. Naive values are rejected."""

    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ApprovalError(f"invalid timestamp {value!r}") from exc
    return _aware(parsed, field_name="timestamp")


def compute_idempotency_key(actor_id: str, tool: str, payload: Mapping[str, Any]) -> str:
    """Key for one logical write: who is asking, which tool, and the exact arguments.

    The payload is canonicalised first, so ``{"b": 1, "a": 2}`` and ``{"a": 2, "b": 1}``
    are the same action. A replay or a double-clicked approval hits this key and does
    not start a second one.
    """

    if not isinstance(payload, Mapping):
        raise PayloadError("Payload must be a JSON object")
    encoded = canonical_json(dict(payload))
    raw = f"{actor_id}:{tool}:{encoded}"
    return sha256_text(raw)


def hash_arguments(payload: Any) -> str:
    """SHA-256 of the canonical arguments. Non-JSON values are hashed from ``repr``."""

    try:
        encoded = canonical_json(payload)
    except PayloadError:
        encoded = repr(payload)
    return sha256_text(encoded)


@dataclass(frozen=True)
class TransitionRecord:
    """One row of the append-only history on an action."""

    from_state: ApprovalState | None
    to_state: ApprovalState
    at: datetime
    actor: str | None
    reason: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "actor": self.actor,
            "at": isoformat(self.at),
            "from_state": None if self.from_state is None else self.from_state.value,
            "reason": self.reason,
            "to_state": self.to_state.value,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> TransitionRecord:
        data = _need_mapping(raw, "history entry")
        from_raw = data.get("from_state")
        from_state = None if from_raw is None else _need_state(from_raw)
        return cls(
            from_state=from_state,
            to_state=_need_state(data.get("to_state")),
            at=parse_iso(_need_str(data, "at")),
            actor=_opt_str(data, "actor"),
            reason=_opt_str(data, "reason"),
        )


@dataclass
class ProposedAction:
    """One governed write. Mutate it only through :class:`ApprovalGateway`, which saves it."""

    action_id: str
    actor_id: str
    tool: str
    payload: dict[str, Any]
    args_hash: str
    idempotency_key: str
    state: ApprovalState = ApprovalState.PROPOSED
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    approval_expires_at: datetime | None = None
    resolved_at: datetime | None = None
    resolved_by: str | None = None
    resolution_reason: str | None = None
    executed_at: datetime | None = None
    failure_reason: str | None = None
    result: Any = None
    history: list[TransitionRecord] = field(default_factory=list)

    def transition(
        self,
        new_state: ApprovalState,
        *,
        now: datetime,
        actor: str | None = None,
        reason: str | None = None,
    ) -> None:
        """Move to ``new_state`` or raise :class:`InvalidTransitionError`."""

        allowed = _ALLOWED[self.state]
        if new_state not in allowed:
            allowed_text = ", ".join(sorted(state.value for state in allowed)) or "none"
            raise InvalidTransitionError(
                f"Cannot move action {self.action_id} from {self.state.value} "
                f"to {new_state.value}; allowed: {allowed_text}"
            )
        previous = self.state
        self.state = new_state
        if new_state in {ApprovalState.APPROVED, ApprovalState.REJECTED, ApprovalState.EXPIRED}:
            self.resolved_at = now
            self.resolved_by = actor
            self.resolution_reason = reason
        if new_state is ApprovalState.EXECUTED:
            self.executed_at = now
        if new_state is ApprovalState.FAILED:
            self.failure_reason = reason
        self.history.append(
            TransitionRecord(
                from_state=previous,
                to_state=new_state,
                at=now,
                actor=actor,
                reason=reason,
            )
        )

    def is_expired(self, now: datetime) -> bool:
        """True at and after ``approval_expires_at``. An action with no deadline is open."""

        if self.approval_expires_at is None:
            return False
        return now >= self.approval_expires_at

    def holds_key(self) -> bool:
        """True while this action still owns its idempotency key."""

        return self.state.value in _KEY_HOLDING

    def to_dict(self) -> dict[str, Any]:
        return {
            "action_id": self.action_id,
            "actor_id": self.actor_id,
            "approval_expires_at": _iso_or_none(self.approval_expires_at),
            "args_hash": self.args_hash,
            "created_at": isoformat(self.created_at),
            "executed_at": _iso_or_none(self.executed_at),
            "failure_reason": self.failure_reason,
            "history": [item.to_dict() for item in self.history],
            "idempotency_key": self.idempotency_key,
            "payload": self.payload,
            "resolution_reason": self.resolution_reason,
            "resolved_at": _iso_or_none(self.resolved_at),
            "resolved_by": self.resolved_by,
            "result": self.result,
            "state": self.state.value,
            "tool": self.tool,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> ProposedAction:
        data = _need_mapping(raw, "action")
        history_raw = data.get("history", [])
        if not isinstance(history_raw, list):
            raise ApprovalError("action history must be a list")
        action = cls(
            action_id=_need_str(data, "action_id"),
            actor_id=_need_str(data, "actor_id"),
            tool=_need_str(data, "tool"),
            payload=_need_dict(data, "payload"),
            args_hash=_need_str(data, "args_hash"),
            idempotency_key=_need_str(data, "idempotency_key"),
            state=_need_state(data.get("state")),
            created_at=parse_iso(_need_str(data, "created_at")),
            approval_expires_at=_opt_iso(data, "approval_expires_at"),
            resolved_at=_opt_iso(data, "resolved_at"),
            resolved_by=_opt_str(data, "resolved_by"),
            resolution_reason=_opt_str(data, "resolution_reason"),
            executed_at=_opt_iso(data, "executed_at"),
            failure_reason=_opt_str(data, "failure_reason"),
            result=data.get("result"),
            history=[TransitionRecord.from_dict(item) for item in history_raw],
        )
        return action


@dataclass(frozen=True)
class ProposeResult:
    """An action from :meth:`ApprovalGateway.propose`, and whether this call created it."""

    action: ProposedAction
    created: bool


class ApprovalBackend:
    """Persistence for proposed actions. Implementations must be safe inside :meth:`transaction`."""

    def transaction(self) -> AbstractContextManager[None]:
        """Exclusive read-modify-write scope. Nested calls join the outer scope."""

        raise NotImplementedError

    def get(self, action_id: str) -> ProposedAction | None:
        raise NotImplementedError

    def find_by_idempotency_key(self, key: str) -> ProposedAction | None:
        raise NotImplementedError

    def save(self, action: ProposedAction) -> None:
        raise NotImplementedError

    def all(self) -> list[ProposedAction]:
        raise NotImplementedError


class MemoryApprovalBackend(ApprovalBackend):
    """Process-local store. Tests and single-process hosts use this."""

    def __init__(self) -> None:
        self._by_id: dict[str, ProposedAction] = {}
        self._by_key: dict[str, str] = {}
        self._lock = threading.RLock()
        self._depth = 0

    def transaction(self) -> AbstractContextManager[None]:
        return self._scope()

    @contextmanager
    def _scope(self) -> Iterator[None]:
        with self._lock:
            self._depth += 1
            try:
                yield
            finally:
                self._depth -= 1

    def get(self, action_id: str) -> ProposedAction | None:
        self._require_open()
        return self._by_id.get(action_id)

    def find_by_idempotency_key(self, key: str) -> ProposedAction | None:
        self._require_open()
        action_id = self._by_key.get(key)
        if action_id is None:
            return None
        return self._by_id.get(action_id)

    def save(self, action: ProposedAction) -> None:
        self._require_open()
        self._by_id[action.action_id] = action
        current = self._by_key.get(action.idempotency_key)
        if action.holds_key():
            self._by_key[action.idempotency_key] = action.action_id
        elif current == action.action_id:
            del self._by_key[action.idempotency_key]

    def all(self) -> list[ProposedAction]:
        self._require_open()
        return list(self._by_id.values())

    def _require_open(self) -> None:
        if self._depth <= 0:
            raise ConfigurationError("Approval backend method called outside transaction()")


@dataclass
class _Cache:
    by_id: dict[str, ProposedAction]
    by_key: dict[str, str]


class JsonFileApprovalBackend(ApprovalBackend):
    """JSON file store shared by a process and ``agent-guard approve``.

    Writes are atomic (temp file, then replace). A lock file stops two processes
    rewriting the store at once. A lock older than 30 seconds is treated as abandoned.
    """

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock_path = self.path.with_name(self.path.name + ".lock")
        self._thread_lock = threading.RLock()
        self._cache: _Cache | None = None

    def transaction(self) -> AbstractContextManager[None]:
        return self._scope()

    @contextmanager
    def _scope(self) -> Iterator[None]:
        with self._thread_lock:
            outermost = self._cache is None
            if outermost:
                self._acquire()
                self._cache = self._read()
            try:
                yield
                if outermost and self._cache is not None:
                    self._write(self._cache)
            finally:
                if outermost:
                    self._cache = None
                    self._release()

    def get(self, action_id: str) -> ProposedAction | None:
        return self._cache_or_raise().by_id.get(action_id)

    def find_by_idempotency_key(self, key: str) -> ProposedAction | None:
        cache = self._cache_or_raise()
        action_id = cache.by_key.get(key)
        if action_id is None:
            return None
        return cache.by_id.get(action_id)

    def save(self, action: ProposedAction) -> None:
        cache = self._cache_or_raise()
        cache.by_id[action.action_id] = action
        current = cache.by_key.get(action.idempotency_key)
        if action.holds_key():
            cache.by_key[action.idempotency_key] = action.action_id
        elif current == action.action_id:
            del cache.by_key[action.idempotency_key]

    def all(self) -> list[ProposedAction]:
        return list(self._cache_or_raise().by_id.values())

    def _cache_or_raise(self) -> _Cache:
        if self._cache is None:
            raise ConfigurationError("Approval backend method called outside transaction()")
        return self._cache

    def _acquire(self) -> None:
        import os
        import time

        deadline = time.monotonic() + 5
        while True:
            try:
                fd = os.open(self._lock_path, os.O_CREAT | os.O_EXCL | os.O_RDWR)
                os.close(fd)
                return
            except FileExistsError:
                try:
                    age = time.time() - self._lock_path.stat().st_mtime
                except FileNotFoundError:
                    continue
                if age > 30:
                    with suppress(FileNotFoundError):
                        self._lock_path.unlink()
                    continue
                if time.monotonic() > deadline:
                    raise ApprovalError(f"timed out waiting for {self._lock_path}") from None
                time.sleep(0.02)

    def _release(self) -> None:
        with suppress(FileNotFoundError):
            self._lock_path.unlink()

    def _read(self) -> _Cache:
        import json

        if not self.path.exists():
            return _Cache({}, {})
        try:
            loaded: Any = json.loads(self.path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise ApprovalError(f"corrupt approval store {self.path}") from exc
        if not isinstance(loaded, dict) or loaded.get("version") != 1:
            raise ApprovalError(f"unrecognised approval store {self.path}")
        raw_actions = loaded.get("actions")
        if not isinstance(raw_actions, list):
            raise ApprovalError(f"unrecognised approval store {self.path}")
        by_id: dict[str, ProposedAction] = {}
        by_key: dict[str, str] = {}
        for item in raw_actions:
            action = ProposedAction.from_dict(item)
            if action.action_id in by_id:
                raise ApprovalError("duplicate action id in approval store")
            by_id[action.action_id] = action
            if action.holds_key():
                if action.idempotency_key in by_key:
                    raise ApprovalError("duplicate live idempotency key in approval store")
                by_key[action.idempotency_key] = action.action_id
        return _Cache(by_id, by_key)

    def _write(self, cache: _Cache) -> None:
        import json
        import os

        payload = {
            "actions": [action.to_dict() for action in cache.by_id.values()],
            "version": 1,
        }
        text = json.dumps(payload, indent=2, sort_keys=True) + "\n"
        temporary = self.path.with_suffix(self.path.suffix + ".tmp")
        temporary.write_text(text, encoding="utf-8")
        os.replace(temporary, self.path)


@dataclass(frozen=True)
class ExecutionOutcome:
    """Result of trying to run an approved action."""

    action: ProposedAction
    invoked: bool


class ApprovalGateway:
    """Legal transitions over an :class:`ApprovalBackend`.

    The approval window bounds how long a person has to answer. It does not bound
    execution: once someone has approved, a slow executor must not expire that
    decision out from under them. Execution holds the backend transaction so two
    callers cannot both run the same action.
    """

    def __init__(
        self,
        backend: ApprovalBackend | None = None,
        *,
        approval_ttl: timedelta = timedelta(minutes=30),
        clock: Clock | None = None,
    ) -> None:
        if approval_ttl <= timedelta(0):
            raise ValueError("approval_ttl must be positive")
        self.backend = backend if backend is not None else MemoryApprovalBackend()
        self._approval_ttl = approval_ttl
        self._clock = clock or (lambda: datetime.now(timezone.utc))

    def get(self, action_id: str) -> ProposedAction:
        with self.backend.transaction():
            return self._require(action_id)

    def list_actions(self, state: ApprovalState | None = None) -> list[ProposedAction]:
        with self.backend.transaction():
            actions = self.backend.all()
        if state is None:
            return actions
        return [action for action in actions if action.state == state]

    def propose(
        self,
        actor_id: str,
        tool: str,
        payload: dict[str, Any],
    ) -> ProposeResult:
        """Return the live action for this key, or create one and submit it for approval."""

        actor_id = _require_text(actor_id, "actor_id")
        tool = _require_text(tool, "tool")
        frozen = _freeze_payload(payload)
        key = compute_idempotency_key(actor_id, tool, frozen)
        args_hash = hash_arguments(frozen)

        with self.backend.transaction():
            now = self._now()
            existing = self.backend.find_by_idempotency_key(key)
            waiting = existing is not None and existing.state == ApprovalState.AWAITING_APPROVAL
            if waiting and existing is not None and existing.is_expired(now):
                existing.transition(
                    ApprovalState.EXPIRED,
                    now=now,
                    reason="approval window elapsed",
                )
                self.backend.save(existing)
                existing = None
            if existing is not None and existing.holds_key():
                if existing.state == ApprovalState.PROPOSED:
                    existing.transition(
                        ApprovalState.AWAITING_APPROVAL,
                        now=now,
                        reason="submitted for approval",
                    )
                    existing.approval_expires_at = now + self._approval_ttl
                    self.backend.save(existing)
                return ProposeResult(existing, False)

            action = ProposedAction(
                action_id=str(uuid.uuid4()),
                actor_id=actor_id,
                tool=tool,
                payload=frozen,
                args_hash=args_hash,
                idempotency_key=key,
                created_at=now,
            )
            action.history.append(
                TransitionRecord(
                    from_state=None,
                    to_state=ApprovalState.PROPOSED,
                    at=now,
                    actor=actor_id,
                    reason="proposed",
                )
            )
            action.transition(
                ApprovalState.AWAITING_APPROVAL,
                now=now,
                reason="submitted for approval",
            )
            action.approval_expires_at = now + self._approval_ttl
            self.backend.save(action)
            return ProposeResult(action, True)

    def resolve(
        self,
        action_id: str,
        *,
        approved: bool,
        resolved_by: str,
        reason: str | None = None,
    ) -> ProposedAction:
        """Record a human decision.

        The proposer may reject their own request (withdraw) but may not approve it.
        A decision that arrives at or after the deadline expires the action instead.
        """

        resolved_by = _require_text(resolved_by, "resolved_by")
        if reason is None:
            reason = "approved" if approved else "rejected"
        else:
            reason = _require_text(reason, "reason")

        with self.backend.transaction():
            now = self._now()
            action = self._require(action_id)
            if action.state == ApprovalState.EXPIRED:
                return action
            if action.state == ApprovalState.AWAITING_APPROVAL and action.is_expired(now):
                action.transition(
                    ApprovalState.EXPIRED,
                    now=now,
                    reason="approval window elapsed",
                )
                self.backend.save(action)
                return action
            if (
                approved
                and resolved_by == action.actor_id
                and action.state == ApprovalState.AWAITING_APPROVAL
            ):
                raise SelfApprovalError(action.action_id, action.actor_id)
            action.transition(
                ApprovalState.APPROVED if approved else ApprovalState.REJECTED,
                now=now,
                actor=resolved_by,
                reason=reason,
            )
            self.backend.save(action)
            return action

    def expire_stale(self) -> list[ProposedAction]:
        """Move unanswered approvals whose window has elapsed to ``expired``."""

        with self.backend.transaction():
            now = self._now()
            expired: list[ProposedAction] = []
            for action in self.backend.all():
                if action.state == ApprovalState.AWAITING_APPROVAL and action.is_expired(now):
                    action.transition(
                        ApprovalState.EXPIRED,
                        now=now,
                        reason="approval window elapsed",
                    )
                    self.backend.save(action)
                    expired.append(action)
            return expired

    def execute_if_ready(
        self,
        action_id: str,
        runner: Callable[[ProposedAction], Any],
    ) -> ExecutionOutcome:
        """Run ``runner`` for an approved or failed action.

        An already-executed action is returned with ``invoked=False``. If ``runner``
        raises, the action stays retryable in ``failed`` and the error is stored.
        The backend transaction is held across ``runner`` so the side effect cannot
        be entered twice.
        """

        with self.backend.transaction():
            now = self._now()
            action = self._require(action_id)
            if action.state == ApprovalState.EXECUTED:
                return ExecutionOutcome(action, False)
            if action.state not in {ApprovalState.APPROVED, ApprovalState.FAILED}:
                raise InvalidTransitionError(
                    f"Cannot execute action {action_id} from {action.state.value}; "
                    "only an approved or failed action can be executed"
                )
            try:
                result = runner(action)
            except Exception as exc:
                message = f"{type(exc).__name__}: {exc}"
                action.transition(ApprovalState.FAILED, now=now, reason=message)
                self.backend.save(action)
                return ExecutionOutcome(action, True)
            action.transition(ApprovalState.EXECUTED, now=now, reason="executed")
            action.result = result
            self.backend.save(action)
            return ExecutionOutcome(action, True)

    def _require(self, action_id: str) -> ProposedAction:
        action = self.backend.get(action_id)
        if action is None:
            raise ActionNotFoundError(action_id)
        return action

    def _now(self) -> datetime:
        current = self._clock()
        if not isinstance(current, datetime):
            raise ValueError("Clock must return a datetime")
        if current.tzinfo is None:
            raise ValueError("Clock must return timezone-aware datetimes")
        return current.astimezone(timezone.utc)


def _freeze_payload(payload: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise PayloadError("Payload must be a JSON object")
    encoded = canonical_json(payload)
    import json

    loaded: Any = json.loads(encoded)
    if not isinstance(loaded, dict):
        raise PayloadError("Payload must be a JSON object")
    frozen: dict[str, Any] = {}
    for key, value in loaded.items():
        if not isinstance(key, str):
            raise PayloadError("Payload keys must be strings")
        frozen[key] = value
    return frozen


def _iso_or_none(moment: datetime | None) -> str | None:
    if moment is None:
        return None
    return isoformat(moment)


def _need_mapping(raw: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(raw, dict):
        raise ApprovalError(f"{label} must be an object")
    mapping: dict[str, Any] = {}
    for key, value in raw.items():
        if not isinstance(key, str):
            raise ApprovalError(f"{label} keys must be strings")
        mapping[key] = value
    return mapping


def _need_str(data: Mapping[str, Any], key: str) -> str:
    value = data.get(key)
    if not isinstance(value, str) or not value:
        raise ApprovalError(f"approval record field {key} must be a non-empty string")
    return value


def _opt_str(data: Mapping[str, Any], key: str) -> str | None:
    if key not in data or data[key] is None:
        return None
    value = data[key]
    if not isinstance(value, str):
        raise ApprovalError(f"approval record field {key} must be a string")
    return value


def _opt_iso(data: Mapping[str, Any], key: str) -> datetime | None:
    text = _opt_str(data, key)
    if text is None:
        return None
    return parse_iso(text)


def _need_dict(data: Mapping[str, Any], key: str) -> dict[str, Any]:
    value = data.get(key)
    mapping = _need_mapping(value, key)
    return dict(mapping)


def _need_state(value: Any) -> ApprovalState:
    if not isinstance(value, str):
        raise ApprovalError("state must be a string")
    try:
        return ApprovalState(value)
    except ValueError as exc:
        raise ApprovalError(f"unknown approval state {value!r}") from exc
