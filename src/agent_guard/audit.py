"""Append-only audit log with a hash chain.

Each record stores the hash of the previous record. Editing a line, or deleting a
line in the middle, breaks the chain. Deleting the tail leaves a shorter chain that
still verifies; pin :meth:`AuditSink.head` out of band and pass it to ``verify``
if that matters. Replacing the whole file with a fresh chain also verifies unless
the head is pinned. v0.1 does not sign the log.
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
from collections.abc import Callable, Iterator
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from agent_guard.canonical import canonical_json, sha256_text
from agent_guard.errors import AuditError, PayloadError

GENESIS_HASH = "0" * 64
Clock = Callable[[], datetime]

_BODY_FIELDS = (
    "action_id",
    "actor",
    "args_hash",
    "decision",
    "decided_by",
    "outcome",
    "prev_hash",
    "reason",
    "timestamp",
    "tool",
)


@dataclass(frozen=True)
class AuditEvent:
    """One decision, before the sink assigns its place in the chain."""

    action_id: str
    actor: str
    tool: str
    args_hash: str
    decision: str
    decided_by: str
    reason: str
    outcome: str


@dataclass(frozen=True)
class AuditRecord:
    """One sealed line of the log."""

    timestamp: str
    action_id: str
    actor: str
    tool: str
    args_hash: str
    decision: str
    decided_by: str
    reason: str
    outcome: str
    prev_hash: str
    record_hash: str

    def body(self) -> dict[str, str]:
        return {
            "action_id": self.action_id,
            "actor": self.actor,
            "args_hash": self.args_hash,
            "decision": self.decision,
            "decided_by": self.decided_by,
            "outcome": self.outcome,
            "prev_hash": self.prev_hash,
            "reason": self.reason,
            "timestamp": self.timestamp,
            "tool": self.tool,
        }

    def to_dict(self) -> dict[str, str]:
        data = self.body()
        data["record_hash"] = self.record_hash
        return data

    @classmethod
    def from_dict(cls, raw: Any, *, index: int | None = None) -> AuditRecord:
        if not isinstance(raw, dict):
            raise AuditError("audit record must be an object", index=index)
        values: dict[str, str] = {}
        for key in (*_BODY_FIELDS, "record_hash"):
            value = raw.get(key)
            if not isinstance(value, str):
                raise AuditError(f"audit record field {key} must be a string", index=index)
            values[key] = value
        return cls(
            timestamp=values["timestamp"],
            action_id=values["action_id"],
            actor=values["actor"],
            tool=values["tool"],
            args_hash=values["args_hash"],
            decision=values["decision"],
            decided_by=values["decided_by"],
            reason=values["reason"],
            outcome=values["outcome"],
            prev_hash=values["prev_hash"],
            record_hash=values["record_hash"],
        )


@dataclass(frozen=True)
class VerifyResult:
    """Outcome of walking the hash chain."""

    ok: bool
    count: int
    head: str
    index: int | None
    reason: str


def hash_record_body(body: dict[str, str]) -> str:
    """SHA-256 of the canonical record body. ``record_hash`` itself is not an input."""

    return sha256_text(canonical_json(body))


def seal(event: AuditEvent, *, prev_hash: str, timestamp: str) -> AuditRecord:
    """Attach ``prev_hash`` and the content hash. Pure: the sink decides ordering."""

    record = AuditRecord(
        timestamp=timestamp,
        action_id=event.action_id,
        actor=event.actor,
        tool=event.tool,
        args_hash=event.args_hash,
        decision=event.decision,
        decided_by=event.decided_by,
        reason=event.reason,
        outcome=event.outcome,
        prev_hash=prev_hash,
        record_hash="",
    )
    digest = hash_record_body(record.body())
    return AuditRecord(
        timestamp=record.timestamp,
        action_id=record.action_id,
        actor=record.actor,
        tool=record.tool,
        args_hash=record.args_hash,
        decision=record.decision,
        decided_by=record.decided_by,
        reason=record.reason,
        outcome=record.outcome,
        prev_hash=record.prev_hash,
        record_hash=digest,
    )


class AuditSink:
    """Append-only destination for audit records. Both shipped sinks share :meth:`verify`."""

    def append(self, event: AuditEvent) -> AuditRecord:
        raise NotImplementedError

    def records(self) -> list[AuditRecord]:
        raise NotImplementedError

    def head(self) -> str:
        """Hash of the last record, or the genesis hash when the log is empty."""

        rows = self.records()
        if not rows:
            return GENESIS_HASH
        return rows[-1].record_hash

    def verify(self) -> VerifyResult:
        """Recompute the chain. A broken link or a rewritten line returns ``ok=False``."""

        try:
            rows = self.records()
        except AuditError as exc:
            return VerifyResult(ok=False, count=0, head="", index=exc.index, reason=str(exc))
        except PayloadError as exc:
            return VerifyResult(ok=False, count=0, head="", index=None, reason=str(exc))

        previous = GENESIS_HASH
        for index, record in enumerate(rows):
            if record.prev_hash != previous:
                return VerifyResult(
                    ok=False,
                    count=len(rows),
                    head=record.record_hash,
                    index=index,
                    reason="previous hash does not match",
                )
            try:
                expected = hash_record_body(record.body())
            except PayloadError as exc:
                return VerifyResult(
                    ok=False,
                    count=len(rows),
                    head=record.record_hash,
                    index=index,
                    reason=str(exc),
                )
            if expected != record.record_hash:
                return VerifyResult(
                    ok=False,
                    count=len(rows),
                    head=record.record_hash,
                    index=index,
                    reason="record hash does not match contents",
                )
            previous = record.record_hash
        return VerifyResult(ok=True, count=len(rows), head=previous, index=None, reason="ok")


def _timestamp(clock: Clock) -> str:
    current = clock()
    if not isinstance(current, datetime):
        raise ValueError("Clock must return a datetime")
    if current.tzinfo is None:
        raise ValueError("Clock must return timezone-aware datetimes")
    return current.astimezone(timezone.utc).isoformat(timespec="microseconds")


class JsonlAuditSink(AuditSink):
    """One JSON object per line. The file is created at startup so a missing file is visible."""

    def __init__(self, path: str | Path, *, clock: Clock | None = None) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if not self.path.exists():
            self.path.write_text("", encoding="utf-8")
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._lock = threading.RLock()
        self._lock_path = self.path.with_name(self.path.name + ".lock")

    def append(self, event: AuditEvent) -> AuditRecord:
        with self._file_lock():
            previous = self._last_hash()
            record = seal(event, prev_hash=previous, timestamp=_timestamp(self._clock))
            line = json.dumps(record.to_dict(), sort_keys=True, separators=(",", ":"))
            with self.path.open("a", encoding="utf-8", newline="\n") as handle:
                handle.write(line + "\n")
                handle.flush()
                os.fsync(handle.fileno())
            return record

    def records(self) -> list[AuditRecord]:
        if not self.path.exists():
            raise AuditError(f"audit log does not exist: {self.path}")
        rows: list[AuditRecord] = []
        text = self.path.read_text(encoding="utf-8")
        for index, line in enumerate(text.splitlines()):
            if not line.strip():
                continue
            try:
                loaded: Any = json.loads(line)
            except json.JSONDecodeError as exc:
                raise AuditError(f"corrupt audit line {index}: {exc}", index=index) from exc
            rows.append(AuditRecord.from_dict(loaded, index=index))
        return rows

    def _last_hash(self) -> str:
        rows = self.records()
        if not rows:
            return GENESIS_HASH
        return rows[-1].record_hash

    @contextmanager
    def _file_lock(self) -> Iterator[None]:
        import os
        import time

        with self._lock:
            deadline = time.monotonic() + 5
            held = False
            while not held:
                try:
                    fd = os.open(self._lock_path, os.O_CREAT | os.O_EXCL | os.O_RDWR)
                    os.close(fd)
                    held = True
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
                        raise AuditError(f"timed out waiting for {self._lock_path}") from None
                    time.sleep(0.02)
            try:
                yield
            finally:
                with suppress(FileNotFoundError):
                    self._lock_path.unlink()


class SqliteAuditSink(AuditSink):
    """SQLite sink with the same records and the same chain as the JSONL sink."""

    def __init__(self, path: str | Path, *, clock: Clock | None = None) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._lock = threading.RLock()
        connection = self._connect()
        try:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS audit (
                    seq INTEGER PRIMARY KEY AUTOINCREMENT,
                    record_hash TEXT NOT NULL UNIQUE,
                    prev_hash TEXT NOT NULL,
                    payload TEXT NOT NULL
                )
                """
            )
            connection.commit()
        finally:
            connection.close()

    def append(self, event: AuditEvent) -> AuditRecord:
        with self._lock:
            connection = self._connect()
            try:
                connection.execute("BEGIN IMMEDIATE")
                row = connection.execute(
                    "SELECT record_hash FROM audit ORDER BY seq DESC LIMIT 1"
                ).fetchone()
                previous = GENESIS_HASH if row is None else str(row[0])
                record = seal(event, prev_hash=previous, timestamp=_timestamp(self._clock))
                connection.execute(
                    "INSERT INTO audit (record_hash, prev_hash, payload) VALUES (?, ?, ?)",
                    (
                        record.record_hash,
                        record.prev_hash,
                        json.dumps(record.to_dict(), sort_keys=True, separators=(",", ":")),
                    ),
                )
                connection.commit()
                return record
            except Exception:
                connection.rollback()
                raise
            finally:
                connection.close()

    def records(self) -> list[AuditRecord]:
        if not self.path.exists():
            raise AuditError(f"audit log does not exist: {self.path}")
        connection = self._connect()
        try:
            rows = connection.execute(
                "SELECT seq, record_hash, payload FROM audit ORDER BY seq ASC"
            ).fetchall()
        finally:
            connection.close()
        records: list[AuditRecord] = []
        for position, (seq, column_hash, payload) in enumerate(rows):
            try:
                loaded: Any = json.loads(str(payload))
            except json.JSONDecodeError as exc:
                raise AuditError(f"corrupt audit row {seq}: {exc}", index=position) from exc
            record = AuditRecord.from_dict(loaded, index=position)
            if record.record_hash != column_hash:
                raise AuditError(
                    f"audit row {seq} hash column does not match payload",
                    index=position,
                )
            records.append(record)
        return records

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=5)
        connection.execute("PRAGMA journal_mode=WAL")
        return connection


def open_audit(path: str | Path, *, clock: Clock | None = None) -> AuditSink:
    """Open JSONL, or SQLite for a ``.db``, ``.sqlite``, or ``.sqlite3`` suffix."""

    destination = Path(path)
    if destination.suffix in {".db", ".sqlite", ".sqlite3"}:
        return SqliteAuditSink(destination, clock=clock)
    return JsonlAuditSink(destination, clock=clock)


def verify_path(path: str | Path) -> VerifyResult:
    """Verify an existing log. A missing file is a failure, not an empty chain."""

    destination = Path(path)
    if not destination.exists():
        raise AuditError(f"audit log does not exist: {destination}")
    return open_audit(destination).verify()


def head_path(path: str | Path) -> str:
    """Return the head hash of an existing log."""

    destination = Path(path)
    if not destination.exists():
        raise AuditError(f"audit log does not exist: {destination}")
    return open_audit(destination).head()
