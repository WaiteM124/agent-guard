"""JSONL and SQLite audit sinks, including hash-chain tamper detection."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

import pytest

from agent_guard import AuditError, JsonlAuditSink, SqliteAuditSink, open_audit
from agent_guard.audit import GENESIS_HASH, AuditEvent, head_path, verify_path
from agent_guard.canonical import json_safe


def _event(reason: str, action_id: str = "act-1") -> AuditEvent:
    return AuditEvent(
        action_id=action_id,
        actor="agent",
        tool="make_payment",
        args_hash="a" * 64,
        decision="deny",
        decided_by="policy",
        reason=reason,
        outcome="blocked",
    )


@pytest.fixture(params=["jsonl", "sqlite"])
def sink(request: pytest.FixtureRequest, tmp_path: Path) -> JsonlAuditSink | SqliteAuditSink:
    if request.param == "jsonl":
        return JsonlAuditSink(tmp_path / "audit.jsonl")
    return SqliteAuditSink(tmp_path / "audit.sqlite")


def test_chain_links_and_empty_log_uses_genesis(sink: JsonlAuditSink | SqliteAuditSink) -> None:
    assert sink.verify().ok is True
    assert sink.head() == GENESIS_HASH
    first = sink.append(_event("one", "a"))
    second = sink.append(_event("two", "b"))
    third = sink.append(_event("three", "c"))
    rows = sink.records()
    assert [row.reason for row in rows] == ["one", "two", "three"]
    assert rows[0].prev_hash == GENESIS_HASH
    assert rows[1].prev_hash == first.record_hash
    assert rows[2].prev_hash == second.record_hash
    result = sink.verify()
    assert result.ok is True
    assert result.count == 3
    assert result.head == third.record_hash
    assert rows[0].timestamp.endswith("+00:00")
    parsed = datetime.fromisoformat(rows[0].timestamp)
    assert parsed.tzinfo is not None
    assert parsed.utcoffset() == timezone.utc.utcoffset(parsed)


def test_edited_record_breaks_the_chain(sink: JsonlAuditSink | SqliteAuditSink) -> None:
    sink.append(_event("one", "a"))
    sink.append(_event("two", "b"))
    assert sink.verify().ok is True
    if isinstance(sink, JsonlAuditSink):
        lines = sink.path.read_text(encoding="utf-8").splitlines()
        payload = json.loads(lines[0])
        payload["reason"] = "tampered"
        lines[0] = json.dumps(payload)
        sink.path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    else:
        connection = sqlite3.connect(sink.path)
        row = connection.execute("SELECT payload FROM audit WHERE seq = 1").fetchone()
        assert row is not None
        payload = json.loads(str(row[0]))
        payload["reason"] = "tampered"
        connection.execute("UPDATE audit SET payload = ? WHERE seq = 1", (json.dumps(payload),))
        connection.commit()
        connection.close()
    result = sink.verify()
    assert result.ok is False
    assert result.index == 0
    assert "hash" in result.reason


def test_truncation_still_verifies_until_the_head_is_pinned(tmp_path: Path) -> None:
    sink = JsonlAuditSink(tmp_path / "audit.jsonl")
    sink.append(_event("one", "a"))
    sink.append(_event("two", "b"))
    head = sink.head()
    lines = [line for line in sink.path.read_text(encoding="utf-8").splitlines() if line.strip()]
    sink.path.write_text(lines[0] + "\n\n", encoding="utf-8")
    assert sink.verify().ok is True
    assert sink.head() != head
    checked = verify_path(sink.path)
    assert checked.ok is True
    assert checked.head != head


def test_corrupt_line_and_missing_file(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    sink = JsonlAuditSink(path)
    sink.append(_event("one"))
    path.write_text("{not-json\n", encoding="utf-8")
    result = sink.verify()
    assert result.ok is False
    missing = tmp_path / "gone.jsonl"
    with pytest.raises(AuditError):
        verify_path(missing)
    with pytest.raises(AuditError):
        head_path(missing)


def test_sqlite_hash_column_must_match_payload(tmp_path: Path) -> None:
    sink = SqliteAuditSink(tmp_path / "audit.sqlite")
    sink.append(_event("one"))
    connection = sqlite3.connect(sink.path)
    connection.execute("UPDATE audit SET record_hash = ? WHERE seq = 1", ("b" * 64,))
    connection.commit()
    connection.close()
    result = sink.verify()
    assert result.ok is False
    assert result.index == 0


def test_open_audit_selects_the_sink_from_the_suffix(tmp_path: Path) -> None:
    assert isinstance(open_audit(tmp_path / "a.jsonl"), JsonlAuditSink)
    assert isinstance(open_audit(tmp_path / "a.db"), SqliteAuditSink)
    assert isinstance(open_audit(tmp_path / "a.sqlite3"), SqliteAuditSink)


def test_naive_clock_is_rejected(tmp_path: Path) -> None:
    sink = JsonlAuditSink(tmp_path / "audit.jsonl", clock=lambda: datetime(2026, 1, 1))
    with pytest.raises(ValueError):
        sink.append(_event("one"))


def test_json_safe_falls_back_for_non_json_values() -> None:
    assert json_safe({"amount": 1}) == {"amount": 1}
    fallback = json_safe(float("nan"))
    assert isinstance(fallback, dict)
    assert "_repr" in fallback
