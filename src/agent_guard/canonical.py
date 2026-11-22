"""Stable JSON encoding and SHA-256 helpers shared by approval and audit."""

from __future__ import annotations

import hashlib
import json
from typing import Any

from agent_guard.errors import PayloadError


def canonical_json(value: Any) -> str:
    """Encode ``value`` so key order and insignificant whitespace do not change the bytes.

    ``NaN`` and ``Infinity`` are rejected. They are not JSON, and they must not appear
    in an idempotency key or an audit hash.
    """

    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise PayloadError("Value must be JSON-serialisable") from exc


def sha256_text(text: str) -> str:
    """Hex SHA-256 of a UTF-8 string."""

    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def json_safe(value: Any) -> Any:
    """Return a JSON round-trip of ``value``, or a ``{"_repr": ...}`` stand-in.

    Tool results are stored on the approval record so a replay can return them.
    A result that is not JSON becomes a short placeholder rather than failing the
    execution after the side effect has already happened.
    """

    try:
        encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)
    except (TypeError, ValueError):
        return {"_repr": repr(value)}
    loaded: Any = json.loads(encoded)
    return loaded
