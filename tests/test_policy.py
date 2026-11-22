"""Policy loading, the condition language, and fail-fast validation."""

from __future__ import annotations

from datetime import timedelta
from pathlib import Path

import pytest

from agent_guard import Effect, Policy, PolicyError, load_policy
from agent_guard.policy import parse_condition
from tests.support import AP_POLICY


def test_loads_accounts_payable_policy() -> None:
    policy = Policy.loads(AP_POLICY)
    assert policy.version == 1
    assert policy.default_effect is Effect.DENY
    assert policy.approval_ttl == timedelta(minutes=30)
    assert policy.decide("make_payment", {"amount": 1000}).effect is Effect.REQUIRE_APPROVAL
    assert policy.decide("make_payment", {"amount": 1001}).effect is Effect.DENY
    assert policy.decide("make_payment", {"amount": 0}).effect is Effect.DENY
    assert policy.decide("make_payment", {"amount": 1}).reason == "payment needs a person"
    assert policy.decide("nope", {}).effect is Effect.DENY
    assert "amount" in policy.referenced_fields("make_payment")
    assert policy.referenced_fields("missing") == set()


def test_default_ttl_when_omitted() -> None:
    policy = Policy.loads("version: 1\ndefault: deny\ntools: {}\n")
    assert policy.approval_ttl == timedelta(minutes=30)


@pytest.mark.parametrize(
    ("raw", "seconds"),
    [("45", 45), ("45s", 45), ("2m", 120), ("2h", 7200), ("1d", 86400)],
)
def test_ttl_formats(raw: str, seconds: int) -> None:
    text = f"version: 1\ndefault: deny\napproval_ttl: {raw}\ntools: {{}}\n"
    if raw.isdigit():
        text = f"version: 1\ndefault: deny\napproval_ttl: {int(raw)}\ntools: {{}}\n"
    assert Policy.loads(text).approval_ttl == timedelta(seconds=seconds)


@pytest.mark.parametrize(
    "text",
    [
        "",
        "[]",
        "version: 1\ndefault: allow\ntools: {}\n",
        "version: 2\ndefault: deny\ntools: {}\n",
        "version: '1'\ndefault: deny\ntools: {}\n",
        "version: 1\ndefault: deny\ntools: []\n",
        "version: 1\ndefault: deny\nextra: 1\ntools: {}\n",
        "version: 1\ndefault: deny\ntools:\n  1bad:\n    effect: allow\n",
        "version: 1\ndefault: deny\ntools:\n  pay: []\n",
        "version: 1\ndefault: deny\ntools:\n  pay:\n    effect: allow\n    extra: 1\n",
        "version: 1\ndefault: deny\ntools:\n  pay:\n    reason: because\n",
        "version: 1\ndefault: deny\ntools:\n  pay:\n    effect: maybe\n",
        "version: 1\ndefault: deny\ntools:\n  pay:\n    effect: allow\n    reason: '   '\n",
        "version: 1\ndefault: deny\ntools:\n  pay:\n    effect: allow\n    conditions: {}\n",
        "version: 1\ndefault: deny\ntools:\n  pay:\n    effect: allow\n    conditions:\n      - effect: deny\n",
        "version: 1\ndefault: deny\ntools:\n  pay:\n    effect: allow\n    conditions:\n      - when: 1\n        effect: deny\n",
        "version: 1\ndefault: deny\ntools:\n  pay:\n    effect: allow\n    conditions:\n      - when: 'amount >> 1'\n        effect: deny\n",
        "version: 1\ndefault: deny\ntools:\n  pay:\n    effect: allow\n    conditions:\n      - when: 'amount > 1'\n        effect: deny\n        extra: 1\n",
        "version: 1\ndefault: deny\napproval_ttl: 0\ntools: {}\n",
        "version: 1\ndefault: deny\napproval_ttl: -5\ntools: {}\n",
        "version: 1\ndefault: deny\napproval_ttl: 0m\ntools: {}\n",
        "version: 1\ndefault: deny\napproval_ttl: later\ntools: {}\n",
        "version: 1\ndefault: deny\napproval_ttl: true\ntools: {}\n",
        "version: 1\ndefault: deny\napproval_ttl: 1.5\ntools: {}\n",
        "version: 1\nversion: 1\ndefault: deny\ntools: {}\n",
        "version: 1\ndefault: deny\ntools:\n  pay:\n    effect: allow\n  pay:\n    effect: deny\n",
    ],
)
def test_invalid_policy_fails_fast(text: str) -> None:
    with pytest.raises(PolicyError):
        Policy.loads(text)


def test_load_missing_file(tmp_path: Path) -> None:
    with pytest.raises(PolicyError):
        load_policy(tmp_path / "missing.yaml")


def test_first_matching_condition_wins() -> None:
    policy = Policy.loads(
        """
        version: 1
        default: deny
        tools:
          pay:
            effect: allow
            conditions:
              - when: "amount > 1000"
                effect: deny
              - when: "amount > 100"
                effect: require_approval
        """
    )
    assert policy.decide("pay", {"amount": 5000}).effect is Effect.DENY
    assert policy.decide("pay", {"amount": 500}).effect is Effect.REQUIRE_APPROVAL
    assert policy.decide("pay", {"amount": 50}).effect is Effect.ALLOW


@pytest.mark.parametrize(
    ("expression", "arguments", "expected"),
    [
        ("amount > 10", {"amount": 11}, True),
        ("amount >= 10", {"amount": 10}, True),
        ("amount < 10", {"amount": 9}, True),
        ("amount <= 10", {"amount": 10}, True),
        ("amount == 10", {"amount": 10}, True),
        ("amount != 10", {"amount": 11}, True),
        ("amount > 10.5", {"amount": 11}, True),
        ("amount > 10", {"amount": "11"}, True),
        ('currency == "GBP"', {"currency": "GBP"}, True),
        ('currency != "GBP"', {"currency": "EUR"}, True),
        ("flag == true", {"flag": True}, True),
        ("flag == false", {"flag": False}, True),
        ("note == null", {"note": None}, True),
        ("amount in [100, 250]", {"amount": 250}, True),
        ('name in ["acme", "other"]', {"name": "acme"}, True),
        ('supplier.country == "GB"', {"supplier": {"country": "GB"}}, True),
        ('amount > 10 and currency == "GBP"', {"amount": 11, "currency": "GBP"}, True),
        ('amount > 10 and currency == "GBP"', {"amount": 11, "currency": "EUR"}, False),
        ('amount > 100 or currency == "USD"', {"amount": 1, "currency": "USD"}, True),
        ("not amount > 10", {"amount": 3}, True),
        ("not not amount > 1", {"amount": 5}, True),
        ("amount > 10", {}, False),
        ("amount != 5", {}, False),
        ("not amount > 5", {}, True),
        ("amount > 10", {"amount": "nope"}, False),
        ("flag > 1", {"flag": True}, False),
    ],
)
def test_condition_evaluation(
    expression: str, arguments: dict[str, object], expected: bool
) -> None:
    assert parse_condition(expression).evaluate(arguments) is expected


@pytest.mark.parametrize(
    "expression",
    [
        "",
        "amount >",
        "amount > 1 leftover",
        "amount in [1,]",
        "'unterminated",
        "'bad \\q'",
        "amount > -",
        "1.2.3 > 1",
        "@ > 1",
    ],
)
def test_condition_syntax_errors(expression: str) -> None:
    with pytest.raises(PolicyError):
        parse_condition(expression)


def test_condition_roots() -> None:
    expr = parse_condition('supplier.country == "GB" and amount > 1')
    assert expr.roots() == {"supplier", "amount"}
