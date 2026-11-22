"""YAML policy: per-tool effect, first-match conditions, default deny."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import timedelta
from decimal import Decimal, InvalidOperation
from enum import Enum
from pathlib import Path
from typing import Any

import yaml

from agent_guard.errors import PolicyError

_DURATION = re.compile(r"^(\d+)(s|m|h|d)$")
_TOOL_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_TOP_KEYS = frozenset({"version", "default", "approval_ttl", "tools"})
_TOOL_KEYS = frozenset({"effect", "conditions", "reason"})
_CONDITION_KEYS = frozenset({"when", "effect", "reason"})
_TWO_CHAR_OPS = frozenset({">=", "<=", "==", "!="})
_ONE_CHAR_OPS = frozenset({">", "<"})
_DEFAULT_TTL = timedelta(minutes=30)


class Effect(str, Enum):
    """What the guard may do with a tool call after the schema accepts it."""

    ALLOW = "allow"
    REQUIRE_APPROVAL = "require_approval"
    DENY = "deny"


@dataclass(frozen=True)
class PolicyDecision:
    """The effect chosen for one call, and the reason a person can read."""

    effect: Effect
    reason: str
    tool: str


@dataclass(frozen=True)
class _Tok:
    kind: str
    value: Any


class Expr:
    """A boolean condition over tool arguments. No function calls and no attribute code."""

    def evaluate(self, arguments: Mapping[str, Any]) -> bool:
        raise NotImplementedError

    def roots(self) -> set[str]:
        """Top-level argument names this expression reads."""

        raise NotImplementedError


@dataclass(frozen=True)
class _And(Expr):
    left: Expr
    right: Expr

    def evaluate(self, arguments: Mapping[str, Any]) -> bool:
        return self.left.evaluate(arguments) and self.right.evaluate(arguments)

    def roots(self) -> set[str]:
        return self.left.roots() | self.right.roots()


@dataclass(frozen=True)
class _Or(Expr):
    left: Expr
    right: Expr

    def evaluate(self, arguments: Mapping[str, Any]) -> bool:
        return self.left.evaluate(arguments) or self.right.evaluate(arguments)

    def roots(self) -> set[str]:
        return self.left.roots() | self.right.roots()


@dataclass(frozen=True)
class _Not(Expr):
    inner: Expr

    def evaluate(self, arguments: Mapping[str, Any]) -> bool:
        return not self.inner.evaluate(arguments)

    def roots(self) -> set[str]:
        return self.inner.roots()


@dataclass(frozen=True)
class _Compare(Expr):
    path: tuple[str, ...]
    op: str
    value: Any

    def evaluate(self, arguments: Mapping[str, Any]) -> bool:
        found, current = _lookup(arguments, self.path)
        # A missing field does not satisfy the comparison, including ``!=``.
        # Required fields have already been checked by the schema, so this only
        # comes up for optional ones. ``not`` inverts the result, which is why
        # negative conditions on optional fields are a footgun.
        if not found:
            return False
        return _compare(current, self.op, self.value)

    def roots(self) -> set[str]:
        return {self.path[0]} if self.path else set()


@dataclass(frozen=True)
class _In(Expr):
    path: tuple[str, ...]
    values: tuple[Any, ...]

    def evaluate(self, arguments: Mapping[str, Any]) -> bool:
        found, current = _lookup(arguments, self.path)
        if not found:
            return False
        return any(_same(current, item) for item in self.values)

    def roots(self) -> set[str]:
        return {self.path[0]} if self.path else set()


@dataclass(frozen=True)
class Condition:
    """One ordered rule. The first condition that evaluates true wins."""

    source: str
    expr: Expr
    effect: Effect
    reason: str

    def roots(self) -> set[str]:
        return self.expr.roots()


@dataclass(frozen=True)
class ToolRule:
    """Base effect for one tool, plus optional conditions evaluated in order."""

    name: str
    effect: Effect
    conditions: tuple[Condition, ...]
    reason: str

    def referenced_fields(self) -> set[str]:
        names: set[str] = set()
        for condition in self.conditions:
            names |= condition.roots()
        return names


@dataclass(frozen=True)
class Policy:
    """A validated policy. Construct it with :func:`load_policy` or :meth:`loads`."""

    version: int
    default_effect: Effect
    approval_ttl: timedelta
    tools: Mapping[str, ToolRule]

    def decide(self, tool: str, arguments: Mapping[str, Any]) -> PolicyDecision:
        """Choose an effect for ``tool``. Unknown tools are denied."""

        rule = self.tools.get(tool)
        if rule is None:
            return PolicyDecision(Effect.DENY, f"unknown tool {tool}", tool)

        for condition in rule.conditions:
            if condition.expr.evaluate(arguments):
                return PolicyDecision(condition.effect, condition.reason, tool)
        return PolicyDecision(rule.effect, rule.reason, tool)

    def referenced_fields(self, tool: str) -> set[str]:
        """Argument names the policy reads for ``tool``. Empty if the tool is unknown."""

        rule = self.tools.get(tool)
        if rule is None:
            return set()
        return rule.referenced_fields()

    @classmethod
    def loads(cls, text: str, *, source: str = "<policy>") -> Policy:
        """Parse and validate a policy document. Raises :class:`PolicyError` on failure."""

        if not isinstance(text, str) or not text.strip():
            raise PolicyError(f"{source} is empty")
        try:
            loaded = yaml.load(text, Loader=_UniqueLoader)
        except PolicyError:
            raise
        except yaml.YAMLError as exc:
            raise PolicyError(f"{source} is not valid YAML: {exc}") from exc
        return _build_policy(loaded, source)

    @classmethod
    def load(cls, path: str | Path) -> Policy:
        """Read a UTF-8 policy file. Missing files and invalid documents fail immediately."""

        policy_path = Path(path)
        if not policy_path.is_file():
            raise PolicyError(f"policy file not found: {policy_path}")
        try:
            text = policy_path.read_text(encoding="utf-8")
        except OSError as exc:
            raise PolicyError(f"could not read policy file {policy_path}: {exc}") from exc
        return cls.loads(text, source=str(policy_path))


def load_policy(path: str | Path) -> Policy:
    """Load a policy file. Invalid policy raises :class:`PolicyError` and does not continue."""

    return Policy.load(path)


class _UniqueLoader(yaml.SafeLoader):
    """Safe loader that rejects duplicate keys instead of keeping the last one."""


def _construct_unique_mapping(
    loader: yaml.SafeLoader,
    node: yaml.MappingNode,
    deep: bool = False,
) -> dict[Any, Any]:
    mapping: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in mapping:
            raise PolicyError(f"duplicate key {key!r} in policy")
        value = loader.construct_object(value_node, deep=deep)
        mapping[key] = value
    return mapping


_UniqueLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_mapping,
)


def _build_policy(loaded: Any, source: str) -> Policy:
    if not isinstance(loaded, dict):
        raise PolicyError(f"{source} must be a mapping")
    unknown = set(loaded) - _TOP_KEYS
    if unknown:
        names = ", ".join(repr(name) for name in sorted(unknown, key=repr))
        raise PolicyError(f"{source} has unknown fields: {names}")

    version = loaded.get("version")
    if isinstance(version, bool) or not isinstance(version, int) or version != 1:
        raise PolicyError(f"{source} version must be 1")

    default_value = loaded.get("default", Effect.DENY.value)
    default_effect = _parse_effect(default_value, where=f"{source} default")
    if default_effect is not Effect.DENY:
        raise PolicyError(f"{source} default must be deny")

    approval_ttl = _DEFAULT_TTL
    if "approval_ttl" in loaded:
        approval_ttl = _parse_ttl(loaded["approval_ttl"])

    tools_node = loaded.get("tools", {})
    if not isinstance(tools_node, dict):
        raise PolicyError(f"{source} tools must be a mapping")

    tools: dict[str, ToolRule] = {}
    for name, body in tools_node.items():
        if not isinstance(name, str) or _TOOL_NAME.fullmatch(name) is None:
            raise PolicyError(f"invalid tool name {name!r}")
        tools[name] = _parse_tool(name, body)
    return Policy(
        version=version,
        default_effect=default_effect,
        approval_ttl=approval_ttl,
        tools=tools,
    )


def _parse_tool(name: str, body: Any) -> ToolRule:
    if not isinstance(body, dict):
        raise PolicyError(f"tool {name} must be a mapping")
    unknown = set(body) - _TOOL_KEYS
    if unknown:
        names = ", ".join(repr(item) for item in sorted(unknown, key=repr))
        raise PolicyError(f"tool {name} has unknown fields: {names}")
    if "effect" not in body:
        raise PolicyError(f"tool {name} is missing effect")
    effect = _parse_effect(body["effect"], where=f"tool {name}")
    reason = _parse_reason(body.get("reason"), where=f"tool {name}")
    if reason is None:
        reason = f"tool rule: {effect.value}"

    raw_conditions = body.get("conditions", [])
    if not isinstance(raw_conditions, list):
        raise PolicyError(f"tool {name} conditions must be a list")
    conditions: list[Condition] = []
    for index, raw in enumerate(raw_conditions, start=1):
        conditions.append(_parse_condition(name, index, raw))
    return ToolRule(name=name, effect=effect, conditions=tuple(conditions), reason=reason)


def _parse_condition(tool: str, index: int, raw: Any) -> Condition:
    where = f"tool {tool} condition {index}"
    if not isinstance(raw, dict):
        raise PolicyError(f"{where} must be a mapping")
    unknown = set(raw) - _CONDITION_KEYS
    if unknown:
        names = ", ".join(repr(item) for item in sorted(unknown, key=repr))
        raise PolicyError(f"{where} has unknown fields: {names}")
    when = raw.get("when")
    if not isinstance(when, str) or not when.strip():
        raise PolicyError(f"{where} needs a string 'when' expression")
    if "effect" not in raw:
        raise PolicyError(f"{where} is missing effect")
    effect = _parse_effect(raw["effect"], where=where)
    reason = _parse_reason(raw.get("reason"), where=where)
    try:
        expr = parse_condition(when)
    except PolicyError as exc:
        raise PolicyError(f"{where}: {exc}") from exc
    if reason is None:
        reason = f"matched condition: {when.strip()}"
    return Condition(source=when.strip(), expr=expr, effect=effect, reason=reason)


def _parse_effect(value: Any, *, where: str) -> Effect:
    if not isinstance(value, str):
        raise PolicyError(f"{where} effect must be allow, require_approval, or deny")
    try:
        return Effect(value)
    except ValueError as exc:
        raise PolicyError(f"{where} effect must be allow, require_approval, or deny") from exc


def _parse_reason(value: Any, *, where: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value.strip():
        raise PolicyError(f"{where} reason must be a non-empty string")
    return value.strip()


def _parse_ttl(value: Any) -> timedelta:
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        raise PolicyError(
            "approval_ttl must be a positive number of seconds or a duration like 30m"
        )
    if isinstance(value, int):
        seconds = value
    else:
        match = _DURATION.fullmatch(value.strip())
        if match is None:
            raise PolicyError(f"invalid approval_ttl {value!r}; use seconds or a unit s, m, h, d")
        amount = int(match.group(1))
        unit = match.group(2)
        multiplier = {"s": 1, "m": 60, "h": 3600, "d": 86400}[unit]
        seconds = amount * multiplier
    if seconds <= 0:
        raise PolicyError("approval_ttl must be positive")
    return timedelta(seconds=seconds)


def parse_condition(source: str) -> Expr:
    """Parse a condition expression. The grammar is documented in the README."""

    if not source.strip():
        raise PolicyError("condition must not be empty")
    parser = _Parser(_tokenize(source), source)
    expr = parser.parse_or()
    if parser.peek().kind != "eof":
        raise PolicyError(f"trailing input in condition {source!r}")
    return expr


def _tokenize(source: str) -> list[_Tok]:
    tokens: list[_Tok] = []
    index = 0
    length = len(source)
    while index < length:
        char = source[index]
        if char.isspace():
            index += 1
            continue
        if char in "\"'":
            text, index = _read_string(source, index)
            tokens.append(_Tok("string", text))
            continue
        if char == "[":
            tokens.append(_Tok("lbrack", "["))
            index += 1
            continue
        if char == "]":
            tokens.append(_Tok("rbrack", "]"))
            index += 1
            continue
        if char == ",":
            tokens.append(_Tok("comma", ","))
            index += 1
            continue
        if char == ".":
            tokens.append(_Tok("dot", "."))
            index += 1
            continue
        if char in "><=!":
            pair = source[index : index + 2]
            if pair in _TWO_CHAR_OPS:
                tokens.append(_Tok("op", pair))
                index += 2
                continue
            if char in _ONE_CHAR_OPS:
                tokens.append(_Tok("op", char))
                index += 1
                continue
            raise PolicyError(f"unexpected character {char!r} in condition {source!r}")
        if char == "-" or char.isdigit():
            number, index = _read_number(source, index)
            tokens.append(_Tok("number", number))
            continue
        if char.isalpha() or char == "_":
            word, index = _read_word(source, index)
            tokens.append(_word_token(word))
            continue
        raise PolicyError(f"unexpected character {char!r} in condition {source!r}")
    tokens.append(_Tok("eof", None))
    return tokens


def _read_string(source: str, index: int) -> tuple[str, int]:
    quote = source[index]
    index += 1
    chars: list[str] = []
    escapes = {"n": "\n", "t": "\t", "\\": "\\", "'": "'", '"': '"'}
    while index < len(source):
        char = source[index]
        if char == "\\":
            if index + 1 >= len(source) or source[index + 1] not in escapes:
                raise PolicyError(f"invalid escape in condition {source!r}")
            chars.append(escapes[source[index + 1]])
            index += 2
            continue
        if char == quote:
            return "".join(chars), index + 1
        chars.append(char)
        index += 1
    raise PolicyError(f"unterminated string in condition {source!r}")


def _read_number(source: str, index: int) -> tuple[int | float, int]:
    start = index
    if source[index] == "-":
        index += 1
        if index >= len(source) or not source[index].isdigit():
            raise PolicyError(f"expected a digit after '-' in condition {source!r}")
    while index < len(source) and source[index].isdigit():
        index += 1
    if index < len(source) and source[index] == ".":
        index += 1
        if index >= len(source) or not source[index].isdigit():
            raise PolicyError(f"expected a digit after '.' in condition {source!r}")
        while index < len(source) and source[index].isdigit():
            index += 1
    text = source[start:index]
    if index < len(source) and (source[index].isalpha() or source[index] == "_"):
        raise PolicyError(f"invalid number {text!r} in condition {source!r}")
    value: int | float = float(text) if "." in text else int(text)
    return value, index


def _read_word(source: str, index: int) -> tuple[str, int]:
    start = index
    while index < len(source) and (source[index].isalnum() or source[index] == "_"):
        index += 1
    return source[start:index], index


def _word_token(word: str) -> _Tok:
    if word == "and":
        return _Tok("and", word)
    if word == "or":
        return _Tok("or", word)
    if word == "not":
        return _Tok("not", word)
    if word == "in":
        return _Tok("in", word)
    if word == "true":
        return _Tok("bool", True)
    if word == "false":
        return _Tok("bool", False)
    if word == "null":
        return _Tok("null", None)
    return _Tok("ident", word)


class _Parser:
    def __init__(self, tokens: list[_Tok], source: str) -> None:
        self._tokens = tokens
        self._source = source
        self._index = 0

    def peek(self) -> _Tok:
        return self._tokens[self._index]

    def accept(self, kind: str) -> _Tok | None:
        if self.peek().kind == kind:
            token = self.peek()
            self._index += 1
            return token
        return None

    def expect(self, kind: str) -> _Tok:
        token = self.accept(kind)
        if token is None:
            found = self.peek().kind
            raise PolicyError(f"invalid condition {self._source!r}: expected {kind}, found {found}")
        return token

    def parse_or(self) -> Expr:
        left = self.parse_and()
        while self.accept("or") is not None:
            left = _Or(left, self.parse_and())
        return left

    def parse_and(self) -> Expr:
        left = self.parse_not()
        while self.accept("and") is not None:
            left = _And(left, self.parse_not())
        return left

    def parse_not(self) -> Expr:
        if self.accept("not") is not None:
            return _Not(self.parse_not())
        return self.parse_comparison()

    def parse_comparison(self) -> Expr:
        path = self.parse_path()
        if self.accept("in") is not None:
            self.expect("lbrack")
            values: list[Any] = []
            if self.peek().kind != "rbrack":
                values.append(self.parse_literal())
                while self.accept("comma") is not None:
                    values.append(self.parse_literal())
            self.expect("rbrack")
            return _In(path, tuple(values))
        op = self.expect("op")
        literal = self.parse_literal()
        return _Compare(path, str(op.value), literal)

    def parse_path(self) -> tuple[str, ...]:
        first = self.expect("ident")
        parts = [str(first.value)]
        while self.accept("dot") is not None:
            nxt = self.expect("ident")
            parts.append(str(nxt.value))
        return tuple(parts)

    def parse_literal(self) -> Any:
        token = self.peek()
        if token.kind in {"string", "number", "bool", "null"}:
            self._index += 1
            return token.value
        raise PolicyError(
            f"invalid condition {self._source!r}: expected a literal, found {token.kind}"
        )


def _lookup(arguments: Mapping[str, Any], path: tuple[str, ...]) -> tuple[bool, Any]:
    current: Any = arguments
    for part in path:
        if not isinstance(current, Mapping) or part not in current:
            return False, None
        current = current[part]
    return True, current


def _decimal(value: Any) -> Decimal | None:
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, Decimal):
        return value
    if isinstance(value, int):
        return Decimal(value)
    if isinstance(value, float):
        return Decimal(str(value))
    if isinstance(value, str):
        try:
            return Decimal(value)
        except InvalidOperation:
            return None
    return None


def _compare(left: Any, op: str, right: Any) -> bool:
    left_num = _decimal(left)
    right_num = _decimal(right)
    if left_num is not None and right_num is not None:
        return _compare_ordered(left_num, op, right_num)
    if op == "==":
        return bool(left == right)
    if op == "!=":
        return bool(left != right)
    return False


def _compare_ordered(left: Decimal, op: str, right: Decimal) -> bool:
    if op == ">":
        return left > right
    if op == ">=":
        return left >= right
    if op == "<":
        return left < right
    if op == "<=":
        return left <= right
    if op == "==":
        return left == right
    if op == "!=":
        return left != right
    return False


def _same(left: Any, right: Any) -> bool:
    left_num = _decimal(left)
    right_num = _decimal(right)
    if left_num is not None and right_num is not None:
        return left_num == right_num
    return bool(left == right)
