"""Governed tool execution for AI agents.

The guard sits between an agent and its tools. A call runs only when the policy
allows it, a risky call waits for a different person, and every decision is appended
to a hash-chained audit log.

Imports are resolved on first use so the pytest plugin can load without pulling the
library in before coverage starts measuring.
"""

from __future__ import annotations

from importlib import import_module
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from agent_guard.approval import (
        ApprovalGateway as ApprovalGateway,
    )
    from agent_guard.approval import (
        ApprovalState as ApprovalState,
    )
    from agent_guard.approval import (
        JsonFileApprovalBackend as JsonFileApprovalBackend,
    )
    from agent_guard.approval import (
        MemoryApprovalBackend as MemoryApprovalBackend,
    )
    from agent_guard.audit import (
        AuditSink as AuditSink,
    )
    from agent_guard.audit import (
        JsonlAuditSink as JsonlAuditSink,
    )
    from agent_guard.audit import (
        SqliteAuditSink as SqliteAuditSink,
    )
    from agent_guard.audit import (
        open_audit as open_audit,
    )
    from agent_guard.errors import (
        ActionNotFoundError as ActionNotFoundError,
    )
    from agent_guard.errors import (
        AgentGuardError as AgentGuardError,
    )
    from agent_guard.errors import (
        ApprovalError as ApprovalError,
    )
    from agent_guard.errors import (
        AuditError as AuditError,
    )
    from agent_guard.errors import (
        ConfigurationError as ConfigurationError,
    )
    from agent_guard.errors import (
        InvalidTransitionError as InvalidTransitionError,
    )
    from agent_guard.errors import (
        PayloadError as PayloadError,
    )
    from agent_guard.errors import (
        PolicyError as PolicyError,
    )
    from agent_guard.errors import (
        SchemaError as SchemaError,
    )
    from agent_guard.errors import (
        SelfApprovalError as SelfApprovalError,
    )
    from agent_guard.errors import (
        ToolBlocked as ToolBlocked,
    )
    from agent_guard.guard import (
        Guard as Guard,
    )
    from agent_guard.guard import (
        GuardResult as GuardResult,
    )
    from agent_guard.guard import (
        PendingAction as PendingAction,
    )
    from agent_guard.guard import (
        ValidationIssue as ValidationIssue,
    )
    from agent_guard.policy import (
        Effect as Effect,
    )
    from agent_guard.policy import (
        Policy as Policy,
    )
    from agent_guard.policy import (
        PolicyDecision as PolicyDecision,
    )
    from agent_guard.policy import (
        load_policy as load_policy,
    )

__version__ = "0.1.0"

_EXPORTS: dict[str, tuple[str, str]] = {
    "ActionNotFoundError": ("agent_guard.errors", "ActionNotFoundError"),
    "AgentGuardError": ("agent_guard.errors", "AgentGuardError"),
    "ApprovalError": ("agent_guard.errors", "ApprovalError"),
    "ApprovalGateway": ("agent_guard.approval", "ApprovalGateway"),
    "ApprovalState": ("agent_guard.approval", "ApprovalState"),
    "AuditError": ("agent_guard.errors", "AuditError"),
    "AuditSink": ("agent_guard.audit", "AuditSink"),
    "ConfigurationError": ("agent_guard.errors", "ConfigurationError"),
    "Effect": ("agent_guard.policy", "Effect"),
    "Guard": ("agent_guard.guard", "Guard"),
    "GuardResult": ("agent_guard.guard", "GuardResult"),
    "InvalidTransitionError": ("agent_guard.errors", "InvalidTransitionError"),
    "JsonFileApprovalBackend": ("agent_guard.approval", "JsonFileApprovalBackend"),
    "JsonlAuditSink": ("agent_guard.audit", "JsonlAuditSink"),
    "MemoryApprovalBackend": ("agent_guard.approval", "MemoryApprovalBackend"),
    "PayloadError": ("agent_guard.errors", "PayloadError"),
    "PendingAction": ("agent_guard.guard", "PendingAction"),
    "Policy": ("agent_guard.policy", "Policy"),
    "PolicyDecision": ("agent_guard.policy", "PolicyDecision"),
    "PolicyError": ("agent_guard.errors", "PolicyError"),
    "SchemaError": ("agent_guard.errors", "SchemaError"),
    "SelfApprovalError": ("agent_guard.errors", "SelfApprovalError"),
    "SqliteAuditSink": ("agent_guard.audit", "SqliteAuditSink"),
    "ToolBlocked": ("agent_guard.errors", "ToolBlocked"),
    "ValidationIssue": ("agent_guard.guard", "ValidationIssue"),
    "load_policy": ("agent_guard.policy", "load_policy"),
    "open_audit": ("agent_guard.audit", "open_audit"),
}

__all__ = [
    "ActionNotFoundError",
    "AgentGuardError",
    "ApprovalError",
    "ApprovalGateway",
    "ApprovalState",
    "AuditError",
    "AuditSink",
    "ConfigurationError",
    "Effect",
    "Guard",
    "GuardResult",
    "InvalidTransitionError",
    "JsonFileApprovalBackend",
    "JsonlAuditSink",
    "MemoryApprovalBackend",
    "PayloadError",
    "PendingAction",
    "Policy",
    "PolicyDecision",
    "PolicyError",
    "SchemaError",
    "SelfApprovalError",
    "SqliteAuditSink",
    "ToolBlocked",
    "ValidationIssue",
    "__version__",
    "load_policy",
    "open_audit",
]


def __getattr__(name: str) -> Any:
    target = _EXPORTS.get(name)
    if target is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    module_name, attr = target
    value = getattr(import_module(module_name), attr)
    globals()[name] = value
    return value


def __dir__() -> list[str]:
    return sorted(set(globals()) | set(_EXPORTS))
