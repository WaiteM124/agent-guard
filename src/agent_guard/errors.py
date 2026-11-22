"""Expected failures from policy, validation, approval, and audit."""

from __future__ import annotations


class AgentGuardError(Exception):
    """Base for failures a caller can handle. Programming bugs stay as built-in errors."""


class PolicyError(AgentGuardError):
    """The policy document is missing, unreadable, or not valid."""


class SchemaError(AgentGuardError):
    """A tool was registered with a schema this library cannot enforce."""


class ConfigurationError(AgentGuardError):
    """The host wired the guard incorrectly."""


class ToolBlocked(AgentGuardError):
    """A decorated tool was called and the guard did not execute it.

    ``result`` is the same object :meth:`agent_guard.Guard.call` would have returned.
    Pending, denied, invalid, and failed calls all raise this from the wrapper so a
    direct function call cannot ignore the decision.
    """

    def __init__(self, result: object) -> None:
        self.result = result
        reason = getattr(result, "reason", "")
        status = getattr(result, "status", "blocked")
        super().__init__(f"{status}: {reason}")


class ApprovalError(AgentGuardError):
    """Base for approval-store and state-machine failures."""


class InvalidTransitionError(ApprovalError):
    """The action is not in a state that allows this transition."""


class ActionNotFoundError(ApprovalError):
    """No action with this id is in the store."""

    def __init__(self, action_id: str) -> None:
        self.action_id = action_id
        super().__init__(f"No action with id {action_id}")


class SelfApprovalError(ApprovalError):
    """The actor who proposed an action tried to approve it."""

    def __init__(self, action_id: str, actor_id: str) -> None:
        self.action_id = action_id
        self.actor_id = actor_id
        super().__init__(f"Actor {actor_id} cannot approve their own action {action_id}")


class PayloadError(ApprovalError):
    """Arguments could not be canonicalised into a stable idempotency key."""


class AuditError(AgentGuardError):
    """The audit log is missing, unreadable, or structurally corrupt."""

    def __init__(self, message: str, *, index: int | None = None) -> None:
        self.index = index
        super().__init__(message)
