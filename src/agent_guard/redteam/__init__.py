"""Red-team helper. Point it at an agent that calls tools through a :class:`Guard`."""

from __future__ import annotations

from importlib import import_module
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from agent_guard.redteam.runner import (
        REDTEAM_POLICY as REDTEAM_POLICY,
    )
    from agent_guard.redteam.runner import (
        Agent as Agent,
    )
    from agent_guard.redteam.runner import (
        RedTeamReport as RedTeamReport,
    )
    from agent_guard.redteam.runner import (
        ScenarioResult as ScenarioResult,
    )
    from agent_guard.redteam.runner import (
        run as run,
    )
    from agent_guard.redteam.runner import (
        unguarded_side_effects as unguarded_side_effects,
    )
    from agent_guard.redteam.scenarios import (
        SCENARIOS as SCENARIOS,
    )
    from agent_guard.redteam.scenarios import (
        GullibleAgent as GullibleAgent,
    )
    from agent_guard.redteam.scenarios import (
        Scenario as Scenario,
    )

_EXPORTS: dict[str, tuple[str, str]] = {
    "REDTEAM_POLICY": ("agent_guard.redteam.runner", "REDTEAM_POLICY"),
    "Agent": ("agent_guard.redteam.runner", "Agent"),
    "RedTeamReport": ("agent_guard.redteam.runner", "RedTeamReport"),
    "ScenarioResult": ("agent_guard.redteam.runner", "ScenarioResult"),
    "run": ("agent_guard.redteam.runner", "run"),
    "unguarded_side_effects": ("agent_guard.redteam.runner", "unguarded_side_effects"),
    "SCENARIOS": ("agent_guard.redteam.scenarios", "SCENARIOS"),
    "GullibleAgent": ("agent_guard.redteam.scenarios", "GullibleAgent"),
    "Scenario": ("agent_guard.redteam.scenarios", "Scenario"),
}

__all__ = [
    "REDTEAM_POLICY",
    "SCENARIOS",
    "Agent",
    "GullibleAgent",
    "RedTeamReport",
    "Scenario",
    "ScenarioResult",
    "run",
    "unguarded_side_effects",
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
