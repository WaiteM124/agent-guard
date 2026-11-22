"""Pytest plugin. ``pytest --agent-guard-redteam`` fails if a gullible agent is not blocked."""

from __future__ import annotations

from typing import Any


def pytest_addoption(parser: Any) -> None:
    """Register ``--agent-guard-redteam``."""

    parser.addoption(
        "--agent-guard-redteam",
        action="store_true",
        default=False,
        help="Run bundled agent-guard red-team scenarios and fail if a side effect lands",
    )


def pytest_configure(config: Any) -> None:
    """Register the ``agent_guard_redteam`` marker."""

    config.addinivalue_line(
        "markers",
        "agent_guard_redteam: scenario covered by agent_guard.redteam.run",
    )


def pytest_sessionfinish(session: Any, exitstatus: int) -> None:
    """Run the bundled scenarios when the flag is set. Leave the exit code alone otherwise."""

    if not session.config.getoption("--agent-guard-redteam"):
        return
    from agent_guard.redteam import GullibleAgent, run

    report = run(GullibleAgent())
    reporter = session.config.pluginmanager.get_plugin("terminalreporter")
    if reporter is not None:
        reporter.write_line(report.summary())
    if not report.all_blocked:
        session.exitstatus = 1
    elif exitstatus != 0:
        session.exitstatus = exitstatus
