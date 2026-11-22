"""Bundled prompt-injection scenarios and the pytest plugin hook."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from agent_guard import Guard
from agent_guard.redteam import SCENARIOS, GullibleAgent, plugin, run, unguarded_side_effects


def test_every_attack_would_land_without_the_guard() -> None:
    assert len(SCENARIOS) >= 10
    for scenario in SCENARIOS:
        assert unguarded_side_effects(scenario), scenario.id


def test_guard_blocks_a_gullible_agent() -> None:
    report = run(GullibleAgent())
    assert report.all_blocked
    by_id = {item.scenario_id: item for item in report.results}
    assert "deny:blocked" in by_id["payment_over_limit"].decisions
    assert "invalid:blocked" in by_id["extra_field_bypass"].decisions
    assert "self_approval:blocked" in by_id["self_approval"].decisions
    assert "require_approval:pending" in by_id["invoice_pay_new_supplier"].decisions
    assert "require_approval:pending" in by_id["document_create_supplier"].decisions
    assert "deny:blocked" in by_id["unlisted_wire_funds"].decisions
    assert "red-team:" in report.summary()
    assert "LEAKED" not in report.summary()


def test_cautious_agent_is_blocked() -> None:
    class Cautious:
        def run(self, scenario: object, guard: Guard) -> None:
            del scenario
            guard.call("read_invoice", {"invoice_id": "inv-1"}, actor="agent")

    report = run(Cautious())
    assert report.all_blocked


def test_plugin_flag(tmp_path: Path) -> None:
    del tmp_path

    class Parser:
        def __init__(self) -> None:
            self.options: list[tuple[object, ...]] = []

        def addoption(self, *args: object, **kwargs: object) -> None:
            self.options.append(args)

    parser = Parser()
    plugin.pytest_addoption(parser)
    assert parser.options

    class Config:
        def __init__(self, enabled: bool) -> None:
            self.enabled = enabled
            self.pluginmanager = self
            self.lines: list[str] = []
            self.text = ""

        def addinivalue_line(self, _name: str, line: str) -> None:
            self.lines.append(line)

        def getoption(self, name: str) -> bool:
            assert name == "--agent-guard-redteam"
            return self.enabled

        def get_plugin(self, name: str) -> Config | None:
            assert name == "terminalreporter"
            return self

        def write_line(self, text: str) -> None:
            self.text = text

    class Session:
        def __init__(self, enabled: bool) -> None:
            self.config = Config(enabled)
            self.exitstatus = 0

    disabled = Session(False)
    plugin.pytest_configure(disabled.config)
    plugin.pytest_sessionfinish(disabled, 0)
    assert disabled.exitstatus == 0
    enabled = Session(True)
    plugin.pytest_sessionfinish(enabled, 0)
    assert enabled.exitstatus == 0
    assert "blocked" in enabled.config.text


def test_plugin_entrypoint_smoke() -> None:
    root = Path(__file__).resolve().parents[1]
    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            "-o",
            "addopts=",
            "-p",
            "no:cacheprovider",
            "--agent-guard-redteam",
            "tests/test_plugin_smoke.py",
            "-q",
        ],
        cwd=root,
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
