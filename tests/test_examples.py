"""The examples run without an API key or optional extras."""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _load(path: Path, name: str) -> object:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_ap_agent(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    module = _load(ROOT / "examples" / "ap_agent" / "main.py", "ap_agent_main")
    assert module.main(["--workdir", str(tmp_path)]) == 0
    output = capsys.readouterr().out
    assert "read_invoice status=executed" in output
    assert "create_supplier status=pending" in output
    assert "make_payment amount=500 status=pending" in output
    assert "make_payment amount=1500 status=denied" in output
    assert "make_payment amount=0 status=denied" in output
    assert "create_supplier status=executed" in output
    assert "make_payment amount=500 status=executed" in output
    assert "replay status=executed" in output
    assert "payments=1 suppliers=1" in output
    assert "audit=ok" in output


def test_langgraph_example(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    module = _load(ROOT / "examples" / "langgraph_example.py", "langgraph_example")
    assert module.main(["--workdir", str(tmp_path)]) == 0
    output = capsys.readouterr().out
    assert "interrupt kind=agent_guard.approval_required" in output
    assert "denied status=denied" in output


def test_mcp_example(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    module = _load(ROOT / "examples" / "mcp_example.py", "mcp_example")
    assert module.main(["--workdir", str(tmp_path)]) == 0
    output = capsys.readouterr().out
    assert "pending status=pending" in output
    assert "registered=make_payment" in output
    assert "ran=0" in output
