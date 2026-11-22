"""Public package surface."""

from agent_guard import Guard, __version__


def test_version_and_guard_are_importable() -> None:
    assert __version__ == "0.1.0"
    assert Guard.from_policy.__doc__
