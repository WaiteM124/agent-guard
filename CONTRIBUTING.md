# Contributing

Thanks for contributing to **agent-guard**. This short guide is for humans (including first-time open-source contributors). Agents and detailed product rules: see [AGENTS.md](AGENTS.md).

## Setup

**Prerequisites:** Python 3.10 or newer, and pip.

```bash
python -m pip install -e ".[dev]"
```

Optional extras (only needed for those integration sketches):

```bash
python -m pip install -e ".[langgraph]"
python -m pip install -e ".[mcp]"
```

No API keys are required for the default test suite, red-team gate, or the scripted accounts-payable example.

### Pre-commit hooks (recommended)

```bash
python -m pip install pre-commit
pre-commit install
```

This runs the same ruff checks CI expects, plus a gitleaks secret scan, before each commit. You can also run `pre-commit run --all-files` once after cloning.

## Running examples

```bash
python examples/ap_agent/main.py
python examples/langgraph_example.py
python examples/mcp_example.py
agent-guard --help
```

## Tests and lint

```bash
ruff check . && ruff format --check .
mypy src
pytest
pytest --agent-guard-redteam   # deterministic red-team eval; no API key
```

CI runs lint, typecheck, and tests on Python 3.10–3.12, plus a dedicated red-team job on pull requests and pushes.

## Branch and PR conventions

- Branch from `main` with a short, descriptive name.
- Keep PRs **small and focused** on one concern.
- Fill in the pull request template checklist.
- State assumptions, optional extras touched, and follow-ups in the description.
- Do not commit secrets; use env vars or a secret manager (`OPENAI_API_KEY` for the optional LLM demo only).
- Do not delete or weaken tests solely to make CI pass.

## Definition of done

- Product principles in `AGENTS.md` respected (default deny; schema before policy; four-eyes; wired-path honesty; audit)
- Tests added/updated and passing; lint and mypy clean
- No secrets in the change
- Docs updated when behaviour or workflow changes
- CI green on the PR

## Questions

Open an issue if something in the docs is unclear. Prefer a small failing test or a concrete reproduction over a vague report.
