# AGENTS.md — agent-guard contributor & agent guide

Single source of truth for humans and AI agents (including Cursor) working in this repository.

**Product:** agent-guard — a small Python library that sits between an AI agent and its tools so the agent can only do what policy allows, risky actions wait for a human, and every decision is auditable. It is a **library**, not a hosted product. It has no production deployments and no users to claim.

**Owner:** Miles Waite. Public open-source (MIT). Published to PyPI as `agent-guard`.

---

## Repository map

| Path | Role |
|---|---|
| `src/agent_guard/` | Library package: `Guard`, policy, approval state machine, audit sinks, CLI entry |
| `src/agent_guard/policy.py` | YAML policy load + small condition language (no `eval`) |
| `src/agent_guard/approval.py` | Approval state machine; memory and JSON-file backends |
| `src/agent_guard/audit.py` | Hash-chained JSONL and SQLite audit sinks |
| `src/agent_guard/guard.py` | Public `Guard` API: schema → policy → approve/execute |
| `src/agent_guard/cli.py` | `agent-guard` CLI (`list`, `approve`, `reject`, `audit`) |
| `src/agent_guard/integrations/` | Thin LangGraph interrupt helper and MCP-style wrappers |
| `src/agent_guard/redteam/` | Injection scenarios, `GullibleAgent` control, pytest plugin |
| `tests/` | Unit/integration coverage (pytest + coverage ≥ 90%) |
| `examples/` | Accounts-payable demo, LangGraph and MCP sketches |
| `docs/design.md` | Design notes for policy, state machine, and audit chain |
| `docs/decisions/` | Decision records (ADRs) |
| `.github/workflows/ci.yml` | PR/push CI: ruff, mypy, pytest; red-team eval gate |
| `.github/workflows/publish.yml` | Tag-only PyPI publish (trusted publisher) |

Stack: **Python 3.10+**, Pydantic v2, PyYAML; **ruff** (lint/format), **mypy** (strict on `src`), **pytest** (+ coverage). Optional extras: `agent-guard[langgraph]`, `agent-guard[mcp]`. Core install needs no cloud credentials or API keys.

---

## Product principles (non-negotiable)

1. **Default deny.** Unknown tools are denied. Policy `default` must be `deny` (omitted means deny). Fail closed at load time: invalid policy raises `PolicyError` and nothing starts.
2. **Schema before policy before side effects.** Arguments are validated with Pydantic (`extra="forbid"`) before any policy decision or approval row. A smuggled field must never influence governance or reach a tool body.
3. **Four-eyes for approvals.** The proposer cannot approve their own action. They may reject (withdraw). Actor ids are host-supplied strings; this library does not authenticate them.
4. **Enforce only on the wired path.** The host must route tool calls through `Guard`. A function the model can import directly is unprotected — do not claim otherwise in docs or APIs.
5. **Auditable decisions.** Every schema rejection, policy decision, human decision, expiry, and execution result is one hash-chained audit record. Prefer hashes of arguments in the log; keep raw args where a person must read them (approval store).

---

## Engineering standards

- **Typed code.** Type hints on public functions and methods. Pydantic models (typically `extra="forbid"`) at tool-argument boundaries. Package ships `py.typed`.
- **Tests as the spec.** Prefer known-answer cases for policy effects, state transitions, idempotency keys, and audit verification. Cover happy path, deny, pending, self-approval, and failure/retry where relevant.
- **Green before PR.** Pinned `ruff` (`check` + `format --check`), `mypy src`, and `pytest` must pass locally. CI must stay green.
- **Small, focused PRs.** One concern per PR; clear title and description; state assumptions and out-of-scope items.
- **No secrets in git.** Use environment variables or a secret manager. Never commit API keys, credentials, private keys, or tokens in code, config, examples, or remotes. Optional LLM demo reads `OPENAI_API_KEY` from the environment only.
- **Pin versions for release-bound work.** Prefer pinned tool versions in CI (`ruff`, `pytest`). Do not silently bump model or dependency pins in an unrelated feature PR.
- **Structured logging.** Use the library logger (`logging.getLogger("agent_guard")`) with key=value style fields (`tool`, `decision`, `outcome`, `action`, `actor`). Do not log secrets or full argument payloads when a hash suffices.
- **AI / LLM outputs are untrusted.** Model plans (e.g. `AGENT_GUARD_LLM=1` in the AP example) never bypass the guard. Evaluate agent behaviour with the red-team suite; never trust LLM output blindly.
- **Docs track behaviour.** Update README / `docs/design.md` / ADRs / this file / CHANGELOG when behaviour, contracts, or run instructions change. Do not invent features or deployment claims.

### Definition of done

- [ ] Principles above respected (default deny, schema-first, four-eyes, wired-path honesty, audit)
- [ ] Types and Pydantic contracts in place at tool boundaries
- [ ] Tests added or updated; known-answer cases for policy/state/audit changes
- [ ] Lint and tests pass (`ruff` / `mypy` / `pytest` or CI equivalents)
- [ ] No secrets introduced
- [ ] Docs updated if behaviour or workflow changed

---

## How to run and test

### Setup

```bash
python -m pip install -e ".[dev]"
```

Optional extras for integration sketches: `pip install -e ".[langgraph]"` / `".[mcp]"`. Python 3.10 or newer.

### Run (examples)

```bash
python examples/ap_agent/main.py          # scripted; no API key
python examples/langgraph_example.py
python examples/mcp_example.py
agent-guard --help
```

`AGENT_GUARD_LLM=1` plus `OPENAI_API_KEY` asks a model for a plan in the AP example; the guard still wraps every call.

### Test and lint

```bash
ruff check . && ruff format --check .
mypy src
pytest
pytest --agent-guard-redteam    # red-team eval gate (deterministic; no API key)
```

Coverage is configured in `pyproject.toml` (`--cov-fail-under=90`). CI runs the same on Python 3.10, 3.11, and 3.12, plus a dedicated red-team job.

### Pre-commit (optional, recommended)

```bash
pip install pre-commit
pre-commit install
```

See [CONTRIBUTING.md](CONTRIBUTING.md).

---

## Workflow for agents

1. **Read before writing.** Inspect the real layout, `docs/design.md`, ADRs, and neighbouring tests. Prefer matching existing patterns over inventing new ones.
2. **Plan large changes.** For multi-file or cross-cutting work, outline the approach, files touched, and risks before coding. Keep scope to the assigned task.
3. **Do not weaken tests.** Never delete, skip, or loosen assertions solely to make CI pass. Fix the code or add a justified, documented test change.
4. **State assumptions in the PR.** Call out env expectations, optional extras, and anything left as follow-up.
5. **Docs/config-only vs library code.** If the task says docs/config only, do not change application behaviour.
6. **Cursor rules.** Follow `.cursor/rules/*.mdc`; they summarise this file for scoped globs. When in conflict, **this file wins**.

---

## Related docs

- [CONTRIBUTING.md](CONTRIBUTING.md) — short human setup and PR conventions
- [README.md](README.md) — product overview and quick start
- [docs/design.md](docs/design.md) — policy, state machine, audit design
- [docs/decisions/](docs/decisions/) — decision records
- [CHANGELOG.md](CHANGELOG.md)
