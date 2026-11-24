## Summary

<!-- What changed and why. State assumptions and out-of-scope items. -->

## Checklist

- [ ] **Principles respected** — default deny; schema before policy/side effects; four-eyes; no overclaiming host wiring; audit retained ([AGENTS.md](../AGENTS.md))
- [ ] **Tests added or updated** — known-answer cases where policy, approval, or audit behaviour changes; existing tests not weakened or deleted to pass
- [ ] **Tests and lint passing** — `ruff check` / `ruff format --check`, `mypy src`, and `pytest` (CI green); red-team gate when governance paths change
- [ ] **No secrets** — no API keys, credentials, or private keys in code, config, or this PR
- [ ] **Docs updated** — README / design notes / ADRs / `AGENTS.md` / `CONTRIBUTING.md` / CHANGELOG updated if behaviour or workflow changed

## Test plan

<!-- Commands run locally, or "rely on CI". -->
