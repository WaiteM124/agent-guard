# ADR-002: Default-deny YAML policy with a restricted condition language

**Status:** Accepted  
**Date:** 2026-11-22  
**Source:** Reconstructed from code (`docs/design.md`, `policy.py`)

---

## Context

Hosts need a readable, file-based way to say which tools may run, which wait for a human, and which are forbidden — including simple argument conditions — without turning the policy file into an application.

## Decision

- Policy is YAML, version `1`, loaded and rejected at startup (`PolicyError`).
- `default` must be `deny` (omitted means deny). Unknown tools are denied. Unknown/duplicate keys are errors.
- Per-tool `effect` is `allow`, `require_approval`, or `deny`. Optional `conditions` are first-match overrides.
- Conditions use a small expression grammar (comparisons, `and` / `or` / `not`, `in`). **No function calls and no `eval`.**

## Alternatives rejected

- **Default allow** — unsafe for agent tool surfaces; fail-open is incompatible with the library’s purpose.
- **Embedding Python / `eval` in policy** — turns policy into code execution and expands the attack surface.
- **Hard-coded tool lists in the library** — the reference `governed-agent-toolkit` style does not scale to an importable, multi-tool library.

## Consequences

- Invalid policy fails closed before serving traffic.
- Authors must prefer positive conditions; a missing optional field makes comparisons false (including `!=`), so `not` on optionals is easy to misuse (documented in README).
- Richer condition languages, multi-tenant policy, and remote policy services are out of scope for v0.1.
