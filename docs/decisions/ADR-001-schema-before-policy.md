# ADR-001: Schema validation before policy and side effects

**Status:** Accepted  
**Date:** 2026-11-22  
**Source:** Reconstructed from code (`docs/design.md`, `guard.py`)

---

## Context

A tool call from an agent is not a transaction. Malformed arguments or smuggled fields (for example `approved: true`) must not influence whether a write happens, create approval rows, or reach tool bodies.

## Decision

Every governed call is processed in this order:

1. **Schema** — validate arguments against a Pydantic model with `extra="forbid"`. On failure: audit, return invalid; no approval row; tool not called.
2. **Policy** — decide `allow`, `require_approval`, or `deny` for a known tool (unknown → deny).
3. **Approval / execution** — only `require_approval` enters the state machine; `allow` may run the tool; `deny` stops. Human decision and execution are separate steps.

## Alternatives rejected

- **Policy before schema** — would let undeclared fields participate in conditions and decisions.
- **Execute inside the approve CLI click** — the CLI does not hold tool functions; the process that registered the tool must `execute` (or re-`call` after approval).
- **Trust the model to omit extra fields** — agents and wrappers routinely add metadata; forbid-extra is the contract.

## Consequences

- Tool authors must supply a schema at registration; policy field names are checked against that schema at register time.
- Invalid calls are auditable without polluting the approval queue.
- Hosts that bypass `Guard` get no protection — enforcement is only on the wired path (see product principles in `AGENTS.md`).
