# ADR-003: Unsigned hash-chained audit log

**Status:** Accepted  
**Date:** 2026-11-22  
**Source:** Reconstructed from code (`docs/design.md`, `audit.py`)

---

## Context

Investigators need a durable record of schema failures, policy decisions, human decisions, expiry, and execution outcomes. The log should detect mid-file edits and deletions without requiring a hosted audit service in v0.1.

## Decision

- Every relevant event appends one JSON record with a SHA-256 over canonical fields plus the previous record’s hash (genesis of 64 zero hex digits).
- Argument **hashes** appear in the log; raw arguments stay in the approval store where a person must read them.
- Two sinks share the same record bytes and chain rules: JSONL (default) and SQLite (`.sqlite` path).
- CLI `audit verify` recomputes the chain; `audit head` / `verify --expect` support an out-of-band pinned head. **v0.1 does not sign records.**

## Alternatives rejected

- **Audit only on the approval row** — cross-action investigation and shareable logs need a separate append-only stream.
- **Store full arguments in every audit line** — increases leakage risk when sharing logs; approvers already need args on the approval record.
- **Signed / externally anchored chain in v0.1** — valuable, but out of scope for the first release (roadmap).

## Consequences

- Mid-chain edits fail verification; truncating the tail still leaves a valid shorter chain unless a head hash is pinned.
- A holder who can rewrite the whole file can forge a fresh valid chain — hosts should pin `head` somewhere the agent cannot write.
- Signed checkpoints remain a documented roadmap item, not a current guarantee.
