# Changelog

## 0.1.0 - 2026-11-22

First release.

- YAML policy with `allow`, `require_approval`, and `deny`, default deny, and a small condition language.
- Strict Pydantic validation before any policy decision or side effect.
- Approval state machine with four-eyes, expiry, idempotency keys, and a retryable `failed` state.
- In-memory and JSON-file approval stores, plus `agent-guard approve`, `reject`, and `list`.
- Hash-chained JSONL and SQLite audit logs, with `agent-guard audit verify` and `audit head`.
- Red-team helper and pytest plugin.
- Thin LangGraph and MCP wrappers.
- Scripted accounts-payable example that does not need an API key.
