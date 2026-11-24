# Decision records

Lightweight architecture / product decision records for **agent-guard**.

## Format

Each record is a Markdown file named `ADR-NNN-short-title.md` (zero-padded number) and uses these sections:

1. **Context** — the problem or force that required a choice.
2. **Decision** — what we chose, stated as a concrete rule the codebase should follow.
3. **Alternatives rejected** — serious options we considered and why they were not chosen.
4. **Consequences** — what becomes easier, harder, or out of scope as a result.

Also include a short header: **Status** (`Accepted` / `Superseded` / `Proposed`), **Date**, and whether the write-up was **reconstructed from code** (reasoning inferred from implementation and `docs/design.md` rather than written at the time of the change).

## Index

| ADR | Title | Status |
| --- | --- | --- |
| [001](ADR-001-schema-before-policy.md) | Schema validation before policy and side effects | Accepted |
| [002](ADR-002-default-deny-policy-language.md) | Default-deny YAML policy with a restricted condition language | Accepted |
| [003](ADR-003-hash-chained-audit.md) | Unsigned hash-chained audit log | Accepted |

Narrative design background (not ADR-shaped): [../design.md](../design.md).
