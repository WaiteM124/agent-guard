# Design notes

These are the decisions behind agent-guard 0.1, written so they can be explained without the code open. The library is a local check in the host process. It is not a service, and it does not claim a deployment history.

## What problem the order solves

A tool call is not a transaction. The model can ask for a write. Three separate checks decide whether that write happens, and the order is the design:

1. **Schema.** Arguments are validated against a Pydantic model with `extra="forbid"`. A malformed call, or one with a surprise field such as `approved: true`, is rejected and logged. No approval row is created and the function is not called.
2. **Policy.** A known tool is `allow`, `require_approval`, or `deny`. Conditions on the arguments can override that, first match wins. Anything not listed is deny.
3. **Approval, then execution.** Only `require_approval` enters the state machine. `allow` runs immediately. `deny` stops. Execution is a separate step from the human decision, so a crash after approval can be retried without asking again and without inventing a second payment.

Doing policy before validation would let a smuggled field influence the decision. Doing execution inside the approval click would force the CLI, which does not have the tool functions, to perform the side effect. The CLI only changes state. The process that registered the function calls `execute`, or the agent repeats `call` with the same arguments after approval.

## Policy file

The policy is YAML, loaded and rejected at startup. Version must be 1. `default` must be `deny` (that is also the default when the key is omitted). Unknown keys are errors. Duplicate keys are errors; PyYAML's usual last-key-wins behaviour would let a later stanza silently override an earlier one.

Effects are per tool. Conditions are a small expression language: comparisons, `and` / `or` / `not`, and `in`. There is no `eval` and no function call syntax. That is deliberate. A policy file that can call Python is an application, not a policy.

A missing field does not satisfy a comparison, including `!=`. Validation runs first, so required fields are present by the time the policy sees the arguments. Optional fields are the remaining case, and `not` on a missing field flips the false comparison to true. The README tells authors to prefer positive conditions. At registration, every name the policy mentions must be a field on that tool's schema, which catches typos before the process serves traffic.

`approval_ttl` is how long a person has to answer. It starts when the action enters `awaiting_approval`. It is not an execution timeout. Once someone has approved, a slow tool must not expire that decision out from under them.

The accounts-payable example is the shape this is aimed at:

- `read_invoice` is `allow`. Reading is not the side effect we are governing.
- `create_supplier` is `require_approval`. A new bank account changes who can be paid.
- `make_payment` is `require_approval`, with `amount > 1000` denied and `amount <= 0` denied. Up to 1000 is allowed only after a person says so.

Amounts in the example are integers. The condition evaluator will coerce numeric strings, but money should not be a binary float. The schema is the right place to refuse floats if a tool needs exact decimal values. This library does not impose one money type on every tool.

## State machine

```text
proposed -> awaiting_approval -> approved | rejected | expired
approved -> executed | failed
failed   -> executed | failed
```

`proposed` is the moment the record is created. The gateway submits it for approval in the same transaction, so callers normally observe `awaiting_approval`. The history still contains both steps.

Terminal states `rejected`, `expired`, and `executed` do not move. `failed` is the exception, and it is retryable. If the downstream call raises, the action stays `failed` and a later `execute` calls the function again. The idempotency key is still held, so the agent cannot "retry" by proposing a second payment with the same arguments.

The key is SHA-256 of `actor + tool + canonical JSON`. Canonical JSON sorts keys and rejects `NaN`. `{"b": 1, "a": 2}` and `{"a": 2, "b": 1}` are the same action. Two actors proposing the same payload are different actions, because the person accountable is part of the identity.

Which states hold the key:

| State | Holds the key? | Why |
| --- | --- | --- |
| `awaiting_approval`, `approved` | yes | The write is in flight. A duplicate request must join it. |
| `executed` | yes | The write happened. A duplicate must return the stored result, not run again. |
| `failed` | yes | The write was attempted and did not succeed. Retry the same action. |
| `rejected`, `expired` | no | The write did not happen. A later request is a new decision. |

Releasing the key on rejection is what makes "withdraw and try again" possible. Keeping it on failure is what stops a retry storm from doubling the payment.

Four-eyes: `resolved_by` must differ from `actor_id` when the decision is approval. The proposer may reject their own request. If the window has already elapsed, the resolve call expires the action instead of approving it, including when the caller is the proposer. Expiry wins over the self-approval error so a late click cannot be interpreted as a policy breach; the action is simply closed.

The in-memory backend is the default and is what tests use. The JSON file backend is the same interface with an atomic replace and a lock file, so `agent-guard approve` in another process can see the queue. A lock older than 30 seconds is treated as abandoned. That is enough for a single operator. It is not a distributed queue.

Execution holds the backend transaction for the duration of the tool call. A slow payment blocks other decisions on that store. v0.1 accepts that in exchange for not running the tool twice. There is no async API.

## Audit chain

Each record stores the SHA-256 of its own fields plus the previous record's hash. The fields are the ones an investigator needs: when, which action, who asked, which tool, the hash of the arguments, the decision, who decided, why, and what the outcome was. The arguments are not copied into the log. They live on the approval record, because the approver has to read them, and the log stays shareable.

Verification walks the file and recomputes every hash. Changing a reason, or deleting a row in the middle, breaks the chain. Deleting the tail does not: the remaining prefix is still a valid chain. Replacing the whole file with a freshly hashed log also verifies. `agent-guard audit head` prints the latest hash so it can be stored somewhere the agent cannot write, and `verify --expect` checks that pin. v0.1 does not sign records or anchor them to an external timestamp.

Both sinks implement the same `AuditSink` and the same bytes for a record. JSONL is the default because it is obvious in a demo. SQLite is there when a host wants a file that concurrent readers can query. The chain rules do not change between them.

A decision that never becomes an approval (schema failure, deny, unknown tool) still gets a record. Its action id is a fresh id for that decision, not a row in the approval store. Approval, rejection, expiry, execution, failure, and idempotent replay each get their own line, so a later reader can reconstruct the sequence without trusting the process that claims it happened.

## What was adapted

The approval transitions, the idempotency key, and the rule that schemas use `extra="forbid"` before any governance state is created follow the reference implementation in `governed-agent-toolkit` (`approval_gate.py`, `tool_schemas.py`, `governed_write.py`). That repository is a single-purpose gate around two write tools. This one is an importable library:

- The tool set and the effects come from a policy file, not from constants in the module.
- `failed` is a real state. The reference left a failed call in `approved` and retried from there. Making failure visible matters once more than one tool exists and the audit log has to say what happened.
- The approval store is an interface. Memory and a JSON file both ship. The CLI talks to the file.
- The audit log is a hash chain with two sinks, not a list of transitions hanging off the action alone. The action history is still there, for the approver looking at one row. The log is the cross-action record.
- Red-team scenarios and the LangGraph / MCP wrappers are new. They are thin on purpose. The enforcement is the guard, not the framework.

Duplicate detection from the reference was not carried over. It is a product rule for master-data writes, not a property of governed tool execution. A host that wants it can put it in the tool or in a condition.

## What this does not do

The guard cannot see a call that never reaches it. Four-eyes compares actor strings; it does not prove the second string is a different human. The file lock is local. The hash chain is integrity against tampering of a log you still hold, not non-repudiation against the person who can rewrite the file. Those are the boundaries to state before describing the library as "agents under auditable human control." The control is real only on the path the host actually wired through `Guard.call`.
