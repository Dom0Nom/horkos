# GDPR Article 17 — Deletion Route Rollout Plan

## Phase 2 contract (current)

`DELETE /api/account/{id}/data` returns:
- `503 Service Unavailable`
- `Retry-After: 86400`
- Body: `{"status":"unavailable","reason":"deletion service not yet provisioned"}`

The route is wired and reachable so clients can compile against the URL surface.
The contract makes no promise the persistence layer cannot honor (risk register
entry R10).

## Flip phase (follow-up under /tdd)

The contract flips to `202 Accepted` + 30-day SLA only after these prerequisites land:

1. **Durable persistence layer** — Postgres or SQLite-WAL (decided in the flip phase).
2. **Deletion worker** — background job that processes deletion requests against
   the persistence layer, deletes from blob stores, and emits a completion event.
3. **Append-only audit log** — every deletion request and completion event is
   recorded with a tamper-evident hash chain.
4. **Test coverage under /tdd** — at minimum:
   - 202 contract test on the route.
   - Worker drains the queue under load.
   - Audit log integrity: cannot delete entries; hash chain validates.
   - Replay test: a worker restart never re-processes a completed request and
     never drops an in-flight request.
5. **Doc update** — this file is updated to point at the new contract and link
   to the chosen persistence implementation.

## Operator-of-record

Horkos Service Operator processes deletion requests on behalf of the data
controller (the game studio shipping the SDK). The studio remains the
controller; Horkos is the processor under Article 28 of the GDPR.

## Out of scope (future phases)

- Right of access (Article 15) — separate route under `/api/account/{id}/data`
  with `GET` semantics.
- Data portability (Article 20) — separate export endpoint.
