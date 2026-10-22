# ADR 0006: Audit log hash chains, partitioning, retention and SIEM streaming

- Status: accepted
- Date: 2026-10-23

## Context

The audit log is append-only at three levels (model, QuerySet, a PostgreSQL trigger), and the
API's database role cannot update, delete or truncate it (ADR 0001). That stops the
application. It does not stop someone with the schema owner's credentials, a restored and
edited backup, or a direct edit of the data files, and if any of those happened nobody would
know. The table also grows without bound, and security teams want these events in their
SIEM, not in a table only this application can query.

## Decision

### Hash chains (tamper evidence)

- **One chain per tenant, plus one for platform-level events.** A single global chain would
  serialise every audit write in the system and could not be computed under row-level
  security, where a tenant's transaction cannot see other tenants' rows. Per-tenant chains
  keep both properties and let a tenant's chain be verified on its own.
- Each row gets `chain_seq` (gapless, from 1), `prev_hash` and `hash` =
  HMAC-SHA256(`AUDIT_CHAIN_KEY`, canonical JSON of every content field and `prev_hash`).
  The key lives outside the database (derived from `DJANGO_SECRET_KEY` when unset), so
  someone who can rewrite rows still cannot recompute valid hashes.
- `record()` appends under a per-chain transaction-scoped advisory lock
  (`pg_advisory_xact_lock`), reads the chain's head, and sets `created_at` inside the lock,
  never earlier than the head's, so sequence order and time order agree within a chain.
  Concurrent writers to one tenant queue for microseconds; different tenants never wait for
  each other.
- `manage.py verify_audit_chain` walks every chain in sequence order and reports, with row
  IDs, a **modified** row (hash mismatch), a **deleted** row (sequence gap or broken link), a
  **reordered or re-linked** row (`prev_hash` not the previous row's hash), a duplicated
  sequence number, and a chain whose head is behind what was already streamed to the SIEM
  (**truncated tail**). It exits non-zero on any finding.

### Time-based partitioning and retention (PostgreSQL)

- The table becomes `PARTITION BY RANGE (created_at)` with monthly partitions and a default
  partition, so no insert can fail for want of one. The primary key is `(id, created_at)`,
  as PostgreSQL requires; IDs are UUID4. The append-only trigger, row-level security and the
  runtime role's `SELECT, INSERT`-only grant are on the parent; the runtime role has no
  privilege on any partition, so partitions cannot be read around the policies.
- `manage.py audit_partitions --months-ahead N` creates upcoming partitions (run it monthly;
  the migration creates the current month and twelve ahead). It refuses to create a month
  that already has rows in the default partition, rather than move them silently.
- `manage.py audit_retention --keep-months N` (as the owner) drops whole partitions older
  than the cutoff. First it records, for every chain with rows in them, a **checkpoint**: the
  last sequence number and hash being dropped. Verification then starts each chain from its
  latest checkpoint, so a retention cut is distinguishable from a deletion. The retention run
  is itself an audited, platform-level event. `--dry-run` reports what would go.

### Streaming to a SIEM

- `manage.py stream_audit_log` ships events to `AUDIT_SIEM_URL` as newline-delimited JSON,
  signed with HMAC-SHA256 (`X-Audit-Signature: sha256=...`, key `AUDIT_SIEM_SECRET`), with
  timeouts and exponential backoff with jitter. It keeps one cursor per chain (the last
  sequence number delivered) and reads each chain in sequence order, so delivery is
  at-least-once, in order, and resumes exactly where it stopped; every event carries its
  `id` and `hash` for deduplication. Since commits within a chain happen in sequence order
  (the lock is held to commit), a cursor never skips an event that commits later.
- The SIEM's copy anchors the chain outside the database: an attacker who rewrites history
  and recomputes the chain (which already needs the HMAC key) is still contradicted by the
  events and hashes the SIEM already holds, and a truncated tail is visible against the
  cursors.
- Locally, Vector (`docker compose --profile siem`) receives the stream on an HTTP source
  and writes it to a file, standing in for Splunk, Elastic or Loki behind it.

## Consequences

- Audit writes for one tenant are serialised. They are low-volume (sign-ins and admin
  actions) and the lock is held only until the surrounding transaction commits.
- `AUDIT_CHAIN_KEY` must stay stable; rotating it requires a checkpoint and a new chain
  generation, which is not built yet. The key is as sensitive as the signing key.
- Django's migration framework does not model partitioned tables; the conversion is a
  hand-written, reversible migration, and later schema changes to the audit table need the
  same care. SQLite (local development) keeps a plain table and has no retention command.
- Tail truncation that happens before an event was streamed cannot be detected by the chain
  alone; streaming continuously keeps that window small.
