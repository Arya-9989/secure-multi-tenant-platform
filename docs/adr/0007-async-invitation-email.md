# ADR 0007: Asynchronous invitation email through a transactional task queue

- Status: accepted
- Date: 2026-10-23

## Context

Creating an invitation sent its email inside the request, from an `on_commit` hook. A slow
or failing SMTP server made the request slow, a failure was only logged ("the admin can
share the link"), nobody could see whether an invitation had been delivered, and a crash
between the commit and the hook lost the email silently.

## Options considered

- **Celery or RQ on Redis.** Mature, but the job would be enqueued after the commit (the
  same lost-email window), it is another moving part with its own retry and visibility
  semantics, and its workers know nothing about row-level security.
- **Django 6's task framework with a database backend (chosen).** `django.tasks` gives the
  standard `@task` / `.enqueue()` API; Django ships no production backend, so the platform
  provides one: `apps.tasks.backend.DatabaseBackend`, storing tasks in PostgreSQL.

## Decision

- **Transactional enqueue (outbox).** `enqueue()` inserts the task row in the caller's
  transaction. The invitation and its email task commit together or not at all.
- **Tenant scope travels with the task.** The row records the database scope it was
  enqueued under (ADR 0001): the tenant, or the platform. The worker claims tasks in a short
  platform-scoped transaction and runs each one in its own recorded scope, so a task sees
  exactly what the request that queued it could see.
- **Worker.** `manage.py run_worker` claims ready tasks with `SELECT ... FOR UPDATE SKIP
  LOCKED`, so several workers never take the same task, and leases them
  (`lease_seconds`): a task whose worker died is claimed again when its lease expires. It
  stops on SIGTERM after the task in hand. Priorities and `run_after` (deferral) are
  supported, and results and errors are kept on the row (`get_result()` works).
- **Retries.** A failed task is retried with exponential backoff and jitter (`base_delay`
  doubling up to `max_delay`, `max_attempts` attempts in all); raising `PermanentTaskError`
  fails it at once. Finished tasks are deleted by `manage.py prune_tasks` after a week.
- **Idempotency.** An identical task (same function, arguments and scope) is not enqueued
  twice while one is still waiting or running: a partial unique index on a hash of the three
  makes the second `enqueue()` return the first. The same task for another tenant is another
  task. The email task itself is idempotent: it does nothing
  for an invitation already sent, revoked, accepted or expired, or whose token has been
  replaced since, and it sends a stable `Message-ID`. Delivery is at-least-once: a crash
  after the SMTP server accepted the message and before the status is saved means one
  duplicate, which the `Message-ID` lets mail systems recognise.
- **Delivery status on the invitation.** `email_status` (`queued`, `sent`, `failed`,
  `skipped`), `email_attempts`, `email_sent_at` and a short `email_last_error`, all in the
  API. The final failed attempt marks the invitation `failed`.
- **The raw token.** The email needs the token, and only its hash is stored. The task's
  argument is therefore the token encrypted with `FIELD_ENCRYPTION_KEYS`, never the token
  itself; it is useless without the key, expires with the invitation (72 hours), and the
  row is pruned. `POST /invitations/{id}/resend/` issues a new token (the old link stops
  working) and queues a new email, which also covers a failed delivery.
- **Mail.** Plain SMTP with a timeout (`EMAIL_TIMEOUT`). Locally Mailpit receives
  everything; nothing ever goes to a real address.

## Consequences

- Creating an invitation no longer waits for SMTP, and its delivery is visible and retried.
- Email needs a running worker: the compose stack starts one. Without it, invitations stay
  `queued` and their link can still be shared from the API response.
- Polling the task table costs one indexed query per idle interval per worker.
