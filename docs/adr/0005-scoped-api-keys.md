# ADR 0005: Scoped API keys for service-to-service access

- Status: accepted
- Date: 2026-10-23

## Context

Services that integrate with a tenant (a SIEM pulling the audit log, a directory sync, a
reporting job) currently have to sign in as a person: a shared password, MFA that cannot be
completed by a machine, and a session that carries the person's whole role. A credential for
software should belong to the organization rather than to a person, carry only the access it
needs, expire, be rotatable without downtime, and be revocable on its own.

## Decision

- **Tenant-bound keys.** An `ApiKey` belongs to one organization and is created by its admins
  (new permission `api_key:manage`; super admins may create one for any organization). A key
  sees exactly what a member of that organization would see, through the same
  `visible_to()` scoping and the same row-level security (ADR 0001): authenticating a key
  binds its tenant's database scope.
- **Format and storage.** `mtk_<prefix>_<secret>`: a 12-character public prefix that
  identifies the row and a 256-bit secret. Only the SHA-256 of the secret is stored; with that
  much entropy no slow hash or pepper is needed, and the comparison is constant-time. The
  full key is returned once, at creation or rotation.
- **Scopes, enforced per endpoint.** Keys are read-only by design in this version: scopes are
  `organization:read`, `users:read`, `invitations:read` and `audit:read`. Each view declares
  which scope each action needs (`api_key_scopes`), and an action that declares none is
  refused to keys, which is the same fail-closed rule as `required_permissions`. A structural
  test fails the build if a view grants a key an unsafe method. Changes stay attributable to
  a person: every write requires a user session.
- **Lifecycle.** Keys expire (`expires_in_days`, default 90, at most 365). Rotation issues a
  new key with the same name and scopes and lets the old one keep working for a grace period
  of 0 to 1440 minutes, so a deployment can switch over without downtime. Revocation is
  immediate. Creation, rotation and revocation are audited (`api_key.created`,
  `api_key.rotated`, `api_key.revoked`).
- **Last use.** `last_used_at` and `last_used_ip` are updated at most once a minute per key
  (a conditional `UPDATE`), so a busy integration does not turn every read into a write.
- **Throttling.** A key is its own throttle identity (`apikey:<id>`) under the user rate.
- **Errors.** An unknown prefix, a wrong secret, an expired, revoked or rotated-out key and a
  deactivated organization all answer the same `401` "Invalid API key." A key's attempts on
  an endpoint its scopes do not cover answer `403`, and a foreign object `404`, as for users.

## Consequences

- Integrations get least-privilege, tenant-bound, expiring credentials that can be rotated
  with overlap, and every key's lifecycle is in the audit log.
- Write access for services is deliberately absent. Adding it later means giving every
  service function a non-human actor and an audit attribution model for it; the scope
  mechanism is ready for write scopes when that exists.
- A key is a bearer credential: anyone holding it has its scopes until it expires or is
  revoked. It is shown once and never stored in recoverable form.
