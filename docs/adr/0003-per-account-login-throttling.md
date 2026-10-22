# ADR 0003: Per-account login throttling with progressive delays

- Status: accepted
- Date: 2026-10-23

## Context

Sign-in is rate-limited per client IP (`THROTTLE_AUTH`, 10/min), keyed on the same address
the audit log records so a forged `X-Forwarded-For` cannot reset it. A per-IP limit does
nothing against a distributed attacker: a botnet with a thousand addresses gets ten thousand
guesses a minute against one account. The usual answer, locking the account after N
failures, hands that same attacker a different weapon: lock out any user whose email they
know, from anywhere, for free. Per-account protection has to slow guessing down without
letting a stranger keep a victim out.

The two ways to lock someone out are:

1. **Fail on their behalf** until a hard lock or a long delay applies to everyone who tries
   that account, the victim included.
2. **Win the race** for whatever attempts the throttle still allows (for example the one
   attempt allowed when a delay expires), so the victim's own attempt is the one rejected.

## Options considered

- **Hard lockout after N failures.** Defeats guessing and gives every attacker a free
  denial of service. Rejected.
- **Throttle on (account, IP) pairs only.** No lockout DoS, but no protection against the
  distributed attack either. Rejected as the only control.
- **CAPTCHA after failures.** Effective, but needs a third-party service. Out of scope.
- **Progressive delays per account, plus device tokens (chosen).** This is the OWASP
  "device cookie" pattern: a browser that has signed in successfully to an account before
  carries a signed token proving it, and its attempts are counted separately from everyone
  else's.

## Decision

- **Buckets.** An attempt is counted against the account (keyed by an HMAC of the normalised
  email, so cache keys hold no addresses) unless it carries a valid device token for that
  account, in which case it is counted against that device alone. The per-IP limit applies
  to every attempt on top.
- **Progressive delay, no lockout.** The first `LOGIN_ACCOUNT_FREE_ATTEMPTS` (5) attempts in a
  bucket are evaluated freely. After that, each evaluated attempt starts a delay before the
  next one: `LOGIN_ACCOUNT_BASE_DELAY_SECONDS` (2) after the sixth, then 4, 8, ... doubling up
  to `LOGIN_ACCOUNT_MAX_DELAY_SECONDS` (900). Attempts during a delay get `429` with
  `Retry-After` and are **not evaluated**, so they cannot be used to guess. The count resets
  on a successful sign-in in that bucket and expires after `LOGIN_ACCOUNT_WINDOW_SECONDS`
  (24 h).
- **Race-safe.** The count holds evaluated attempts only. A free attempt reserves its place
  with an atomic increment before the password is checked (and gives it back if a burst
  overshot the limit); a later attempt must win an atomic `add` of the delay gate, whose length
  follows from the evaluated count. A burst of parallel requests therefore gets exactly the
  attempts twenty sequential ones would, and cannot inflate the delay. Tested with 20 threads
  against the in-process cache and 16 against Redis.
- **Device tokens.** A successful sign-in sets `login_device`, an HttpOnly, `SameSite=Strict`
  cookie holding a signed (`django.core.signing`, salted) token of the account's key and a
  random device ID, valid for `LOGIN_DEVICE_TRUST_DAYS` (90). A stolen device token only
  grants the device's own budget, which follows the same delays.
- **No enumeration.** Unknown emails get buckets exactly like real ones, so the sequence of
  `401` and `429` responses, their bodies and their timing (Django hashes a dummy password
  for unknown accounts) are the same whether or not the account exists.
- **Audit.** A failed attempt that started a delay records `next_attempt_delay` in its
  `auth.login_failed` event, attributed to the account's tenant as before. Rejected attempts
  are logged, not audited, so a flood cannot fill the audit table.
- **Admin.** The Django admin's sign-in uses the same buckets and the same device cookie.
- **Operators.** `manage.py clear_login_throttle <email>` clears an account's bucket, for a
  support case during an attack.

## Consequences

- A distributed attacker gets about 5 attempts and then at most one guess every 15 minutes
  per account, roughly 100 a day, against passwords of at least 12 characters.
- Someone who knows a victim's email can delay sign-ins **from new devices** by keeping the
  account bucket in its delay, and can compete for the single attempt allowed when a delay
  expires. They cannot affect the victim's devices that have signed in before, and they
  never cause a hard lock. This residual risk is accepted and documented; SSO and the
  operator command are the escape hatches.
- Counters live in the cache. With Redis (the compose stack) they are shared and atomic
  across workers; without `REDIS_URL` they are per process, like every other throttle.
