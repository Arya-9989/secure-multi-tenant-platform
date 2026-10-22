# ADR 0002: Refresh-token families with reuse detection

- Status: accepted
- Date: 2026-10-23

## Context

Refresh tokens rotate: every `POST /auth/refresh/` returns a new pair, and the old refresh
token was blacklisted through SimpleJWT's `token_blacklist` app. That stops a token from
being redeemed twice, but it does not answer the important question: *what does it mean when
an already-rotated token comes back?* Only two parties ever held it, the legitimate client
and whoever stole it. One of them is presenting a token it should no longer have, and the
server cannot tell which. The OAuth 2.0 Security Best Current Practice (RFC 9700, section
4.14.2) recommends treating that as a compromise and revoking the whole chain of tokens
descended from the original login, so that the thief's copy and the victim's copy both stop
working and the user signs in again.

The blacklist design had further gaps:

- it stored every issued refresh token verbatim (`OutstandingToken.token`), so a database
  read exposed live credentials;
- logging out one session left that session's access token valid for up to five minutes;
- the claim was atomic only through a unique-constraint trick in `RefreshSerializer`.

## Options considered

**A. Keep the blacklist and add reuse detection on top.** A blacklisted token being presented
again is the reuse signal, but finding "every descendant" means walking a parent chain of
outstanding tokens. It keeps the raw tokens at rest.

**B. A family row per login, holding only the current token's ID (chosen).** One row per
session. The refresh token carries the family ID (`fam`), its own ID (`jti`) and its
generation (`gen`). A token is redeemable only if its `jti` equals the family's
`current_jti`. Since every token of a family is signed by us, a valid signature with a
different `jti` can only be an older token of that same family, so no history is needed.

**C. Opaque refresh tokens stored hashed.** Equivalent security, but a larger change to the
client contract and to SimpleJWT's role here.

## Decision

- **`RefreshTokenFamily`** (`apps/accounts/models.py`): user, organization (denormalised for
  tenant scoping and row-level security), `current_jti`, `generation`, creation time, IP and
  user agent, last rotation, an absolute expiry (`JWT_SESSION_MAX_AGE_DAYS`, default 30) and
  revocation time and reason. No token is ever stored.
- **Rotation is a compare-and-swap**:
  `UPDATE ... SET current_jti = new, generation = generation + 1 WHERE id = fam AND
  user_id = sub AND current_jti = presented AND revoked_at IS NULL AND expires_at > now()`.
  Exactly one of any number of concurrent requests can move a family forward. Under READ
  COMMITTED a racing `UPDATE` waits for the winner's commit, re-reads the row and matches
  nothing. No two valid successors can ever exist.
- **A non-matching `jti` on a live family is reuse.** The family is revoked with a
  conditional `UPDATE ... WHERE revoked_at IS NULL` (so exactly one request records it), an
  `auth.refresh_reuse_detected` audit event is written for the account's tenant, and the
  request gets the same generic `401` as any other invalid token. The revocation commits even
  though the request fails.
- **Concurrent refreshes with the same token are reuse too.** One wins, the others revoke the
  family, and the winner's new tokens die with it. This is the strict reading of the BCP and
  is deliberate: a grace window that hands the same token out twice is exactly the window a
  thief needs. Clients must serialise their refreshes (single-flight), which is standard
  guidance.
- **Access tokens carry `fam`, and authentication checks it.** The family must exist, belong
  to the user, be unrevoked and unexpired. That check is folded into the user lookup every
  request already makes (one `EXISTS` subquery, no extra round trip), so revoking a family
  ends its access token immediately. Logging out a single session no longer leaves a
  five-minute window.
- **Logout** revokes the presented token's family; **logout-all**, password changes,
  deactivation and organization deactivation revoke every family of the affected users and
  bump `token_version` as before.
- SimpleJWT stays for signing and validation. Its `token_blacklist` app is removed, and a
  migration drops its tables, which held raw refresh tokens.
- `manage.py prune_sessions` deletes families that ended (revoked or expired) more than
  `--days` ago.

## Consequences

- A stolen refresh token is useful only until the next refresh by either party; after that,
  both copies are dead and the account's administrators can see the event in the audit log.
- Two tabs refreshing at the same moment with the same token log the user out. That is the
  price of the strict policy, documented for client authors.
- Every authenticated request still costs one database query; it now also proves the
  session is alive.
- Tokens issued before this change carry no `fam` claim and are rejected, so existing
  sessions end once at deploy time.
