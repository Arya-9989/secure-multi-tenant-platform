# ADR 0004: Multi-factor authentication (TOTP, WebAuthn) and SSO via OpenID Connect

- Status: accepted
- Date: 2026-10-23

## Context

Accounts are protected by a password alone. Organization admins can change roles, deactivate
users and read the audit log, so one phished password is a tenant-wide incident. Customers
also expect two things from a B2B platform: a second factor for every user, and single
sign-on through their own identity provider, configured by their own administrators.

## Decision: MFA

**Factors.** TOTP (RFC 6238) and WebAuthn (security keys, platform authenticators, passkeys
used as a second factor), plus single-use recovery codes. Any user can enrol; an
organization admin can reset a member's factors (`POST /users/{id}/reset-mfa/`), which also
ends the member's sessions.

**TOTP.** Implemented directly from RFC 6238 (HMAC-SHA1, 6 digits, 30-second steps, one step
of clock skew either side) and checked against the RFC's own test vectors. Secrets are
encrypted at rest with Fernet (`FIELD_ENCRYPTION_KEYS`, a `MultiFernet`, so keys can be
rotated). **Replay protection:** the device stores the last time step it accepted, and a
code is accepted only through a compare-and-swap `UPDATE ... SET last_used_step = s WHERE
last_used_step < s`. A code cannot be used twice, not even by two concurrent requests inside
its 30 seconds, and an older code cannot be used once a newer one has been.

**Recovery codes.** Ten codes of 60 random bits, shown once, stored as HMAC-SHA256 digests
keyed from the secret key (high-entropy codes need no slow hash; the key stops offline
guessing from a database dump). Using one is a single conditional `UPDATE`, so it is
consumed exactly once.

**WebAuthn.** `py_webauthn` (Duo Labs), a maintained, widely used implementation of the
specification, does the cryptography and the checks of origin, RP ID, challenge, user
presence and signature counter. The relying party is configured with `WEBAUTHN_RP_ID`,
`WEBAUTHN_RP_NAME` and `WEBAUTHN_ORIGINS`. Attestation is `none`: the platform does not
restrict authenticator models. A credential whose signature counter goes backwards is
refused (a cloned-authenticator signal) unless the authenticator does not count at all.

**Sign-in flow.** With MFA enabled, a correct password returns `200` with
`{"mfa_required": true, "mfa_token": ..., "methods": [...]}` and no tokens. The MFA token is
random, lives five minutes in the cache (keyed by its SHA-256), allows five attempts and is
deleted on success. The second step (`/auth/mfa/verify/` for a TOTP or recovery code,
`/auth/mfa/webauthn/begin/` and `/complete/` for WebAuthn) issues the session. The
per-account throttle (ADR 0003) counts second-factor failures in the same bucket as password
failures and is reset only by a complete sign-in, so knowing the password does not buy a
fresh budget for guessing codes. The device cookie is set only after both factors.
Enrolling, removing a factor and regenerating recovery codes require the current password.

## Decision: SSO via OpenID Connect

- **Per organization, configured by its admins.** `/api/v1/sso-providers/` (a tenant-scoped
  viewset, permission `sso:manage`, held by org admins and super admins) stores the issuer,
  client ID, client secret (encrypted, write-only) and an optional list of allowed email
  domains. One provider per organization.
- **Authorization code flow with PKCE (S256), state and nonce.** `GET
  /auth/sso/{organization-slug}/login/` stores a random state with the code verifier, nonce
  and organization (ten minutes, single use) and redirects to the IdP. The callback consumes
  the state, exchanges the code with the verifier and the client secret, and validates the ID
  token: signature against the provider's JWKS, an algorithm allow-list without `none` or any
  HMAC algorithm, `iss` equal to the configured issuer (also required of the discovery
  document, against mix-up attacks), `aud` containing the client ID (and `azp` when there are
  several audiences), `exp`, `iat` and the nonce. HTTP calls have timeouts and the discovery
  document is cached.
- **No just-in-time provisioning.** People still join through invitations, so the IdP vouches
  for an existing, active member of that organization: matched by the IdP's stable subject
  once linked, and on first use by a verified email (`email_verified` must be true) in an
  allowed domain. A subject linked to one user can never sign in as another.
- **Handing the session to the frontend.** The callback redirects to
  `FRONTEND_SSO_URL` with a one-time code (60 seconds, single use), which the frontend
  exchanges at `POST /auth/sso/exchange/` for the token pair. Tokens never appear in a URL.
  Failures redirect with a generic error and are audited with the specific reason.
- **Local and end-to-end runs** use Keycloak in compose (`--profile sso`), with a realm
  imported at start-up. An e2e test runs inside the compose network and drives the whole
  flow, including Keycloak's login form.
- SSO sign-ins skip the platform's own second factor: the IdP's policy applies.

## Decision: SAML deferred

SAML 2.0 was not built. The vetted Python libraries (`python3-saml`, `pysaml2`) depend on
`xmlsec1` and libxml2 native libraries, which would add a C toolchain to the image and to
every developer machine, and XML signature validation is where SAML implementations have
historically failed (signature wrapping, comment truncation). OIDC covers the same customer
need with every major IdP (Entra ID, Okta, Google, Keycloak). SAML can be added behind the
same provider model when a customer requires it, with the native dependencies pinned and an
attack-focused test suite of its own.

## Consequences

- A stolen password is no longer enough for accounts with MFA, and a stolen TOTP code is
  useless once used. Recovery codes are the only way past a lost device besides an admin
  reset, which is audited and ends the member's sessions.
- MFA secrets depend on `FIELD_ENCRYPTION_KEYS` (derived from the secret key when unset):
  losing the key loses the factors, which then need an admin reset.
- SSO relies on the IdP's availability; password sign-in stays available.
