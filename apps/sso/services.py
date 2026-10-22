"""SSO providers (managed by org admins) and the sign-in they vouch for (ADR 0004)."""

from __future__ import annotations

from typing import Any

from django.db import IntegrityError, transaction
from django.utils import timezone
from rest_framework.exceptions import ValidationError

from apps.accounts.authentication import user_can_authenticate
from apps.accounts.models import User, normalize_email
from apps.accounts.roles import Perm
from apps.auditlogs.models import AuditAction
from apps.auditlogs.services import record
from apps.common import crypto, rls
from apps.common.guards import require_permission, require_same_tenant
from apps.organizations.models import Organization
from apps.sso import oidc
from apps.sso.models import OidcProvider, SsoIdentity


# ---------------------------------------------------------------- administration
def create_provider(
    *, actor: User, organization: Organization, client_secret: str, **fields: Any
) -> OidcProvider:
    require_permission(actor, Perm.SSO_MANAGE)
    require_same_tenant(actor, organization)
    try:
        with transaction.atomic():
            provider = OidcProvider.objects.create(
                organization=organization,
                client_secret_encrypted=crypto.encrypt(client_secret),
                **fields,
            )
            record(
                AuditAction.SSO_PROVIDER_CREATED,
                actor=actor,
                organization=organization,
                target=provider,
                metadata={"issuer": provider.issuer, "client_id": provider.client_id},
            )
    except IntegrityError as exc:
        raise ValidationError(
            {"organization": ["This organization already has an SSO provider."]}
        ) from exc
    return provider


def update_provider(
    *, actor: User, provider: OidcProvider, changes: dict[str, Any]
) -> OidcProvider:
    require_permission(actor, Perm.SSO_MANAGE)
    require_same_tenant(actor, provider)
    secret = changes.pop("client_secret", None)
    changed = sorted(k for k, v in changes.items() if getattr(provider, k) != v)
    if secret is not None:
        changed.append("client_secret")
    if not changed:
        return provider
    with transaction.atomic():
        for field, value in changes.items():
            setattr(provider, field, value)
        if secret is not None:
            provider.client_secret_encrypted = crypto.encrypt(secret)
        provider.save()
        record(
            AuditAction.SSO_PROVIDER_UPDATED,
            actor=actor,
            organization=provider.organization,
            target=provider,
            metadata={"fields": changed},  # names only: never the secret
        )
    return provider


def delete_provider(*, actor: User, provider: OidcProvider) -> None:
    require_permission(actor, Perm.SSO_MANAGE)
    require_same_tenant(actor, provider)
    with transaction.atomic():
        record(
            AuditAction.SSO_PROVIDER_DELETED,
            actor=actor,
            organization=provider.organization,
            target=provider,
            metadata={"issuer": provider.issuer},
        )
        provider.delete()


# ---------------------------------------------------------------- sign-in
def provider_for_slug(slug: str) -> OidcProvider | None:
    """An enabled provider for an active organization, looked up before sign-in."""
    with rls.platform_scope():
        organization_id = (
            Organization.objects.filter(slug=slug, is_active=True)
            .values_list("pk", flat=True)
            .first()
        )
    if organization_id is None:
        return None
    with rls.tenant_scope(organization_id):
        return (
            OidcProvider.objects.select_related("organization")
            .filter(organization_id=organization_id, enabled=True)
            .first()
        )


def login_url(provider: OidcProvider) -> str:
    return oidc.begin(
        provider_id=str(provider.pk),
        organization_id=str(provider.organization_id),
        issuer=provider.issuer,
        client_id=provider.client_id,
    )


def complete(*, state: str, code: str) -> User:
    """Finish the callback: the member of the provider's organization the IdP vouched for."""
    data = oidc.consume_state(state)
    rls.bind(rls.for_tenant(data["organization"]))
    provider = (
        OidcProvider.objects.select_related("organization")
        .filter(pk=data["provider"], enabled=True, organization__is_active=True)
        .first()
    )
    if provider is None:
        raise oidc.SsoError("provider_gone")
    try:
        discovery = oidc.discover(provider.issuer)
        id_token = oidc.exchange_code(
            discovery,
            code=code,
            verifier=data["verifier"],
            client_id=provider.client_id,
            client_secret=crypto.decrypt(provider.client_secret_encrypted),
        )
        claims = oidc.validate_id_token(
            discovery, id_token, client_id=provider.client_id, nonce=data["nonce"]
        )
        return _member_for(provider, claims)
    except oidc.SsoError as exc:
        exc.provider = provider
        raise


def _member_for(provider: OidcProvider, claims: dict[str, Any]) -> User:
    subject = str(claims["sub"])
    identity = (
        SsoIdentity.objects.select_related("user__organization")
        .filter(provider=provider, subject=subject)
        .first()
    )
    if identity is not None:
        user = identity.user
    else:
        # First use: a verified email of an existing member, in an allowed domain.
        if claims.get("email_verified") is not True:
            raise oidc.SsoError("email_not_verified")
        email = normalize_email(str(claims.get("email", "")))
        domain = email.rpartition("@")[2]
        if not email or (provider.allowed_domains and domain not in provider.allowed_domains):
            raise oidc.SsoError("email_domain_not_allowed")
        found = (
            User.objects.select_related("organization")
            .filter(organization=provider.organization, email=email)
            .first()
        )
        if found is None:
            raise oidc.SsoError("no_matching_member")
        user = found
        if SsoIdentity.objects.filter(provider=provider, user=user).exists():
            raise oidc.SsoError("member_linked_to_another_subject")
        try:
            with transaction.atomic():
                identity = SsoIdentity.objects.create(
                    organization=provider.organization,
                    provider=provider,
                    user=user,
                    subject=subject,
                )
        except IntegrityError as exc:
            raise oidc.SsoError("subject_race") from exc
    if user.organization_id != provider.organization_id or not user_can_authenticate(user):
        raise oidc.SsoError("member_inactive")
    SsoIdentity.objects.filter(pk=identity.pk).update(last_used_at=timezone.now())
    return user


def record_failure(reason: str, provider: OidcProvider | None) -> None:
    organization = provider.organization if provider is not None else None
    with rls.scope(rls.for_tenant(organization.pk) if organization else rls.PLATFORM):
        record(
            AuditAction.SSO_FAILED,
            organization=organization,
            target=provider,
            metadata={"reason": reason},
        )
