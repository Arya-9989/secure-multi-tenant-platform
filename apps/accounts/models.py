from __future__ import annotations

import hashlib
import uuid
from collections.abc import Iterator
from enum import StrEnum
from typing import Any, ClassVar

from django.conf import settings
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.db import models
from django.db.models import Q
from django.db.models.functions import Lower
from django.utils import timezone
from django.utils.crypto import salted_hmac

from apps.accounts.roles import ASSIGNABLE_ROLE_CHOICES, ASSIGNABLE_ROLES, Role
from apps.common.tenancy import TenantQuerySet


def normalize_email(email: str) -> str:
    """Emails are the login identifier and are compared case-insensitively."""
    return email.strip().lower()


class UserQuerySet(TenantQuerySet["User"]):
    def active(self) -> UserQuerySet:
        return self.filter(is_active=True)


class UserManager(BaseUserManager["User"]):
    use_in_migrations = True

    def get_queryset(self) -> UserQuerySet:
        return UserQuerySet(self.model, using=self._db)

    def visible_to(self, candidate: object) -> UserQuerySet:
        return self.get_queryset().visible_to(candidate)

    def get_by_natural_key(self, username: str | None) -> User:
        user: User = self.get(email=normalize_email(username or ""))
        return user

    def create_user(self, email: str, password: str | None = None, **extra_fields: Any) -> User:
        if not email:
            raise ValueError("Email is required")
        user: User = self.model(email=normalize_email(email), **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email: str, password: str | None = None, **extra: Any) -> User:
        extra.update(role=Role.SUPER_ADMIN, organization=None, is_staff=True, is_superuser=True)
        return self.create_user(email, password, **extra)


class User(AbstractBaseUser, PermissionsMixin):
    """A platform user. Exactly one organization, except for super admins (none)."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    email = models.EmailField(max_length=254, unique=True)
    full_name = models.CharField(max_length=150, blank=True)
    role = models.CharField(max_length=20, choices=Role.choices, default=Role.MEMBER)
    organization = models.ForeignKey(
        "organizations.Organization",
        on_delete=models.PROTECT,
        null=True,
        blank=True,
        related_name="users",
    )
    is_active = models.BooleanField(
        default=True, help_text="Soft deactivation: inactive users cannot authenticate."
    )
    is_staff = models.BooleanField(default=False, help_text="Django admin access.")
    deactivated_at = models.DateTimeField(null=True, blank=True)
    token_version = models.PositiveIntegerField(
        default=0,
        editable=False,
        help_text="Embedded in JWTs; incrementing it revokes every token issued so far.",
    )
    date_joined = models.DateTimeField(default=timezone.now, editable=False)
    updated_at = models.DateTimeField(auto_now=True)

    USERNAME_FIELD = "email"
    EMAIL_FIELD = "email"
    REQUIRED_FIELDS: ClassVar[list[str]] = []

    objects = UserManager()

    class Meta:
        ordering = ("email",)
        constraints = (
            # The tenancy invariant, enforced by the database rather than by
            # application code that might forget it.
            models.CheckConstraint(
                condition=(
                    Q(role=Role.SUPER_ADMIN, organization__isnull=True)
                    | (~Q(role=Role.SUPER_ADMIN) & Q(organization__isnull=False))
                ),
                name="user_organization_matches_role",
            ),
            models.CheckConstraint(
                condition=Q(is_staff=False, is_superuser=False) | Q(role=Role.SUPER_ADMIN),
                name="user_only_super_admins_are_staff",
            ),
            models.CheckConstraint(condition=Q(email=Lower("email")), name="user_email_lowercase"),
        )
        indexes = (models.Index(fields=("organization", "role")),)

    def __str__(self) -> str:
        return self.email

    def save(self, *args: Any, **kwargs: Any) -> None:
        self.email = normalize_email(self.email)
        super().save(*args, **kwargs)

    @property
    def is_super_admin(self) -> bool:
        return self.role == Role.SUPER_ADMIN

    @property
    def is_org_admin(self) -> bool:
        return self.role == Role.ORG_ADMIN

    @property
    def tenant_id(self) -> uuid.UUID | None:
        return self.organization_id

    # Django ends a user's admin sessions when their password hash changes. Mixing in
    # token_version extends that to everything else that revokes their API tokens:
    # logging out everywhere, deactivation, an organization being switched off.
    def get_session_auth_hash(self) -> str:
        return self._session_auth_hash()

    def get_session_auth_fallback_hash(self) -> Iterator[str]:
        for secret in settings.SECRET_KEY_FALLBACKS:
            yield self._session_auth_hash(secret)

    def _session_auth_hash(self, secret: str | bytes | None = None) -> str:
        return salted_hmac(
            "apps.accounts.models.User.get_session_auth_hash",
            f"{self.password}:{self.token_version}",
            secret=secret,
            algorithm="sha256",
        ).hexdigest()


def hash_invitation_token(raw_token: str) -> str:
    """Only a SHA-256 digest of an invitation token is ever stored."""
    return hashlib.sha256(raw_token.encode()).hexdigest()


class InvitationStatus(StrEnum):
    PENDING = "pending"
    ACCEPTED = "accepted"
    REVOKED = "revoked"
    EXPIRED = "expired"


class InvitationQuerySet(TenantQuerySet["Invitation"]):
    def open(self) -> InvitationQuerySet:
        """Neither accepted nor revoked (may still be expired)."""
        return self.filter(accepted_at__isnull=True, revoked_at__isnull=True)

    def with_status(self, status: InvitationStatus) -> InvitationQuerySet:
        now = timezone.now()
        match status:
            case InvitationStatus.ACCEPTED:
                return self.filter(accepted_at__isnull=False)
            case InvitationStatus.REVOKED:
                return self.filter(revoked_at__isnull=False)
            case InvitationStatus.EXPIRED:
                return self.open().filter(expires_at__lte=now)
            case InvitationStatus.PENDING:
                return self.open().filter(expires_at__gt=now)


class Invitation(models.Model):
    """A single-use, expiring invitation to join an organization with a role."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organization = models.ForeignKey(
        "organizations.Organization", on_delete=models.PROTECT, related_name="invitations"
    )
    email = models.EmailField(max_length=254)
    role = models.CharField(max_length=20, choices=ASSIGNABLE_ROLE_CHOICES)
    token_hash = models.CharField(max_length=64, unique=True, editable=False)
    invited_by = models.ForeignKey(User, on_delete=models.PROTECT, related_name="+")
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    accepted_at = models.DateTimeField(null=True, blank=True)
    accepted_user = models.ForeignKey(
        User, on_delete=models.PROTECT, null=True, blank=True, related_name="+"
    )
    revoked_at = models.DateTimeField(null=True, blank=True)
    revoked_by = models.ForeignKey(
        User, on_delete=models.PROTECT, null=True, blank=True, related_name="+"
    )

    objects = InvitationQuerySet.as_manager()

    class Meta:
        ordering = ("-created_at",)
        constraints = (
            models.UniqueConstraint(
                fields=("organization", "email"),
                condition=Q(accepted_at__isnull=True, revoked_at__isnull=True),
                name="invitation_one_open_per_email_per_org",
            ),
            models.CheckConstraint(
                condition=Q(role__in=[role.value for role in ASSIGNABLE_ROLES]),
                name="invitation_role_assignable",
            ),
            models.CheckConstraint(
                condition=Q(accepted_at__isnull=True) | Q(revoked_at__isnull=True),
                name="invitation_not_accepted_and_revoked",
            ),
        )

    def __str__(self) -> str:
        return f"{self.email} -> {self.organization_id} ({self.status})"

    @property
    def tenant_id(self) -> uuid.UUID:
        return self.organization_id

    @property
    def status(self) -> InvitationStatus:
        if self.accepted_at is not None:
            return InvitationStatus.ACCEPTED
        if self.revoked_at is not None:
            return InvitationStatus.REVOKED
        if self.expires_at <= timezone.now():
            return InvitationStatus.EXPIRED
        return InvitationStatus.PENDING


class SessionEndReason(models.TextChoices):
    LOGOUT = "logout", "Logged out"
    LOGOUT_ALL = "logout_all", "Logged out everywhere"
    REUSE_DETECTED = "reuse_detected", "A rotated refresh token was replayed"
    PASSWORD_CHANGED = "password_changed", "Password changed"
    USER_DEACTIVATED = "user_deactivated", "User deactivated"
    ORGANIZATION_DEACTIVATED = "organization_deactivated", "Organization deactivated"


class RefreshTokenFamilyQuerySet(TenantQuerySet["RefreshTokenFamily"]):
    def live(self) -> RefreshTokenFamilyQuerySet:
        return self.filter(revoked_at__isnull=True, expires_at__gt=timezone.now())


class RefreshTokenFamily(models.Model):
    """One login session: every refresh token rotated from one sign-in (ADR 0002).

    Only the ID of the one redeemable refresh token is kept, never a token. A
    validly signed token of this family whose ID is not ``current_jti`` is an
    older one coming back, which revokes the family.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="session_families")
    organization = models.ForeignKey(
        "organizations.Organization",
        on_delete=models.PROTECT,
        null=True,
        blank=True,
        related_name="+",
        help_text="The user's organization (row-level security); empty for super admins.",
    )
    current_jti = models.CharField(max_length=64, editable=False)
    generation = models.PositiveIntegerField(default=0, help_text="Rotations so far.")
    created_at = models.DateTimeField(default=timezone.now, editable=False)
    last_refreshed_at = models.DateTimeField(null=True, blank=True)
    expires_at = models.DateTimeField(help_text="Absolute end of the session.")
    revoked_at = models.DateTimeField(null=True, blank=True)
    revoked_reason = models.CharField(max_length=32, choices=SessionEndReason.choices, blank=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.CharField(max_length=512, blank=True)

    objects = RefreshTokenFamilyQuerySet.as_manager()

    class Meta:
        verbose_name = "session"
        verbose_name_plural = "sessions"
        ordering = ("-created_at",)
        indexes = (models.Index(fields=("user", "revoked_at")),)
        constraints = (
            models.CheckConstraint(
                condition=Q(revoked_at__isnull=True, revoked_reason="")
                | Q(revoked_at__isnull=False) & ~Q(revoked_reason=""),
                name="session_revocation_has_a_reason",
            ),
        )

    def __str__(self) -> str:
        return f"session {self.pk} of {self.user_id}"

    @property
    def tenant_id(self) -> uuid.UUID | None:
        return self.organization_id

    @property
    def is_live(self) -> bool:
        return self.revoked_at is None and self.expires_at > timezone.now()
