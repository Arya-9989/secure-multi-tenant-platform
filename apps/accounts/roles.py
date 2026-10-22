"""Roles and the role -> permission matrix.

This module is the single source of truth for *what* each role may do. Views
declare which permission each action requires (``required_permissions``) and
:class:`apps.common.permissions.HasRolePermission` checks it. *Which rows* a
user may touch is decided separately by tenant scoping
(:mod:`apps.common.tenancy`).
"""

from __future__ import annotations

from collections.abc import Mapping
from enum import StrEnum

from django.db import models


class Role(models.TextChoices):
    SUPER_ADMIN = "SUPER_ADMIN", "Super admin"
    ORG_ADMIN = "ORG_ADMIN", "Organization admin"
    MEMBER = "MEMBER", "Member"


# Roles that can be granted through the API (invitations / role changes).
# SUPER_ADMIN is deliberately absent: platform operators are created with
# ``manage.py createsuperuser`` and can never be minted over HTTP.
ASSIGNABLE_ROLES: tuple[Role, ...] = (Role.ORG_ADMIN, Role.MEMBER)
ASSIGNABLE_ROLE_CHOICES = [(role.value, role.label) for role in ASSIGNABLE_ROLES]


class Perm(StrEnum):
    ORGANIZATION_VIEW = "organization:view"
    ORGANIZATION_MANAGE = "organization:manage"
    USER_VIEW = "user:view"
    USER_MANAGE = "user:manage"
    INVITATION_MANAGE = "invitation:manage"
    AUDIT_VIEW = "audit:view"


ROLE_PERMISSIONS: Mapping[str, frozenset[Perm]] = {
    Role.SUPER_ADMIN: frozenset(Perm),
    Role.ORG_ADMIN: frozenset(
        {
            Perm.ORGANIZATION_VIEW,
            Perm.USER_VIEW,
            Perm.USER_MANAGE,
            Perm.INVITATION_MANAGE,
            Perm.AUDIT_VIEW,
        }
    ),
    Role.MEMBER: frozenset({Perm.ORGANIZATION_VIEW, Perm.USER_VIEW}),
}


def role_has_permission(role: str, perm: Perm) -> bool:
    return perm in ROLE_PERMISSIONS.get(role, frozenset())
