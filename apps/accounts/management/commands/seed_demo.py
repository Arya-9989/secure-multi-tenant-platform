"""Create two demo tenants with users so reviewers can try isolation immediately."""

from __future__ import annotations

from typing import Any

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError, CommandParser
from django.db import transaction

from apps.accounts.models import User
from apps.accounts.roles import Role
from apps.organizations.models import Organization

DEFAULT_PASSWORD = "Demo-Passw0rd!2026"

TENANTS = (
    ("Acme Corp", "acme", ("alice@acme.test", "Alice Admin"), ("bob@acme.test", "Bob Member")),
    (
        "Globex Inc",
        "globex",
        ("grace@globex.test", "Grace Admin"),
        ("gus@globex.test", "Gus Member"),
    ),
)
SUPER_ADMIN = ("root@platform.test", "Platform Operator")


class Command(BaseCommand):
    help = "Seed two organizations (Acme, Globex), an admin and a member each, and a super admin."

    def add_arguments(self, parser: CommandParser) -> None:
        parser.add_argument("--password", default=DEFAULT_PASSWORD, help="Password for all users.")
        parser.add_argument(
            "--force",
            action="store_true",
            help="Allow running with DEBUG=False. Never use against a real deployment.",
        )

    @transaction.atomic
    def handle(self, *args: Any, **options: Any) -> None:
        if not settings.DEBUG and not options["force"]:
            raise CommandError("Refusing to seed demo accounts with DEBUG=False (use --force).")
        password: str = options["password"]

        rows: list[tuple[str, str, str]] = []
        email, name = SUPER_ADMIN
        if not User.objects.filter(email=email).exists():
            User.objects.create_superuser(email, password, full_name=name)
        rows.append((email, Role.SUPER_ADMIN, "-"))

        for org_name, slug, admin, member in TENANTS:
            org, _ = Organization.objects.get_or_create(slug=slug, defaults={"name": org_name})
            for (user_email, full_name), role in ((admin, Role.ORG_ADMIN), (member, Role.MEMBER)):
                if not User.objects.filter(email=user_email).exists():
                    User.objects.create_user(
                        user_email, password, full_name=full_name, role=role, organization=org
                    )
                rows.append((user_email, role, org.name))

        self.stdout.write(
            self.style.SUCCESS("Demo data ready. Accounts (existing ones untouched):")
        )
        for user_email, role_label, org_label in rows:
            self.stdout.write(f"  {user_email:<22} {role_label:<12} {org_label}")
        self.stdout.write(f"Password for newly created accounts: {password}")
