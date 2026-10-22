from typing import Any

from django.contrib import admin
from django.forms import ModelForm
from django.http import HttpRequest

from apps.common.tenancy import resolve_user
from apps.organizations import services
from apps.organizations.models import Organization


@admin.register(Organization)
class OrganizationAdmin(admin.ModelAdmin[Organization]):
    """Tenants can be created and edited here, through the same audited services as the API."""

    list_display = ("name", "slug", "is_active", "created_at")
    list_filter = ("is_active",)
    search_fields = ("name", "slug")
    readonly_fields = ("id", "created_at", "updated_at")

    def has_delete_permission(self, request: HttpRequest, obj: Any = None) -> bool:
        return False  # tenants are deactivated, never deleted

    def save_model(
        self, request: HttpRequest, obj: Organization, form: ModelForm[Organization], change: bool
    ) -> None:
        actor = resolve_user(request.user)
        if actor is None:  # unreachable: the admin requires an active staff user
            raise PermissionError
        if change:
            services.update_organization(
                actor=actor,
                organization=Organization.objects.get(pk=obj.pk),
                changes={name: form.cleaned_data[name] for name in form.changed_data},
            )
        else:
            created = services.create_organization(
                actor=actor, name=obj.name, slug=obj.slug, is_active=obj.is_active
            )
            obj.pk = created.pk
            obj._state.adding = False
        obj.refresh_from_db()
