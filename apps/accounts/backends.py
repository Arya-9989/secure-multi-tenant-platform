"""Django authentication that works under row-level security (ADR 0001).

Django's ``ModelBackend`` loads the account directly, which in an unscoped
request returns nothing. This backend first resolves the account's tenant, loads
it in that scope, and on success keeps the scope for the rest of the request.
It serves the API login (through SimpleJWT) and the admin's sessions alike.
"""

from __future__ import annotations

from typing import Any

from django.contrib.auth.backends import ModelBackend
from django.http import HttpRequest

from apps.accounts.models import User
from apps.accounts.scopes import scope_for_account
from apps.common import rls


class TenantModelBackend(ModelBackend):
    def authenticate(
        self,
        request: HttpRequest | None,
        username: str | None = None,
        password: str | None = None,
        **kwargs: Any,
    ) -> User | None:
        email = username if username is not None else kwargs.get(User.USERNAME_FIELD)
        scope = scope_for_account(email=email or "")
        with rls.scope(scope):
            user = super().authenticate(request, username=email, password=password, **kwargs)
        if isinstance(user, User):
            rls.bind(scope)
            return user
        return None

    def get_user(self, user_id: Any) -> User | None:
        scope = scope_for_account(user_id=user_id)
        with rls.scope(scope):
            user = super().get_user(user_id)
        if isinstance(user, User):
            rls.bind(scope)
            return user
        return None
