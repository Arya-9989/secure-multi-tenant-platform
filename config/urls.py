from django.conf import settings
from django.contrib import admin
from django.urls import URLPattern, URLResolver, include, path
from rest_framework.routers import SimpleRouter

from apps.accounts.views.auth import (
    LoginView,
    LogoutAllView,
    LogoutView,
    MeView,
    PasswordChangeView,
    RefreshView,
)
from apps.accounts.views.invitations import AcceptInvitationView, InvitationViewSet
from apps.accounts.views.users import UserViewSet
from apps.apikeys.views import ApiKeyViewSet
from apps.auditlogs.views import AuditLogViewSet
from apps.common.views import LivenessView, ReadinessView
from apps.mfa import views as mfa
from apps.organizations.views import OrganizationViewSet
from apps.sso.views import OidcProviderViewSet, SsoCallbackView, SsoExchangeView, SsoLoginView
from apps.web.views import (
    CompressedSchemaView,
    LandingView,
    ThemedRedocView,
    ThemedSwaggerView,
    redoc_bundle,
)

router = SimpleRouter()
router.register("organizations", OrganizationViewSet, basename="organization")
router.register("users", UserViewSet, basename="user")
router.register("invitations", InvitationViewSet, basename="invitation")
router.register("audit-logs", AuditLogViewSet, basename="auditlog")
router.register("sso-providers", OidcProviderViewSet, basename="ssoprovider")
router.register("api-keys", ApiKeyViewSet, basename="apikey")

api_v1: list[URLPattern | URLResolver] = [
    path("auth/login/", LoginView.as_view(), name="auth-login"),
    path("auth/refresh/", RefreshView.as_view(), name="auth-refresh"),
    path("auth/logout/", LogoutView.as_view(), name="auth-logout"),
    path("auth/logout-all/", LogoutAllView.as_view(), name="auth-logout-all"),
    path("auth/me/", MeView.as_view(), name="auth-me"),
    path("auth/password/change/", PasswordChangeView.as_view(), name="auth-password-change"),
    path("invitations/accept/", AcceptInvitationView.as_view(), name="invitation-accept"),
    # Second factors (ADR 0004): the signed-in user's own, and the second sign-in step.
    path("auth/mfa/", mfa.MfaStatusView.as_view(), name="mfa-status"),
    path("auth/mfa/totp/", mfa.TotpSetupView.as_view(), name="mfa-totp-setup"),
    path("auth/mfa/totp/confirm/", mfa.TotpConfirmView.as_view(), name="mfa-totp-confirm"),
    path("auth/mfa/totp/disable/", mfa.TotpDisableView.as_view(), name="mfa-totp-disable"),
    path("auth/mfa/recovery-codes/", mfa.RecoveryCodesView.as_view(), name="mfa-recovery-codes"),
    path(
        "auth/mfa/webauthn/register/",
        mfa.WebAuthnRegisterBeginView.as_view(),
        name="mfa-webauthn-register",
    ),
    path(
        "auth/mfa/webauthn/register/complete/",
        mfa.WebAuthnRegisterCompleteView.as_view(),
        name="mfa-webauthn-register-complete",
    ),
    path(
        "auth/mfa/webauthn/<uuid:credential_id>/remove/",
        mfa.WebAuthnRemoveView.as_view(),
        name="mfa-webauthn-remove",
    ),
    path("auth/mfa/verify/", mfa.MfaVerifyView.as_view(), name="mfa-verify"),
    path("auth/mfa/webauthn/begin/", mfa.WebAuthnBeginView.as_view(), name="mfa-webauthn-begin"),
    path(
        "auth/mfa/webauthn/complete/",
        mfa.WebAuthnCompleteView.as_view(),
        name="mfa-webauthn-complete",
    ),
    # SSO via OpenID Connect (ADR 0004).
    path("auth/sso/callback/", SsoCallbackView.as_view(), name="sso-callback"),
    path("auth/sso/exchange/", SsoExchangeView.as_view(), name="sso-exchange"),
    path("auth/sso/<slug:slug>/login/", SsoLoginView.as_view(), name="sso-login"),
    *router.urls,
]

urlpatterns: list[URLPattern | URLResolver] = [
    path("", LandingView.as_view(), name="landing"),
    path("api/v1/", include(api_v1)),
    path("health/live/", LivenessView.as_view(), name="health-live"),
    path("health/ready/", ReadinessView.as_view(), name="health-ready"),
    path(settings.ADMIN_URL, admin.site.urls),
]

if settings.API_DOCS_ENABLED:
    urlpatterns += [
        path("api/schema/", CompressedSchemaView.as_view(), name="schema"),
        path("api/docs/", ThemedSwaggerView.as_view(url_name="schema"), name="swagger-ui"),
        path("api/redoc/", ThemedRedocView.as_view(url_name="schema"), name="redoc"),
        path("api/redoc/redoc.standalone.js", redoc_bundle, name="redoc-bundle"),
    ]

# Branded pages for people, DRF-style JSON under /api/ (see apps.web.errors).
handler400 = "apps.web.errors.bad_request"
handler403 = "apps.web.errors.permission_denied"
handler404 = "apps.web.errors.page_not_found"
handler500 = "apps.web.errors.server_error"
