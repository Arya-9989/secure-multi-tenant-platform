from django.conf import settings
from django.contrib import admin
from django.urls import URLPattern, URLResolver, include, path
from drf_spectacular.views import SpectacularAPIView
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
from apps.auditlogs.views import AuditLogViewSet
from apps.common.views import LivenessView, ReadinessView
from apps.organizations.views import OrganizationViewSet
from apps.web.views import LandingView, ThemedRedocView, ThemedSwaggerView

router = SimpleRouter()
router.register("organizations", OrganizationViewSet, basename="organization")
router.register("users", UserViewSet, basename="user")
router.register("invitations", InvitationViewSet, basename="invitation")
router.register("audit-logs", AuditLogViewSet, basename="auditlog")

api_v1: list[URLPattern | URLResolver] = [
    path("auth/login/", LoginView.as_view(), name="auth-login"),
    path("auth/refresh/", RefreshView.as_view(), name="auth-refresh"),
    path("auth/logout/", LogoutView.as_view(), name="auth-logout"),
    path("auth/logout-all/", LogoutAllView.as_view(), name="auth-logout-all"),
    path("auth/me/", MeView.as_view(), name="auth-me"),
    path("auth/password/change/", PasswordChangeView.as_view(), name="auth-password-change"),
    path("invitations/accept/", AcceptInvitationView.as_view(), name="invitation-accept"),
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
        path("api/schema/", SpectacularAPIView.as_view(), name="schema"),
        path("api/docs/", ThemedSwaggerView.as_view(url_name="schema"), name="swagger-ui"),
        path("api/redoc/", ThemedRedocView.as_view(url_name="schema"), name="redoc"),
    ]

admin.site.site_header = "Secure Multi-Tenant Platform"
admin.site.site_title = "Platform admin"
