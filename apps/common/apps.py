from django.apps import AppConfig
from django.contrib.admin import apps as admin_apps


class CommonConfig(AppConfig):
    name = "apps.common"
    label = "common"
    verbose_name = "Common infrastructure"


class PlatformAdminConfig(admin_apps.AdminConfig):
    """Installs :class:`apps.common.admin_site.PlatformAdminSite` as ``admin.site``."""

    default = False  # installed explicitly in INSTALLED_APPS, in place of django.contrib.admin
    default_site = "apps.common.admin_site.PlatformAdminSite"
