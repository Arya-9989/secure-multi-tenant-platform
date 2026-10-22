from django.apps import AppConfig


class AccountsConfig(AppConfig):
    name = "apps.accounts"
    label = "accounts"
    verbose_name = "Accounts"

    def ready(self) -> None:
        from apps.accounts import schema  # noqa: F401, PLC0415 - registers the OpenAPI extension
