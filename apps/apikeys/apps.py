from django.apps import AppConfig


class ApiKeysConfig(AppConfig):
    name = "apps.apikeys"
    label = "apikeys"
    verbose_name = "API keys"

    def ready(self) -> None:
        from apps.apikeys import schema  # noqa: F401, PLC0415 - registers the OpenAPI extension
