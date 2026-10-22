#!/usr/bin/env python
"""Django's command-line utility for administrative tasks."""

import os
import sys


def main() -> None:
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")
    from django.core.management import execute_from_command_line

    # Row-level security (ADR 0001): commands see no tenant rows unless they set
    # a scope. An operator can run one across every tenant, for example
    # `APP_DB_SCOPE=platform python manage.py createsuperuser`. HTTP requests
    # always start unscoped whatever this says, and the WSGI app never reads it.
    scope = os.environ.get("APP_DB_SCOPE", "")
    if scope:
        if scope != "platform":
            sys.exit(f"APP_DB_SCOPE must be 'platform' or unset, not {scope!r}.")
        from apps.common import rls

        rls.set_process_default(rls.PLATFORM)

    execute_from_command_line(sys.argv)


if __name__ == "__main__":
    main()
