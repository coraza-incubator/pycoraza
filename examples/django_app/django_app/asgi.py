"""ASGI entry point for the Django example."""

from __future__ import annotations

import os

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "django_app.settings")

from django.core.asgi import get_asgi_application

application = get_asgi_application()
