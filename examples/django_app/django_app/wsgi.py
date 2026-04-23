"""WSGI entry point for the Django example."""

from __future__ import annotations

import os

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "django_app.settings")

from django.core.wsgi import get_wsgi_application

application = get_wsgi_application()
