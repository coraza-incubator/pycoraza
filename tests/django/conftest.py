"""Django test harness — configure Django before importing the middleware.

Uses the same fake_abi fixture as the other adapter suites. Django's
`settings.configure()` must run before anything imports Django model
classes or middleware; we do it at module-load time so pytest
discovery works without a separate DJANGO_SETTINGS_MODULE.
"""

from __future__ import annotations

import pytest

django = pytest.importorskip("django")

from django.conf import settings as _settings

if not _settings.configured:
    _settings.configure(
        DEBUG=False,
        SECRET_KEY="pycoraza-tests-not-secret",
        ALLOWED_HOSTS=["*"],
        ROOT_URLCONF=__name__,
        MIDDLEWARE=[],
        INSTALLED_APPS=[],
        DATABASES={},
        USE_TZ=True,
    )

import django as _django

_django.setup()

# A minimal urlconf for request factory tests — exposed here so
# ROOT_URLCONF above resolves to this module's `urlpatterns`.
from django.urls import path

urlpatterns: list = [path("", lambda r: _settings)]
