"""Minimal Django settings for the pycoraza example."""

from __future__ import annotations

import os
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
SHARED_DIR = BASE_DIR.parent / "shared"
if SHARED_DIR.is_dir() and str(SHARED_DIR) not in sys.path:
    sys.path.insert(0, str(SHARED_DIR))

import pycoraza_shared as shared

from pycoraza import ProcessMode, WAFConfig, create_waf

SECRET_KEY = "pycoraza-example-not-secret"
DEBUG = False
ALLOWED_HOSTS = ["*"]

FTW = shared.ftw_mode_enabled()
_MODE_ENV = os.environ.get("PYCORAZA_MODE", "").lower()
MODE = (
    ProcessMode.BLOCK if _MODE_ENV == "block"
    else ProcessMode.DETECT if _MODE_ENV == "detect"
    else ProcessMode.BLOCK if FTW
    else ProcessMode.DETECT
)

WAF_ENABLED = os.environ.get("PYCORAZA_WAF", "on").lower() != "off"

PYCORAZA_WAF = (
    create_waf(WAFConfig(rules=shared.crs_profile(FTW), mode=MODE)) if WAF_ENABLED else None
)
PYCORAZA_INSPECT_RESPONSE = FTW

MIDDLEWARE = (
    ["pycoraza.django.CorazaMiddleware"] if WAF_ENABLED and PYCORAZA_WAF is not None else []
)

ROOT_URLCONF = "django_app.urls"
INSTALLED_APPS: list[str] = []
DATABASES: dict[str, dict[str, str]] = {}

USE_TZ = True
LANGUAGE_CODE = "en-us"

TEMPLATES: list[dict[str, object]] = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": False,
        "OPTIONS": {},
    },
]

WSGI_APPLICATION = "django_app.wsgi.application"
ASGI_APPLICATION = "django_app.asgi.application"
