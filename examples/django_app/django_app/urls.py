"""URL routing for the Django example."""

from __future__ import annotations

from django.conf import settings
from django.urls import path, re_path

from . import views

if getattr(settings, "FTW", False):
    urlpatterns = [re_path(r"^.*$", views.ftw_catch_all)]
else:
    urlpatterns = [
        path("", views.root),
        path("healthz", views.healthz),
        path("search", views.search),
        path("echo", views.echo),
        path("upload", views.upload),
        path("img/logo.png", views.image),
        path("api/users/<str:user_id>", views.user),
    ]
