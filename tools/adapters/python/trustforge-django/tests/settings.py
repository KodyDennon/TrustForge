"""Minimal Django settings for trustforge-django tests."""

from __future__ import annotations

SECRET_KEY = "tf-django-test-secret"
DEBUG = True
ALLOWED_HOSTS = ["*"]

INSTALLED_APPS: list[str] = []
MIDDLEWARE = ["trustforge_django.TrustForgeMiddleware"]

ROOT_URLCONF = "tests.urls"

DATABASES: dict[str, dict[str, str]] = {}

TRUSTFORGE = {
    "daemon_url": "http://daemon.test",
    "admin_token": "t",
    "mode": "enforce",
}

USE_TZ = True
