"""URLs for the trustforge-django test app."""

from __future__ import annotations

from django.http import JsonResponse
from django.urls import path

from trustforge_django import require_capability


@require_capability("file.read")
def read_file(request, path):
    return JsonResponse({"path": path, "decision": request.tf_decision.decision})


urlpatterns = [path("files/<str:path>", read_file)]
