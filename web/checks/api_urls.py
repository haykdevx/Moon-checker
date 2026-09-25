from django.urls import path

from . import api

urlpatterns = [
    path("ping", api.ping, name="api_ping"),
    path("claim", api.claim, name="api_claim"),
    path("sessions/<uuid:session_id>/progress", api.progress, name="api_progress"),
    path("sessions/<uuid:session_id>/report", api.report, name="api_report"),
]
