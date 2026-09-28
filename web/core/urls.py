from django.conf import settings
from django.urls import path
from django.views.static import serve

from . import views

app_name = "core"

urlpatterns = [
    path("settings/", views.site_settings, name="settings"),
    path("settings/builds/add/", views.build_add, name="build_add"),
    path("settings/builds/<int:pk>/remove/", views.build_remove, name="build_remove"),
    path("audit/", views.audit, name="audit"),
    path("download/", views.download, name="download"),
    path("healthz", views.healthz, name="healthz"),
    path("language/", views.set_language, name="set_language"),
]

if settings.DEBUG:  # production serves the files straight from nginx
    urlpatterns.append(path("download/files/<path:path>", serve, {"document_root": settings.MOON_DOWNLOAD_DIR}))
