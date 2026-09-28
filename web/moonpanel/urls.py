from django.urls import include, path

urlpatterns = [
    path("api/v1/", include("checks.api_urls")),
    path("p/", include("checks.player_urls")),
    path("", include("accounts.urls")),
    path("", include("core.urls")),
    path("", include("checks.urls")),
]

handler404 = "core.views.not_found"
handler403 = "core.views.forbidden"
