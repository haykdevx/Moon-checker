from django.urls import path

from . import views

app_name = "checks"

urlpatterns = [
    path("", views.dashboard, name="dashboard"),
    path("checks/new/", views.new_check, name="new"),
    path("checks/search/", views.search, name="search"),
    path("rules/", views.rules, name="rules"),
    path("checks/<uuid:pk>/", views.detail, name="detail"),
    path("checks/<uuid:pk>/live/", views.live, name="live"),
    path("checks/<uuid:pk>/decide/", views.decide, name="decide"),
    path("checks/<uuid:pk>/cancel/", views.cancel, name="cancel"),
    path("checks/<uuid:pk>/delete/", views.delete, name="delete"),
    path("checks/<uuid:pk>/evidence.json", views.export, name="export"),
]
