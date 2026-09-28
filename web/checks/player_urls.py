from django.urls import path

from . import player

app_name = "player"

urlpatterns = [
    path("<str:token>/", player.status, name="status"),
    path("<str:token>/appeal/", player.appeal, name="appeal"),
    path("<str:token>/delete/", player.deletion, name="deletion"),
    path("<str:token>/report.json", player.export, name="export"),
]
