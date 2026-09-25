from django.urls import path

from . import views

app_name = "accounts"

urlpatterns = [
    path("login/", views.login_view, name="login"),
    path("login/verify/", views.login_2fa, name="login_2fa"),
    path("logout/", views.logout_view, name="logout"),
    path("join/<str:token>/", views.invite_accept, name="invite_accept"),
    path("account/", views.account, name="account"),
    path("account/password/", views.password_change, name="password"),
    path("account/2fa/", views.twofa_setup, name="twofa_setup"),
    path("account/2fa/recovery/", views.twofa_recovery, name="twofa_recovery"),
    path("account/2fa/regenerate/", views.twofa_regenerate, name="twofa_regenerate"),
    path("account/2fa/disable/", views.twofa_disable, name="twofa_disable"),
    path("account/signout-everywhere/", views.signout_everywhere, name="signout_everywhere"),
    path("team/", views.team, name="team"),
    path("team/invite/", views.invite_create, name="invite_create"),
    path("team/invite/<int:pk>/revoke/", views.invite_revoke, name="invite_revoke"),
    path("team/roles/", views.roles, name="roles"),
    path("team/roles/new/", views.role_edit, name="role_new"),
    path("team/roles/<slug:slug>/", views.role_edit, name="role_edit"),
    path("team/roles/<slug:slug>/delete/", views.role_delete, name="role_delete"),
    path("team/m/<str:alias>/", views.member_detail, name="member"),
    path("team/m/<str:alias>/<slug:action>/", views.member_action, name="member_action"),
]
