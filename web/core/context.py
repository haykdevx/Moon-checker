from django.conf import settings
from django.utils.translation import gettext_lazy as _


def panel(request):
    user = getattr(request, "user", None)
    nav = []
    appeals_open = 0
    if user is not None and user.is_authenticated:
        nav.append(("checks:dashboard", _("Checks")))
        nav.append(("checks:appeals", _("Appeals")))
        if user.can("checks.view_all") or user.can("checks.create"):
            nav.append(("checks:search", _("Search")))
        if user.can("team.view"):
            nav.append(("accounts:team", _("Team")))
        nav.append(("checks:rules", _("How it checks")))
        if user.can("audit.view"):
            nav.append(("core:audit", _("Log")))
        if user.can("settings.manage"):
            nav.append(("core:settings", _("Settings")))
        from checks.models import Appeal
        from checks.views import visible_sessions
        appeals_open = Appeal.objects.filter(session__in=visible_sessions(user), status=Appeal.OPEN).count()
    return {"nav": nav, "public_url": settings.PUBLIC_URL, "download_url": settings.MOON_DOWNLOAD_URL,
            "appeals_open": appeals_open}
