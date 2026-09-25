from django.conf import settings


def panel(request):
    user = getattr(request, "user", None)
    nav = []
    if user is not None and user.is_authenticated:
        nav.append(("checks:dashboard", "Checks"))
        if user.can("checks.view_all") or user.can("checks.create"):
            nav.append(("checks:search", "Evidence search"))
        if user.can("team.view"):
            nav.append(("accounts:team", "Team"))
        if user.can("audit.view"):
            nav.append(("core:audit", "Audit log"))
        if user.can("settings.manage"):
            nav.append(("core:settings", "Settings"))
    return {"nav": nav, "public_url": settings.PUBLIC_URL, "download_url": settings.MOON_DOWNLOAD_URL}
