from django.shortcuts import redirect
from django.urls import reverse

from core.models import SiteSettings

# Paths a signed-in member may reach while a mandatory step is outstanding.
_ALWAYS_ALLOWED = ("/static/", "/api/", "/logout/", "/download/")


class AccountGateMiddleware:
    """Forces the password change / 2FA enrollment before anything else in the panel."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        user = getattr(request, "user", None)
        if user is not None and user.is_authenticated and not request.path.startswith(_ALWAYS_ALLOWED):
            target = None
            if user.must_change_password:
                target = reverse("accounts:password")
            elif not user.totp_enabled and SiteSettings.load().require_2fa:
                target = reverse("accounts:twofa_setup")
            if target and request.path != target:
                return redirect(target)
        return self.get_response(request)
