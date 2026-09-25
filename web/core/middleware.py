import ipaddress

from django.conf import settings

CSP = "; ".join([
    "default-src 'self'",
    "script-src 'self'",
    "style-src 'self'",
    "img-src 'self' data:",
    "font-src 'self'",
    "connect-src 'self'",
    "object-src 'none'",
    "base-uri 'none'",
    "form-action 'self'",
    "frame-ancestors 'none'",
])


class RealIpMiddleware:
    """Uses nginx's X-Real-IP as REMOTE_ADDR. Only enabled when gunicorn is
    reachable exclusively through nginx (see MOON_TRUST_X_REAL_IP)."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if settings.MOON_TRUST_X_REAL_IP:
            real = request.META.get("HTTP_X_REAL_IP", "").strip()
            try:
                request.META["REMOTE_ADDR"] = str(ipaddress.ip_address(real))
            except ValueError:
                pass
        return self.get_response(request)


class SecurityHeadersMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        response.setdefault("Content-Security-Policy", CSP)
        response.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=()")
        response.setdefault("Cross-Origin-Resource-Policy", "same-origin")
        if request.user.is_authenticated if hasattr(request, "user") else False:
            response.setdefault("Cache-Control", "no-store")
        return response
