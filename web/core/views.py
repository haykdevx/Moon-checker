from django import forms
from django.conf import settings
from django.contrib import messages
from django.core.paginator import Paginator
from django.http import HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.utils.http import url_has_allowed_host_and_scheme
from django.utils.translation import gettext as _t, gettext_lazy as _
from django.views.decorators.http import require_POST

from accounts.views import perm_required
from checks.models import TrustedBuild

from .audit import record
from .models import AuditEvent, SiteSettings


class SettingsForm(forms.ModelForm):
    class Meta:
        model = SiteSettings
        fields = ["code_ttl_minutes", "heartbeat_timeout_minutes", "fast_scan_seconds", "retention_days",
                  "min_checker_version", "require_2fa", "block_untrusted_builds", "accept_unbound_reports"]
        labels = {
            "code_ttl_minutes": _("Code lifetime, minutes"),
            "heartbeat_timeout_minutes": _("Silence before a check counts as lost, minutes"),
            "fast_scan_seconds": _("Suspiciously fast check, seconds"),
            "retention_days": _("Keep finished checks, days"),
            "min_checker_version": _("Oldest allowed checker version"),
            "require_2fa": _("Two-factor authentication required for everyone"),
            "block_untrusted_builds": _("Refuse checkers that do not claim an official build hash"),
            "accept_unbound_reports": _("Accept checkers older than 1.3 (transition only)"),
        }
        help_texts = {
            "code_ttl_minutes": _("How long a code stays valid before the player enters it."),
            "heartbeat_timeout_minutes": _("A running check that stops reporting for this long is marked lost."),
            "fast_scan_seconds": _("A finished check faster than this (by the server's clock) is flagged."),
            "retention_days": _("Older finished checks are deleted automatically (0 = keep forever)."),
            "min_checker_version": _("Older checkers are refused when they connect."),
            "require_2fa": "",
            "block_untrusted_builds": _("A checker that reports a file hash not in the list below cannot connect. The "
                                        "hash is sent by the player's PC: this stops outdated or casually modified "
                                        "copies, not a determined forger."),
            "accept_unbound_reports": _("Old checkers cannot bind their report to the check, so an old report could "
                                        "be resubmitted. Such checks are marked. Turn this off once players have "
                                        "the new version."),
        }


class TrustedBuildForm(forms.ModelForm):
    class Meta:
        model = TrustedBuild
        fields = ["label", "sha256"]
        labels = {"label": _("Name"), "sha256": "SHA-256"}

    def clean_sha256(self):
        return self.cleaned_data["sha256"].strip().lower()


@perm_required("settings.manage")
def site_settings(request):
    site = SiteSettings.load()
    form = SettingsForm(request.POST or None, instance=site)
    if request.method == "POST" and form.is_valid():
        changed = {k: form.cleaned_data[k] for k in form.changed_data}
        form.save()
        record(request, "settings.changed", "site", **{k: str(v) for k, v in changed.items()})
        messages.success(request, _t("Settings saved."))
        return redirect("core:settings")
    return render(request, "core/settings.html", {
        "form": form, "builds": TrustedBuild.objects.select_related("added_by"),
        "build_form": TrustedBuildForm(),
    })


@perm_required("settings.manage")
@require_POST
def build_add(request):
    form = TrustedBuildForm(request.POST)
    if form.is_valid():
        build = form.save(commit=False)
        build.added_by = request.user
        build.save()
        record(request, "build.trusted", build.sha256, label=build.label)
        messages.success(request, _t("Build added to the trusted list."))
    else:
        messages.error(request, _t("Invalid build: %(errors)s") % {
            "errors": "; ".join(e for errs in form.errors.values() for e in errs)})
    return redirect("core:settings")


@perm_required("settings.manage")
@require_POST
def build_remove(request, pk):
    build = get_object_or_404(TrustedBuild, pk=pk)
    record(request, "build.untrusted", build.sha256, label=build.label)
    build.delete()
    messages.success(request, _t("Build removed."))
    return redirect("core:settings")


@perm_required("audit.view")
def audit(request):
    qs = AuditEvent.objects.all()
    actor, action = request.GET.get("actor", "").strip(), request.GET.get("action", "").strip()
    if actor:
        qs = qs.filter(actor_label=actor.lower())
    if action:
        qs = qs.filter(action__startswith=action)
    page = Paginator(qs, 50).get_page(request.GET.get("page"))
    actions = AuditEvent.objects.values_list("action", flat=True).distinct().order_by("action")
    return render(request, "core/audit.html", {"page": page, "actor": actor, "action": action,
                                               "actions": actions})


def download(request):
    folder = settings.MOON_DOWNLOAD_DIR
    files = []
    if folder.is_dir():
        for p in sorted(folder.iterdir()):
            if p.is_file() and p.suffix in (".zip", ".jar", ".exe") and not p.name.startswith("."):
                files.append({"name": p.name, "size_mb": round(p.stat().st_size / 1048576, 1)})
    from .public_text import pick
    lang, t = pick(request)
    return render(request, "core/download.html", {"files": files, "lang": lang, "t": t})


@require_POST
def set_language(request):
    lang = request.POST.get("lang")
    target = request.POST.get("next") or "/"
    if not url_has_allowed_host_and_scheme(target, {request.get_host()}, require_https=request.is_secure()):
        target = "/"
    response = redirect(target)
    if lang in dict(settings.LANGUAGES):
        response.set_cookie(settings.LANGUAGE_COOKIE_NAME, lang, max_age=365 * 24 * 3600, samesite="Lax",
                            secure=not settings.DEBUG, httponly=True)
    return response


def healthz(request):
    SiteSettings.load()
    return HttpResponse("ok", content_type="text/plain")


def _public_error(request, key, status):
    """Players never see the admin panel's chrome or English-only errors."""
    from .public_text import ERRORS, language
    lang = language(request)
    title, text = ERRORS[lang][key]
    resp = render(request, "core/error_public.html", {"title": title, "text": text, "lang": lang}, status=status)
    resp["X-Robots-Tag"] = "noindex, nofollow"
    return resp


def csrf_failure(request, reason=""):
    from .public_text import is_public_path
    if is_public_path(request.path):
        return _public_error(request, "csrf", 403)
    return render(request, "core/error.html", {"title": _t("Form expired"),
                                               "text": _t("Reload the page and try again.")}, status=403)


def not_found(request, exception=None):
    from .public_text import is_public_path
    if is_public_path(request.path):
        return _public_error(request, "404", 404)
    return render(request, "core/error.html", {"title": _t("Not found"),
                                               "text": _t("That page does not exist or you cannot see it.")},
                  status=404)


def forbidden(request, exception=None):
    from .public_text import is_public_path
    if is_public_path(request.path):
        return _public_error(request, "403", 403)
    return render(request, "core/error.html", {"title": _t("Not allowed"),
                                               "text": _t("Your role does not allow this action.")}, status=403)
