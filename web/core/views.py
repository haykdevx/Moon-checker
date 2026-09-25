from django import forms
from django.conf import settings
from django.contrib import messages
from django.core.paginator import Paginator
from django.http import HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.http import require_POST

from accounts.views import perm_required
from checks.models import TrustedBuild

from .audit import record
from .models import AuditEvent, SiteSettings


class SettingsForm(forms.ModelForm):
    class Meta:
        model = SiteSettings
        fields = ["code_ttl_minutes", "heartbeat_timeout_minutes", "fast_scan_seconds", "retention_days",
                  "min_checker_version", "require_2fa", "block_untrusted_builds"]


class TrustedBuildForm(forms.ModelForm):
    class Meta:
        model = TrustedBuild
        fields = ["label", "sha256"]

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
        messages.success(request, "Settings saved.")
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
        messages.success(request, "Build added to the trusted list.")
    else:
        messages.error(request, "Invalid build: " + "; ".join(e for errs in form.errors.values() for e in errs))
    return redirect("core:settings")


@perm_required("settings.manage")
@require_POST
def build_remove(request, pk):
    build = get_object_or_404(TrustedBuild, pk=pk)
    record(request, "build.untrusted", build.sha256, label=build.label)
    build.delete()
    messages.success(request, "Build removed.")
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
    return render(request, "core/download.html", {"files": files})


def healthz(request):
    SiteSettings.load()
    return HttpResponse("ok", content_type="text/plain")


def csrf_failure(request, reason=""):
    return render(request, "core/error.html", {"title": "Form expired",
                                               "text": "Reload the page and try again."}, status=403)


def not_found(request, exception=None):
    return render(request, "core/error.html", {"title": "Not found",
                                               "text": "That page does not exist or you cannot see it."},
                  status=404)


def forbidden(request, exception=None):
    return render(request, "core/error.html", {"title": "Not allowed",
                                               "text": "Your role does not allow this action."}, status=403)
