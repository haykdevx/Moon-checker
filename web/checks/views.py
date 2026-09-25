import gzip
from datetime import timedelta

from django import forms
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.exceptions import PermissionDenied
from django.core.paginator import Paginator
from django.db import IntegrityError, transaction
from django.db.models import Count, Q
from django.http import Http404, HttpResponse, JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from django.views.decorators.http import require_POST

from accounts.models import User
from accounts.views import perm_required
from core.audit import record
from core.models import SiteSettings

from . import codes
from .models import CheckSession, FindingRow

FINDINGS_RENDER_LIMIT = 5000


class NewCheckForm(forms.ModelForm):
    class Meta:
        model = CheckSession
        fields = ["player_name", "player_steam", "player_discord", "note"]
        widgets = {
            "player_name": forms.TextInput(attrs={"autofocus": True, "placeholder": "In-game nickname"}),
            "player_steam": forms.TextInput(attrs={"placeholder": "https://steamcommunity.com/profiles/… or STEAM_…"}),
            "player_discord": forms.TextInput(attrs={"placeholder": "discord name"}),
            "note": forms.Textarea(attrs={"rows": 2, "placeholder": "Why is this player being checked?"}),
        }


class DecisionForm(forms.Form):
    decision = forms.ChoiceField(choices=CheckSession.DECISION_CHOICES, required=False)
    note = forms.CharField(max_length=1000, required=False, widget=forms.Textarea(attrs={"rows": 2}))


def visible_sessions(user):
    qs = CheckSession.objects.select_related("admin", "decision_by")
    return qs if user.can("checks.view_all") else qs.filter(admin=user)


def _get_visible(user, pk):
    try:
        return visible_sessions(user).get(pk=pk)
    except (CheckSession.DoesNotExist, ValueError):
        raise Http404 from None


def can_decide(user, session):
    return user.can("checks.decide_any") or (user.can("checks.decide") and session.admin_id == user.pk)


def can_cancel(user, session):
    return session.is_open and (session.admin_id == user.pk or user.can("checks.decide_any"))


def _filtered(request):
    user = request.user
    qs = visible_sessions(user)
    f = {k: request.GET.get(k, "").strip() for k in ("q", "status", "verdict", "decision", "admin", "mine")}
    if f["status"] == "open":
        qs = qs.filter(status__in=CheckSession.OPEN_STATUSES)
    elif f["status"]:
        qs = qs.filter(status=f["status"])
    if f["verdict"]:
        qs = qs.filter(verdict=f["verdict"])
    if f["decision"] == "none":
        qs = qs.filter(status=CheckSession.COMPLETED, decision="")
    elif f["decision"]:
        qs = qs.filter(decision=f["decision"])
    if f["mine"] == "1":
        qs = qs.filter(admin=user)
    elif f["admin"] and user.can("checks.view_all"):
        qs = qs.filter(admin__username=f["admin"].lower())
    if f["q"]:
        q = f["q"][:100]
        qs = qs.filter(Q(player_name__icontains=q) | Q(player_steam__icontains=q) | Q(player_discord__icontains=q)
                       | Q(code__iexact=q) | Q(client__hostname__icontains=q) | Q(client_check_id__iexact=q))
    return qs, f


@login_required
def dashboard(request):
    user = request.user
    qs, f = _filtered(request)
    page = Paginator(qs, 30).get_page(request.GET.get("page"))
    base = visible_sessions(user)
    since = timezone.now() - timedelta(days=7)
    stats = {
        "live": base.filter(status__in=CheckSession.LIVE_STATUSES).count(),
        "waiting": base.filter(status=CheckSession.WAITING).count(),
        "week": base.filter(status=CheckSession.COMPLETED, completed_at__gte=since).count(),
        "week_cheat": base.filter(status=CheckSession.COMPLETED, completed_at__gte=since, verdict="CHEAT").count(),
        "undecided": base.filter(status=CheckSession.COMPLETED, decision="").count(),
    }
    admins = User.objects.filter(check_sessions__isnull=False).distinct().order_by("username") \
        if user.can("checks.view_all") else []
    params = request.GET.copy()
    params.pop("page", None)
    params.pop("fragment", None)
    ctx = {"page": page, "f": f, "stats": stats, "admins": admins, "qs": params.urlencode(),
           "can_create": user.can("checks.create"),
           "statuses": CheckSession.STATUS_CHOICES, "decisions": CheckSession.DECISION_CHOICES[1:],
           "any_open": any(s.is_open for s in page)}
    if request.GET.get("fragment") == "1":
        return render(request, "checks/_session_rows.html", ctx)
    return render(request, "checks/dashboard.html", ctx)


@perm_required("checks.create")
def new_check(request):
    form = NewCheckForm(request.POST or None)
    if request.method == "POST" and form.is_valid():
        site = SiteSettings.load()
        session = form.save(commit=False)
        session.admin = request.user
        session.expires_at = timezone.now() + timedelta(minutes=site.code_ttl_minutes)
        for _ in range(8):
            session.code = codes.generate()
            try:
                with transaction.atomic():
                    session.save()
                break
            except IntegrityError:
                continue
        else:  # pragma: no cover - 32^8 space
            messages.error(request, "Could not allocate a code, try again.")
            return redirect("checks:new")
        record(request, "check.created", str(session.pk), player=session.player_name, code=session.code)
        return redirect("checks:detail", pk=session.pk)
    return render(request, "checks/new.html", {"form": form})


@login_required
def detail(request, pk):
    user = request.user
    session = _get_visible(user, pk)
    findings, truncated, modules, env, meta = [], False, {}, {}, {}
    if session.status == CheckSession.COMPLETED:
        rows = list(session.findings.all()[:FINDINGS_RENDER_LIMIT + 1])
        truncated = len(rows) > FINDINGS_RENDER_LIMIT
        findings = rows[:FINDINGS_RENDER_LIMIT]
        report = getattr(session, "report", None)
        if report is not None:
            modules, env, meta = report.modules, report.environment, report.meta
    same_player = Q(player_name__iexact=session.player_name)
    if session.player_steam:
        same_player |= Q(player_steam=session.player_steam)
    if session.client.get("hostname"):
        same_player |= Q(client__hostname=session.client["hostname"])
    related = visible_sessions(user).filter(same_player).exclude(pk=session.pk)[:10]
    return render(request, "checks/detail.html", {
        "s": session, "findings": findings, "truncated": truncated, "modules": sorted(modules.items()),
        "env": env, "meta": meta, "related": related,
        "can_decide": can_decide(user, session) and session.status == CheckSession.COMPLETED,
        "can_cancel": can_cancel(user, session),
        "can_export": user.can("checks.export") and session.status == CheckSession.COMPLETED,
        "can_delete": user.can("checks.delete"),
        "decision_form": DecisionForm(initial={"decision": session.decision, "note": session.decision_note}),
        "severities": FindingRow.SEVERITIES,
        "module_names": sorted({f.module for f in findings}),
    })


@login_required
def live(request, pk):
    s = _get_visible(request.user, pk)
    return JsonResponse({
        "status": s.status,
        "done": s.progress_done,
        "total": s.progress_total,
        "percent": s.progress_percent,
        "module": s.progress_module,
        "counts": dict(s.severity_counts),
        "lastSeen": s.last_seen_at.isoformat() if s.last_seen_at else None,
        "client": {k: s.client.get(k) for k in ("hostname", "user", "os", "appVersion", "elevated")},
    })


@login_required
@require_POST
def decide(request, pk):
    s = _get_visible(request.user, pk)
    if s.status != CheckSession.COMPLETED or not can_decide(request.user, s):
        raise PermissionDenied
    form = DecisionForm(request.POST)
    if form.is_valid():
        old = s.decision
        s.decision, s.decision_note = form.cleaned_data["decision"], form.cleaned_data["note"]
        s.decision_by, s.decision_at = request.user, timezone.now()
        s.save(update_fields=["decision", "decision_note", "decision_by", "decision_at"])
        record(request, "check.decision", str(s.pk), player=s.player_name, old=old, new=s.decision,
               override=s.admin_id != request.user.pk)
        messages.success(request, "Decision saved.")
    return redirect("checks:detail", pk=s.pk)


@login_required
@require_POST
def cancel(request, pk):
    s = _get_visible(request.user, pk)
    if not can_cancel(request.user, s):
        raise PermissionDenied
    with transaction.atomic():
        s = CheckSession.objects.select_for_update().get(pk=s.pk)
        if s.is_open:
            # the token stays valid only so the running checker learns it was cancelled (410)
            s.status = CheckSession.CANCELLED
            s.save(update_fields=["status"])
            record(request, "check.cancelled", str(s.pk), player=s.player_name)
    messages.success(request, "Check cancelled; the code no longer works.")
    return redirect("checks:detail", pk=s.pk)


@perm_required("checks.delete")
@require_POST
def delete(request, pk):
    s = _get_visible(request.user, pk)
    record(request, "check.deleted", str(s.pk), player=s.player_name, verdict=s.verdict, admin=s.admin.username,
           code=s.code)
    s.delete()
    messages.success(request, "Check deleted.")
    return redirect("checks:dashboard")


@perm_required("checks.export")
def export(request, pk):
    s = _get_visible(request.user, pk)
    report = getattr(s, "report", None)
    if report is None:
        raise Http404
    record(request, "check.exported", str(s.pk), player=s.player_name)
    resp = HttpResponse(gzip.decompress(bytes(report.raw_gzip)), content_type="application/json")
    name = f"MoonCheck-{report.meta.get('checkId') or s.code}.json"
    resp["Content-Disposition"] = f'attachment; filename="{name}"'
    return resp


@login_required
def search(request):
    user = request.user
    q = request.GET.get("q", "").strip()[:200]
    results, too_short = [], False
    if q:
        if len(q) < 3:
            too_short = True
        else:
            results = (FindingRow.objects.filter(session__in=visible_sessions(user))
                       .filter(Q(evidence__icontains=q) | Q(title__icontains=q) | Q(detail__icontains=q))
                       .select_related("session", "session__admin").order_by("-session__created_at", "idx")[:300])
    top = []
    if not q:
        top = (FindingRow.objects.filter(session__in=visible_sessions(user), severity__in=["CRITICAL", "HIGH"])
               .values("title").annotate(n=Count("session", distinct=True)).order_by("-n")[:15])
    return render(request, "checks/search.html", {"q": q, "results": results, "too_short": too_short, "top": top})
