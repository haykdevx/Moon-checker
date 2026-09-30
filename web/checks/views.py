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
from django.urls import reverse
from django.utils import timezone
from django.utils.translation import gettext as _t, gettext_lazy as _
from django.views.decorators.http import require_POST

from accounts.models import User
from accounts.views import perm_required
from core.audit import record
from core.models import SiteSettings

from . import codes, policy, trust
from .models import Appeal, CheckSession, DataRequest, FindingRow
from .templatetags.moon import OUTCOMES as OUTCOME_LABELS, collector_name

FINDINGS_RENDER_LIMIT = 5000
CATALOG_PATH = __import__("pathlib").Path(__file__).resolve().parent / "data" / "coverage.json"


def load_catalog():
    import json
    return json.loads(CATALOG_PATH.read_text(encoding="utf-8"))


class NewCheckForm(forms.ModelForm):
    class Meta:
        model = CheckSession
        fields = ["player_name", "player_steam", "player_discord", "note", "is_test"]
        labels = {
            "player_name": _("Player's nickname"),
            "player_steam": _("Steam (link or ID)"),
            "player_discord": _("Discord"),
            "note": _("Note for admins"),
            "is_test": _("Test check — left out of statistics"),
        }
        help_texts = {"player_name": _("As on the server. Nothing else is required."), "is_test": ""}
        widgets = {
            "player_name": forms.TextInput(attrs={"autofocus": True, "autocomplete": "off"}),
            "player_steam": forms.TextInput(attrs={"placeholder": "https://steamcommunity.com/id/…"}),
            "player_discord": forms.TextInput(),
            "note": forms.Textarea(attrs={"rows": 2}),
        }


DECISION_BUTTONS = ("CLEARED", "BANNED", "RECHECK", "REVIEW")


class DecisionForm(forms.Form):
    decision = forms.ChoiceField(choices=[("", "—")] + [(d, d) for d in DECISION_BUTTONS], required=False)
    note = forms.CharField(label=_("Comment — only admins see it"), max_length=1000, required=False,
                           widget=forms.Textarea(attrs={"rows": 3}))


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
    """Work queues first — waiting for your decision, running, waiting for the player — then history.
    Any search or filter switches to one flat, filterable list."""
    user = request.user
    qs, f = _filtered(request)
    filtering = any(f[k] for k in ("q", "status", "verdict", "decision", "admin", "mine"))
    visible = visible_sessions(user)
    queues = {
        "decide": list(visible.filter(status=CheckSession.COMPLETED, decision="").order_by("-completed_at")[:50]),
        "running": list(visible.filter(status__in=CheckSession.LIVE_STATUSES + (CheckSession.ABANDONED,))
                        .order_by("-claimed_at")[:50]),
        "waiting": list(visible.filter(status=CheckSession.WAITING).order_by("-created_at")[:50]),
    }
    history = qs if filtering else qs.exclude(status__in=CheckSession.OPEN_STATUSES + (CheckSession.ABANDONED,)) \
        .exclude(status=CheckSession.COMPLETED, decision="")
    page = Paginator(history, 25).get_page(request.GET.get("page"))
    admins = User.objects.filter(check_sessions__isnull=False).distinct().order_by("username") \
        if user.can("checks.view_all") else []
    params = request.GET.copy()
    params.pop("page", None)
    params.pop("fragment", None)
    from .templatetags.moon import DECISIONS, STATUSES
    ctx = {"page": page, "f": f, "filtering": filtering, "queues": queues, "admins": admins,
           "qs": params.urlencode(), "can_create": user.can("checks.create"),
           "show_admin": user.can("checks.view_all"),
           "appeals_open": Appeal.objects.filter(session__in=visible, status=Appeal.OPEN).count(),
           "outcomes": [(k, v[0]) for k, v in OUTCOME_LABELS.items() if k in policy.OUTCOMES],
           "statuses": list(STATUSES.items()), "decisions": list(DECISIONS.items()),
           "any_open": bool(queues["running"] or queues["waiting"]) or any(s.is_open for s in page)}
    if request.GET.get("fragment") == "1":
        return render(request, "checks/_queues.html", ctx)
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
            messages.error(request, _t("Could not allocate a code, try again."))
            return redirect("checks:new")
        record(request, "check.created", str(session.pk), player=session.player_name, code=session.code)
        return redirect("checks:detail", pk=session.pk)
    return render(request, "checks/new.html", {"form": form})


SEVERITY_RANK = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def moves_outcome(f):
    """The evidence the outcome rests on — as VerdictEngine counts it."""
    return f.kind == "DETECTION" or (f.kind in ("INDICATOR", "CONCEALMENT") and SEVERITY_RANK.get(f.severity, 0) >= 2)


def split_findings(findings):
    """(important groups, the rest). Traces of one file seen by several collectors form one group."""
    groups, by_subject, other = [], {}, []
    for f in findings:
        if not moves_outcome(f):
            other.append(f)
            continue
        subject = (f.evidence or f.title).strip().lower()
        if subject in by_subject:
            by_subject[subject]["also"].append(f)
            continue
        group = {"main": f, "also": []}
        by_subject[subject] = group
        groups.append(group)
    order = {"DETECTION": 0, "CONCEALMENT": 1, "INDICATOR": 2}
    groups.sort(key=lambda g: (order.get(g["main"].kind, 3), -SEVERITY_RANK.get(g["main"].severity, 0),
                               g["main"].idx))
    return groups, other


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
    from core.models import AuditEvent
    timeline = sorted((f for f in findings if f.when), key=lambda f: f.when, reverse=True)[:200]
    audit_trail = AuditEvent.objects.filter(target=str(session.pk)).order_by("at")[:100] \
        if user.can("audit.view") or session.admin_id == user.pk else []
    coverage = meta.get("coverage") or {}
    coverage_done = sum(1 for m in coverage.get("required", []) if coverage.get("modules", {}).get(m) == "OK")
    important, other = split_findings(findings)
    groups = trust.by_dimension(session.flags)
    parts = [{"id": m, "status": coverage.get("modules", {}).get(m, "?"),
              "ok": coverage.get("modules", {}).get(m) == "OK",
              "error": (coverage.get("errors") or {}).get(m, "")} for m in coverage.get("required", [])]
    return render(request, "checks/detail.html", {
        "parts": parts,
        "s": session, "findings": findings, "truncated": truncated, "modules": sorted(modules.items()),
        "important": important, "other": other,
        "warnings": [fl for dim in trust.DIMENSIONS for fl in groups[dim] if fl.get("level") in ("bad", "warn")],
        "assurance_rows": [{"dim": dim, "title": ASSURANCE_TITLES[dim], "flags": groups[dim],
                            "level": assurance_level(dim, groups[dim])}
                           for dim in trust.DIMENSIONS],
        "env": env, "meta": meta, "related": related, "coverage_done": coverage_done,
        "kinds": sorted({f.kind for f in findings if f.kind}),
        "timeline": timeline, "audit_trail": audit_trail,
        "appeals": session.appeals.select_related("resolved_by"),
        "data_requests": session.data_requests.select_related("handled_by"),
        "can_resolve": user.can("checks.decide_any"),
        "player_link": request.session.pop(f"player_link_{session.pk}", None),
        "can_decide": can_decide(user, session) and session.status == CheckSession.COMPLETED,
        "can_cancel": can_cancel(user, session),
        "can_export": user.can("checks.export") and session.status == CheckSession.COMPLETED,
        "can_delete": user.can("checks.delete"),
        "decision_form": DecisionForm(initial={"note": session.decision_note}),
        "decision_buttons": DECISION_BUTTONS,
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
        "moduleLabel": str(collector_name(s.progress_module)) if s.progress_module else "",
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
        messages.success(request, _t("Decision saved."))
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
    messages.success(request, _t("Check cancelled; the code no longer works."))
    return redirect("checks:detail", pk=s.pk)


@perm_required("checks.delete")
@require_POST
def delete(request, pk):
    s = _get_visible(request.user, pk)
    record(request, "check.deleted", str(s.pk), player=s.player_name, verdict=s.verdict, admin=s.admin.username,
           code=s.code)
    s.delete()
    messages.success(request, _t("Check deleted."))
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


@login_required
def rules(request):
    """What every collector inspects, its blind spots, and what each named rule means."""
    catalog = load_catalog()
    seen = (FindingRow.objects.filter(session__in=visible_sessions(request.user)).exclude(rule_id="")
            .values("rule_id", "kind").annotate(n=Count("session", distinct=True)).order_by("-n")[:100])
    return render(request, "checks/rules.html", {"catalog": catalog, "seen": seen})


class ResolveAppealForm(forms.Form):
    # no preselected answer: a slip must not uphold (or overturn) an appeal
    status = forms.ChoiceField(label=_("Outcome"),
                               choices=[("", _("Choose…"))] + [c for c in Appeal.STATUS_CHOICES if c[0] != Appeal.OPEN])
    resolution = forms.CharField(label=_("Answer to the player"), max_length=2000, min_length=10,
                                 widget=forms.Textarea(attrs={"rows": 3}),
                                 help_text=_("The player sees it on their page."))


class HandleRequestForm(forms.Form):
    status = forms.ChoiceField(label=_("What to do"),
                               choices=[("", _("Choose…"))] + [c for c in DataRequest.STATUS_CHOICES
                                                               if c[0] != DataRequest.OPEN])
    note = forms.CharField(label=_("Reason (required when refusing)"), max_length=1000, required=False,
                           widget=forms.Textarea(attrs={"rows": 2}))


@login_required
def appeals(request):
    """Open appeals and data requests for the checks this member can see."""
    visible = visible_sessions(request.user)
    return render(request, "checks/appeals.html", {
        "appeals": Appeal.objects.filter(session__in=visible).select_related("session", "session__admin",
                                                                            "resolved_by")[:200],
        "requests": DataRequest.objects.filter(session__in=visible).select_related("session", "handled_by")[:200]
        if request.user.can("checks.delete") else [],
        "resolve_form": ResolveAppealForm(), "handle_form": HandleRequestForm(),
    })


@perm_required("checks.decide_any")
@require_POST
def resolve_appeal(request, pk):
    appeal = get_object_or_404(Appeal.objects.select_related("session"), pk=pk, status=Appeal.OPEN,
                               session__in=visible_sessions(request.user))
    s = appeal.session
    if s.decision_by_id == request.user.pk and not request.user.is_owner:
        messages.error(request, _t("An appeal must be resolved by a different admin than the one who decided."))
        return redirect("checks:appeals")
    form = ResolveAppealForm(request.POST)
    if not form.is_valid():
        messages.error(request, _t("Choose an outcome and explain it (at least 10 characters)."))
        return redirect("checks:appeals")
    with transaction.atomic():
        appeal.status, appeal.resolution = form.cleaned_data["status"], form.cleaned_data["resolution"]
        appeal.resolved_by, appeal.resolved_at = request.user, timezone.now()
        appeal.save()
        new_decision = {Appeal.OVERTURNED: "CLEARED", Appeal.RECHECK: "RECHECK"}.get(appeal.status)
        if new_decision:
            s.decision, s.decision_note = new_decision, f"Appeal #{appeal.pk}: {appeal.resolution}"[:1000]
            s.decision_by, s.decision_at = request.user, timezone.now()
            s.save(update_fields=["decision", "decision_note", "decision_by", "decision_at"])
    record(request, "appeal.resolved", str(s.pk), appeal=appeal.pk, outcome=appeal.status, decision=s.decision)
    messages.success(request, _t("Appeal resolved."))
    return redirect("checks:appeals")


@perm_required("checks.delete")
@require_POST
def handle_request(request, pk):
    req = get_object_or_404(DataRequest, pk=pk, status=DataRequest.OPEN)
    if req.session is None:
        # the check is already gone: only someone who may see every check handles what is left of it
        if not request.user.can("checks.view_all"):
            raise Http404
    elif not visible_sessions(request.user).filter(pk=req.session_id).exists():
        raise Http404
    form = HandleRequestForm(request.POST)
    if not form.is_valid() or (form.cleaned_data["status"] == DataRequest.REFUSED and not form.cleaned_data["note"]):
        messages.error(request, _t("Choose what to do with the request. Refusing it needs a reason."))
        return redirect("checks:appeals")
    target = str(req.session_id)
    req.status, req.note = form.cleaned_data["status"], form.cleaned_data["note"]
    req.handled_by, req.handled_at = request.user, timezone.now()
    req.save()
    if req.status == DataRequest.DONE and req.session is not None:
        req.session.delete()  # report, findings and appeals go with it; the request row stays as the record
        from core.audit import scrub_player_data
        scrub_player_data([target])  # and the audit trail keeps what happened, not who the player was
    record(request, "data.deletion_" + ("done" if req.status == DataRequest.DONE else "refused"), target,
           note=req.note)
    messages.success(request, _t("Request handled."))
    return redirect("checks:appeals")


@login_required
@require_POST
def player_link(request, pk):
    s = _get_visible(request.user, pk)
    if not (s.admin_id == request.user.pk or request.user.can("checks.decide_any")):
        raise PermissionDenied
    from .player import issue_player_token
    token = issue_player_token(s)
    request.session[f"player_link_{s.pk}"] = request.build_absolute_uri(reverse("player:status", args=[token]))
    record(request, "check.player_link_reissued", str(s.pk))
    return redirect("checks:detail", pk=s.pk)


# the five questions about a delivered report, kept apart on the check page (checks/trust.py)
ASSURANCE_TITLES = {
    "session": _("Delivered for this check"),
    "consistency": _("Report consistency — checked by the panel"),
    "artifact": _("Checker build — claimed by the player's PC"),
    "collector": _("Did the official checker really run?"),
    "device": _("About the PC — reported by the checker"),
}


def assurance_level(dim, flags):
    """Colour of one question: never green for what the player's PC only claims."""
    if dim == trust.COLLECTOR:
        return "none"
    level = trust.worst(flags)
    if level == "ok" and dim in (trust.ARTIFACT, trust.DEVICE):
        return "info"
    return level
