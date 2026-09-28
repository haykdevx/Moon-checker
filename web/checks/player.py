"""
The player's side: a private status page reached through the link the checker
shows after the code is accepted. The token is 256 random bits and only its hash
is stored. The page shows what concerns the player — status, outcome, the
evidence ids behind it, the admin's decision — never the admin's notes, and lets
the player appeal, download their own report, or ask for its deletion.

Russian by default, English through ?lang=en or the browser's language. No
cookie is set for the player: notices travel in the redirect's query string.
"""
import gzip
import secrets
from urllib.parse import urlencode

from django import forms
from django.db import transaction
from django.db.models import Q
from django.http import Http404, HttpResponse
from django.shortcuts import redirect, render
from django.urls import reverse
from django.utils import dateformat, timezone
from django.utils.html import format_html
from django.views.decorators.http import require_POST

from accounts.models import hash_token
from core import ratelimit
from core.audit import client_ip, record
from core.models import SiteSettings
from core.public_text import PLAYER, language

from .models import Appeal, CheckSession, DataRequest

APPEALABLE = ("BANNED", "REVIEW", "RECHECK")
KIND_TONES = {"DETECTION": "bad", "INDICATOR": "review", "CONCEALMENT": "review"}
KIND_LABELS = {
    "ru": {"DETECTION": "Точное совпадение", "INDICATOR": "Признак", "CONCEALMENT": "Сокрытие следов"},
    "en": {"DETECTION": "Exact match", "INDICATOR": "Indicator", "CONCEALMENT": "Concealment"},
}
SHOWN_EVIDENCE = 50


def _localize(form, t, fields):
    for name, (label, help_key) in fields.items():
        field = form.fields[name]
        field.label = t[label]
        field.help_text = t[help_key] if help_key else ""
        field.error_messages = {
            "required": t["e_required"],
            "min_length": t["e_short"].format(n=field.min_length),
            "max_length": t["e_long"].format(n=field.max_length),
        }


class AppealForm(forms.Form):
    statement = forms.CharField(max_length=4000, min_length=20, widget=forms.Textarea(attrs={"rows": 6}))
    contact = forms.CharField(max_length=100, required=False)

    def __init__(self, *args, t, **kwargs):
        super().__init__(*args, **kwargs)
        _localize(self, t, {"statement": ("f_statement", "f_statement_help"), "contact": ("f_contact", None)})


class DeletionForm(forms.Form):
    reason = forms.CharField(max_length=1000, required=False, widget=forms.Textarea(attrs={"rows": 3}))

    def __init__(self, *args, t, **kwargs):
        super().__init__(*args, **kwargs)
        _localize(self, t, {"reason": ("f_reason", None)})


def issue_player_token(session):
    """New private link for the player; returns the raw token (shown once)."""
    token = secrets.token_urlsafe(32)
    session.player_token_hash = hash_token(token)
    session.save(update_fields=["player_token_hash"])
    return token


def _session_for(request, token):
    ip = client_ip(request)
    if ratelimit.exceeded("player-miss", ip, 30):
        raise Http404
    s = None
    if token and len(token) <= 64:
        s = CheckSession.objects.select_related("admin").filter(player_token_hash=hash_token(token)).first()
    if s is None:
        ratelimit.hit("player-miss", ip, 600)
        raise Http404
    return s


def _private(response):
    response["X-Robots-Tag"] = "noindex, nofollow"
    # the token is in the URL: never send it to other sites. Not "no-referrer" — that makes
    # browsers send "Origin: null" on the page's own forms, which CSRF protection rejects.
    response["Referrer-Policy"] = "same-origin"
    response["Cache-Control"] = "no-store"
    return response


def _back(token, lang, anchor, sent=None):
    query = {"lang": lang}
    if sent:
        query["sent"] = sent
    return redirect(reverse("player:status", args=[token]) + "?" + urlencode(query) + "#" + anchor)


def _page(request, s, token, appeal_form=None, deletion_form=None, status=200):
    lang = language(request)
    t = PLAYER[lang]
    open_deletion = s.data_requests.filter(status=DataRequest.OPEN).exists()
    can_appeal = (s.status == CheckSession.COMPLETED and s.decision in APPEALABLE
                  and not s.appeals.filter(status=Appeal.OPEN).exists())
    fmt = "d.m.Y H:i" if lang == "ru" else "Y-m-d H:i"
    outcome = t["outcome"].get(s.verdict) if s.status == CheckSession.COMPLETED else None
    # the items that move the outcome, as VerdictEngine counts them
    moving = s.findings.filter(Q(kind="DETECTION") | Q(kind__in=("INDICATOR", "CONCEALMENT"),
                                                        severity__in=("MEDIUM", "HIGH", "CRITICAL")))
    evidence = [{"id": f"E{f.idx + 1}", "kind": KIND_LABELS[lang][f.kind], "tone": KIND_TONES[f.kind], "title": f.title}
                for f in moving.only("idx", "kind", "title")[:SHOWN_EVIDENCE + 1]]
    ctx = {
        "s": s, "token": token, "lang": lang, "t": t,
        "requested": format_html(t["requested"], admin=format_html("<b>{}</b>", s.admin.username),
                                 when=dateformat.format(timezone.localtime(s.created_at), fmt)),
        "status_label": t["status"].get(s.status, s.status),
        "outcome": outcome,
        "decision_label": t["decisions"].get(s.decision) if s.decision else None,
        "evidence": evidence[:SHOWN_EVIDENCE], "evidence_more": len(evidence) > SHOWN_EVIDENCE,
        "data_text": t["data_text"].format(days=SiteSettings.load().retention_days),
        "appeals": [{"title": t["appeal_n"].format(n=a.pk), "status": a.status, "label": t["appeal_status"].get(a.status, a.status),
                     "when": dateformat.format(timezone.localtime(a.created_at), fmt),
                     "statement": a.statement, "resolution": a.resolution} for a in s.appeals.all()],
        "appeal_form": appeal_form or (AppealForm(t=t) if can_appeal else None),
        "deletion_form": None if open_deletion else (deletion_form or DeletionForm(t=t)),
        "open_deletion": open_deletion,
        "has_report": hasattr(s, "report"),
        "sent": {"appeal": t["appeal_sent"], "deletion": t["delete_sent"],
                 "limit": t["appeal_limit"]}.get(request.GET.get("sent", "")),
        "switch_lang": "en" if lang == "ru" else "ru",
    }
    return _private(render(request, "player/status.html", ctx, status=status))


def status(request, token):
    return _page(request, _session_for(request, token), token)


@require_POST
def appeal(request, token):
    s = _session_for(request, token)
    lang = language(request)
    if ratelimit.hit("appeal-ip", client_ip(request), 3600) > 5:
        return _back(token, lang, "appeals", sent="limit")
    form = AppealForm(request.POST, t=PLAYER[lang])
    with transaction.atomic():
        s = CheckSession.objects.select_for_update().get(pk=s.pk)
        allowed = (s.status == CheckSession.COMPLETED and s.decision in APPEALABLE
                   and not s.appeals.filter(status=Appeal.OPEN).exists())
        if not allowed:
            return _back(token, lang, "appeals")
        if not form.is_valid():
            return _page(request, s, token, appeal_form=form, status=400)
        Appeal.objects.create(session=s, statement=form.cleaned_data["statement"],
                              contact=form.cleaned_data["contact"], decision_at_filing=s.decision,
                              ip=client_ip(request))
        record(request, "appeal.filed", str(s.pk), actor=None, decision=s.decision)
    return _back(token, lang, "appeals", sent="appeal")


@require_POST
def deletion(request, token):
    s = _session_for(request, token)
    lang = language(request)
    form = DeletionForm(request.POST, t=PLAYER[lang])
    if s.data_requests.filter(status=DataRequest.OPEN).exists():
        return _back(token, lang, "data")
    if not form.is_valid():
        return _page(request, s, token, deletion_form=form, status=400)
    DataRequest.objects.create(session=s, session_label=f"{s.code} · {s.player_name}"[:120],
                               reason=form.cleaned_data["reason"])
    record(request, "data.deletion_requested", str(s.pk), actor=None)
    return _back(token, lang, "data", sent="deletion")


def export(request, token):
    s = _session_for(request, token)
    report = getattr(s, "report", None)
    if report is None:
        raise Http404
    record(request, "data.exported_by_player", str(s.pk), actor=None)
    resp = HttpResponse(gzip.decompress(bytes(report.raw_gzip)), content_type="application/json")
    resp["Content-Disposition"] = f'attachment; filename="MoonCheck-{s.code}.json"'
    return _private(resp)
