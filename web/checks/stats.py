"""
Statistics for the checks a member can see: how many, what the checker found, what
the admins decided, how appeals went, and who carries the work. Charts are plain SVG
built here (no script, no inline style — the site's CSP allows neither). Test checks
are left out everywhere.
"""
from datetime import timedelta

from django.contrib.auth.decorators import login_required
from django.db.models import Avg, Count, F, Q
from django.db.models.functions import TruncDate
from django.shortcuts import render
from django.utils import timezone

from .models import Appeal, CheckSession, FindingRow
from .templatetags.moon import DECISIONS, OUTCOMES
from .views import visible_sessions

PERIODS = (7, 30, 90)
# outcome -> bar colour class (matches the tone classes of the badges)
OUTCOME_ORDER = ("VALIDATED_DETECTION", "REVIEW_REQUIRED", "INCOMPLETE_SCAN", "UNSUPPORTED_CONFIGURATION",
                 "NO_EVIDENCE")


def daily_bars(days, counts_by_day, width=720, height=180, pad=24):
    """Stacked day bars: [{x, w, parts: [{y, h, tone}], label, total}] in SVG coordinates."""
    n = len(days)
    if n == 0:
        return {"bars": [], "width": width, "height": height, "max": 0}
    peak = max([sum(counts_by_day.get(d, {}).values()) for d in days] + [1])
    slot = (width - pad) / n
    bar_w = max(2.0, slot * 0.7)
    bars = []
    for i, d in enumerate(days):
        by_outcome = counts_by_day.get(d, {})
        y = height - pad
        parts = []
        for outcome in OUTCOME_ORDER + ("OTHER",):
            c = by_outcome.get(outcome, 0)
            if not c:
                continue
            h = (height - 2 * pad) * c / peak
            y -= h
            parts.append({"y": round(y, 1), "h": round(h, 1), "tone": OUTCOMES.get(outcome, ("", "muted"))[1],
                          "outcome": outcome, "n": c})
        bars.append({"x": round(pad + i * slot + (slot - bar_w) / 2, 1), "w": round(bar_w, 1), "parts": parts,
                     "day": d, "total": sum(by_outcome.values()),
                     "label": d.strftime("%d.%m") if (i % max(1, n // 8) == 0 or i == n - 1) else ""})
    return {"bars": bars, "width": width, "height": height, "max": peak, "baseline": height - pad}


def share_rows(counter, labels, order=None):
    """[{key, label, n, pct}] sorted, with percentages for simple horizontal bars."""
    total = sum(counter.values()) or 1
    keys = order or sorted(counter, key=lambda k: -counter[k])
    return [{"key": k, "label": labels.get(k, (k,))[0] if isinstance(labels.get(k), tuple) else labels.get(k, k),
             "n": counter.get(k, 0), "pct": round(100 * counter.get(k, 0) / total)}
            for k in keys if counter.get(k, 0)]


@login_required
def stats(request):
    try:
        days = int(request.GET.get("days", 30))
    except ValueError:
        days = 30
    days = days if days in PERIODS else 30
    now = timezone.now()
    since = now - timedelta(days=days)
    real = visible_sessions(request.user).filter(is_test=False)
    period = real.filter(created_at__gte=since)
    done = period.filter(status=CheckSession.COMPLETED)

    per_day = {}
    for row in (done.annotate(day=TruncDate("completed_at", tzinfo=timezone.get_current_timezone()))
                .values("day", "verdict").annotate(n=Count("pk"))):
        key = row["verdict"] if row["verdict"] in OUTCOME_ORDER else "OTHER"
        per_day.setdefault(row["day"], {})
        per_day[row["day"]][key] = per_day[row["day"]].get(key, 0) + row["n"]
    today = timezone.localdate()
    day_list = [today - timedelta(days=i) for i in range(days - 1, -1, -1)]

    outcomes = {r["verdict"]: r["n"] for r in done.values("verdict").annotate(n=Count("pk"))}
    decisions = {r["decision"]: r["n"] for r in done.exclude(decision="").values("decision").annotate(n=Count("pk"))}
    undecided = done.filter(decision="").count()
    durations = done.exclude(scan_started_at=None).exclude(completed_at=None).annotate(
        took=F("completed_at") - F("scan_started_at")).aggregate(avg=Avg("took"))["avg"]
    appeals = Appeal.objects.filter(session__in=real, created_at__gte=since)
    appeal_counts = {r["status"]: r["n"] for r in appeals.values("status").annotate(n=Count("pk"))}
    resolved = sum(v for k, v in appeal_counts.items() if k != Appeal.OPEN)
    overturned = appeal_counts.get(Appeal.OVERTURNED, 0)

    important = (FindingRow.objects.filter(session__in=done)
                 .filter(Q(kind="DETECTION") | Q(kind__in=("INDICATOR", "CONCEALMENT"),
                                                  severity__in=("MEDIUM", "HIGH", "CRITICAL")))
                 .values("title", "kind").annotate(checks=Count("session", distinct=True)).order_by("-checks")[:10])
    admins = (period.values("admin__username").annotate(
        created=Count("pk"), finished=Count("pk", filter=Q(status=CheckSession.COMPLETED)),
        banned=Count("pk", filter=Q(decision="BANNED"))).order_by("-created")[:12]
              if request.user.can("checks.view_all") else [])
    peak_admin = max([a["created"] for a in admins] + [1])

    return render(request, "checks/stats.html", {
        "days": days, "periods": PERIODS,
        "kpi": {
            "created": period.count(), "completed": done.count(),
            "banned": decisions.get("BANNED", 0), "cleared": decisions.get("CLEARED", 0),
            "undecided": undecided,
            "avg_minutes": round(durations.total_seconds() / 60, 1) if durations else None,
            "appeals": sum(appeal_counts.values()), "overturned": overturned,
            "overturn_pct": round(100 * overturned / resolved) if resolved else None,
        },
        "chart": daily_bars(day_list, per_day),
        "outcome_rows": share_rows(outcomes, OUTCOMES, [o for o in OUTCOME_ORDER if o in outcomes]
                                   + [o for o in outcomes if o not in OUTCOME_ORDER]),
        "decision_rows": share_rows(decisions, DECISIONS),
        "important": important,
        "admins": [dict(a, pct=round(100 * a["created"] / peak_admin)) for a in admins],
        "legend": OUTCOME_ORDER,
    })


@login_required
def player_history(request):
    """Everything known about one player: by nickname, Steam account or PC name (any of them)."""
    name = request.GET.get("name", "").strip()[:64]
    steam = request.GET.get("steam", "").strip()[:100]
    pc = request.GET.get("pc", "").strip()[:64]
    match = Q(pk__in=[])
    if name:
        match |= Q(player_name__iexact=name)
    if steam:
        match |= Q(player_steam=steam)
    if pc:
        match |= Q(client__hostname=pc)
    checks = list(visible_sessions(request.user).filter(match).order_by("-created_at")[:200]) if (name or steam or pc) \
        else []
    done = [c for c in checks if c.status == CheckSession.COMPLETED]
    findings = (FindingRow.objects.filter(session__in=[c.pk for c in done])
                .filter(Q(kind="DETECTION") | Q(kind__in=("INDICATOR", "CONCEALMENT"),
                                                 severity__in=("MEDIUM", "HIGH", "CRITICAL")))
                .values("title", "kind").annotate(checks=Count("session", distinct=True)).order_by("-checks")[:10])
    return render(request, "checks/player_history.html", {
        "name": name, "steam": steam, "pc": pc, "checks": checks,
        "summary": {
            "total": len(checks), "finished": len(done),
            "banned": sum(1 for c in done if c.decision == "BANNED"),
            "cleared": sum(1 for c in done if c.decision == "CLEARED"),
            "flagged": sum(1 for c in done if c.verdict in ("VALIDATED_DETECTION", "REVIEW_REQUIRED")),
        },
        "names": sorted({c.player_name for c in checks}),
        "pcs": sorted({c.client.get("hostname") for c in checks if c.client.get("hostname")}),
        "steams": sorted({c.player_steam for c in checks if c.player_steam}),
        "findings": findings,
    })
