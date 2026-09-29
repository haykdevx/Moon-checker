from datetime import timedelta

from django.core.cache import cache
from django.test import TestCase
from django.utils import timezone

from checks.models import Appeal, CheckSession

from .helpers import make_session, make_user
from .test_player import no_2fa


def finished(admin, verdict, decision="", days_ago=1, **extra):
    s = make_session(admin, status=CheckSession.COMPLETED, verdict=verdict, decision=decision, **extra)
    when = timezone.now() - timedelta(days=days_ago)
    CheckSession.objects.filter(pk=s.pk).update(created_at=when, completed_at=when,
                                                scan_started_at=when - timedelta(minutes=3))
    return CheckSession.objects.get(pk=s.pk)


class StatsTests(TestCase):
    def setUp(self):
        cache.clear()
        no_2fa()
        self.head = make_user("head", "head-admin")
        self.admin = make_user("adm", "admin")

    def test_counts_leave_test_checks_out_and_the_chart_is_valid_svg(self):
        finished(self.admin, "REVIEW_REQUIRED", "BANNED")
        finished(self.admin, "NO_EVIDENCE", "CLEARED", days_ago=3)
        finished(self.admin, "INCOMPLETE_SCAN", days_ago=5)
        finished(self.admin, "VALIDATED_DETECTION", "BANNED", is_test=True)
        self.client.force_login(self.head)
        page = self.client.get("/stats/?days=7")
        self.assertEqual(page.status_code, 200)
        kpi = page.context["kpi"]
        self.assertEqual((kpi["completed"], kpi["banned"], kpi["cleared"], kpi["undecided"]), (3, 1, 1, 1))
        self.assertEqual(kpi["avg_minutes"], 3.0)
        self.assertContains(page, "<svg")
        body = page.content.decode()
        self.assertNotRegex(body, r'(?:x|y|width|height)="\d+,\d+"', "decimal commas would break the SVG")
        self.assertEqual(len(page.context["chart"]["bars"]), 7)

    def test_a_plain_admin_sees_only_their_own_numbers(self):
        finished(self.head, "REVIEW_REQUIRED", "BANNED")
        finished(self.admin, "NO_EVIDENCE", "CLEARED")
        self.client.force_login(self.admin)
        page = self.client.get("/stats/")
        self.assertEqual(page.context["kpi"]["completed"], 1)
        self.assertEqual(page.context["admins"], [], "the per-admin table needs checks.view_all")

    def test_overturned_appeals_are_measured(self):
        s = finished(self.admin, "REVIEW_REQUIRED", "BANNED")
        Appeal.objects.create(session=s, statement="x" * 30, status=Appeal.OVERTURNED)
        Appeal.objects.create(session=s, statement="y" * 30, status=Appeal.UPHELD)
        self.client.force_login(self.head)
        kpi = self.client.get("/stats/").context["kpi"]
        self.assertEqual((kpi["appeals"], kpi["overturned"], kpi["overturn_pct"]), (2, 1, 50))

    def test_unknown_period_falls_back_to_thirty_days(self):
        self.client.force_login(self.head)
        self.assertEqual(self.client.get("/stats/?days=abc").context["days"], 30)
        self.assertEqual(self.client.get("/stats/?days=365").context["days"], 30)


class PlayerHistoryTests(TestCase):
    def setUp(self):
        cache.clear()
        no_2fa()
        self.head = make_user("head", "head-admin")
        self.admin = make_user("adm", "admin")

    def test_a_player_is_found_by_nickname_steam_or_pc(self):
        a = finished(self.admin, "REVIEW_REQUIRED", "BANNED", player_name="Vortex", player_steam="7656119")
        finished(self.admin, "NO_EVIDENCE", "CLEARED", player_name="vortex_2", player_steam="7656119")
        c = finished(self.admin, "NO_EVIDENCE", player_name="Другой")
        CheckSession.objects.filter(pk=c.pk).update(client={"hostname": "GAMING-PC"})
        CheckSession.objects.filter(pk=a.pk).update(client={"hostname": "GAMING-PC"})
        self.client.force_login(self.head)
        by_name = self.client.get("/player/?name=VORTEX")
        self.assertEqual(by_name.context["summary"]["total"], 1)
        both = self.client.get("/player/?name=Vortex&steam=7656119&pc=GAMING-PC")
        self.assertEqual(both.context["summary"]["total"], 3)
        self.assertEqual(both.context["summary"]["banned"], 1)
        self.assertIn("GAMING-PC", both.context["pcs"])

    def test_nothing_without_a_query_and_no_foreign_checks(self):
        finished(self.head, "REVIEW_REQUIRED", player_name="Hidden")
        self.client.force_login(self.admin)
        self.assertEqual(self.client.get("/player/").context["checks"], [])
        self.assertEqual(self.client.get("/player/?name=Hidden").context["checks"], [],
                         "an admin without view_all never sees another admin's checks")

    def test_detail_links_to_the_history_and_shows_the_parts(self):
        s = finished(self.admin, "INCOMPLETE_SCAN", player_name="Vortex")
        from checks.models import Report
        Report.objects.create(session=s, raw_gzip=b"", sha256="0" * 64, size_bytes=0, meta={"coverage": {
            "required": ["files", "deleted"], "modules": {"files": "OK", "deleted": "TIMEOUT"},
            "errors": {"deleted": "time budget of 300s exceeded"}}})
        finished(self.admin, "NO_EVIDENCE", player_name="Vortex", days_ago=9)
        self.client.force_login(self.admin)
        page = self.client.get(f"/checks/{s.pk}/")
        self.assertContains(page, "/player/?name=Vortex")
        self.assertContains(page, "part-bad")
        self.assertContains(page, "time budget of 300s exceeded")
