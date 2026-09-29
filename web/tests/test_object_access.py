"""
Object-level access over direct HTTP: an admin who may not see every check gets nothing from
another admin's check — no page, no JSON, no action — whatever URL or method is tried. Player
links open nothing without the exact token.
"""
import json

from django.core.cache import cache
from django.test import Client, TestCase

from checks.models import Appeal, CheckSession, DataRequest
from core.models import SiteSettings

from .helpers import bind, canonical, claim_body, evidence_item, gz, make_session, make_user, report_v2


class ObjectAccessTests(TestCase):
    def setUp(self):
        cache.clear()
        s = SiteSettings.load()
        s.require_2fa = False
        s.save()
        self.alice = make_user("alice", "admin")        # no checks.view_all
        self.bob = make_user("bob", "admin")
        self.theirs = self.completed(make_session(self.bob))
        self.appeal = Appeal.objects.create(session=self.theirs, statement="not me", contact="x")
        self.request_ = DataRequest.objects.create(session=self.theirs, session_label="x")
        self.client.force_login(self.alice)

    def completed(self, s):
        c = Client()
        d = c.post("/api/v1/claim", data=json.dumps(claim_body(s.code)), content_type="application/json").json()
        payload = bind(report_v2("REVIEW_REQUIRED", [evidence_item(1)], check_id="MOON-260929-" + s.code.replace("-", "")), d)
        r = c.post(f"/api/v1/sessions/{d['sessionId']}/report", data=gz(canonical(payload)),
                   content_type="application/json", HTTP_CONTENT_ENCODING="gzip", HTTP_AUTHORIZATION=f"Bearer {d['token']}")
        self.assertEqual(r.status_code, 200, r.content)
        return CheckSession.objects.get(pk=s.pk)

    def test_another_admins_check_is_invisible_to_every_endpoint(self):
        pk = self.theirs.pk
        for method, url, data in [
            ("get", f"/checks/{pk}/", None),
            ("get", f"/checks/{pk}/live/", None),
            ("get", f"/checks/{pk}/evidence.json", None),
            ("post", f"/checks/{pk}/decide/", {"decision": "BANNED", "note": "x"}),
            ("post", f"/checks/{pk}/cancel/", {}),
            ("post", f"/checks/{pk}/delete/", {}),
            ("post", f"/checks/{pk}/player-link/", {}),
            ("post", f"/appeals/{self.appeal.pk}/resolve/", {"status": "REJECTED", "resolution": "x"}),
            ("post", f"/requests/{self.request_.pk}/handle/", {"status": "DONE", "note": ""}),
        ]:
            r = getattr(self.client, method)(url, data or {})
            self.assertIn(r.status_code, (403, 404), f"{method.upper()} {url} -> {r.status_code}")
        self.theirs.refresh_from_db()
        self.assertEqual((self.theirs.decision, self.theirs.status), ("", CheckSession.COMPLETED))
        self.assertTrue(CheckSession.objects.filter(pk=pk).exists())
        self.assertEqual(Appeal.objects.get(pk=self.appeal.pk).status, Appeal.OPEN)
        self.assertEqual(DataRequest.objects.get(pk=self.request_.pk).status, DataRequest.OPEN)

    def test_lists_search_and_statistics_leave_it_out(self):
        for url in ("/", f"/checks/search/?q={self.theirs.player_name}", "/stats/",
                    f"/player/?name={self.theirs.player_name}", "/appeals/"):
            html = self.client.get(url).content.decode()
            self.assertNotIn(str(self.theirs.pk), html, url)
            self.assertNotIn(self.theirs.code, html, url)

    def test_a_request_whose_check_is_gone_needs_the_right_to_see_every_check(self):
        from accounts.models import Role
        Role.objects.create(slug="cleaner", name="Cleaner", rank=40, permissions=["checks.delete"])
        self.client.force_login(make_user("carol", "cleaner"))   # may delete, may not see every check
        orphan = DataRequest.objects.create(session=None, session_label="x")
        r = self.client.post(f"/requests/{orphan.pk}/handle/", {"status": "DONE", "note": ""})
        self.assertEqual(r.status_code, 404)
        self.assertEqual(DataRequest.objects.get(pk=orphan.pk).status, DataRequest.OPEN)
        r = self.client.post(f"/requests/{self.request_.pk}/handle/", {"status": "DONE", "note": ""})
        self.assertEqual(r.status_code, 404, "and another admin's check stays invisible to a deleter too")

    def test_player_pages_need_the_exact_token(self):
        anon = Client()
        for url in ("/p/x/", "/p/" + "a" * 43 + "/", "/p/" + "a" * 43 + "/report.json"):
            self.assertEqual(anon.get(url).status_code, 404, url)

    def test_audit_log_and_settings_need_their_permissions(self):
        self.assertEqual(self.client.get("/audit/").status_code, 403)
        self.assertEqual(self.client.get("/settings/").status_code, 403)
        self.assertEqual(self.client.post("/settings/builds/add/", {"sha256": "ab" * 32, "label": "x"}).status_code, 403)


class PlayerDataRetentionTests(TestCase):
    """What identifies a player leaves the audit trail with their check; the trail itself expires."""

    def setUp(self):
        cache.clear()
        s = SiteSettings.load()
        s.require_2fa = False
        s.save()
        self.owner = make_user("boss", "owner")
        self.session = ObjectAccessTests.completed(self, make_session(self.owner, player_name="Ivan Petrov"))

    def events(self):
        from core.models import AuditEvent
        return list(AuditEvent.objects.filter(target=str(self.session.pk)))

    def test_a_deletion_request_removes_the_player_from_the_audit_trail(self):
        before = self.events()
        self.assertTrue(any("Ivan Petrov" in json.dumps(e.details) for e in before)
                        or any(e.ip for e in before), "the trail did hold player data")
        req = DataRequest.objects.create(session=self.session, session_label="Ivan Petrov")
        self.client.force_login(self.owner)
        self.client.post(f"/requests/{req.pk}/handle/", {"status": "DONE", "note": ""})
        after = self.events()
        self.assertTrue(after, "what happened is still on record")
        for e in after:
            self.assertNotIn("Ivan Petrov", json.dumps(e.details), e.action)
            self.assertNotIn("DESKTOP-1", json.dumps(e.details), e.action)
            if e.actor_id is None:
                self.assertIsNone(e.ip, e.action)
                self.assertEqual(e.user_agent, "", e.action)

    def test_retention_scrubs_purged_checks_and_expires_old_events(self):
        from datetime import timedelta
        from django.utils import timezone
        from checks import housekeeping
        from core.models import AuditEvent
        site = SiteSettings.load()
        site.retention_days = 30
        site.save()
        CheckSession.objects.filter(pk=self.session.pk).update(created_at=timezone.now() - timedelta(days=31))
        ancient = AuditEvent.objects.create(action="login", target="x")
        AuditEvent.objects.filter(pk=ancient.pk).update(at=timezone.now() - timedelta(days=800))
        self.assertEqual(housekeeping.purge_old(), 1)
        self.assertFalse(AuditEvent.objects.filter(pk=ancient.pk).exists())
        for e in self.events():
            self.assertNotIn("Ivan Petrov", json.dumps(e.details))

    def test_a_flood_of_progress_updates_is_limited(self):
        s = make_session(self.owner)
        d = Client().post("/api/v1/claim", data=json.dumps(claim_body(s.code)), content_type="application/json").json()
        codes = [Client().post(f"/api/v1/sessions/{d['sessionId']}/progress", data=json.dumps({"done": 1, "total": 9}),
                               content_type="application/json", HTTP_AUTHORIZATION=f"Bearer {d['token']}").status_code
                 for _ in range(125)]
        self.assertEqual(codes[:120], [200] * 120)
        self.assertEqual(codes[-1], 429)
