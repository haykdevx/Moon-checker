import json

from django.core.cache import cache
from django.test import TestCase

from checks.models import Appeal, CheckSession, DataRequest
from core.models import AuditEvent, SiteSettings

from .helpers import canonical, client_info, evidence_item, gz, make_session, make_user, report_v2


def no_2fa():
    s = SiteSettings.load()
    s.require_2fa = False
    s.save()


class PlayerFlowTests(TestCase):
    def setUp(self):
        cache.clear()
        no_2fa()
        self.admin = make_user("adm", "admin")
        self.head = make_user("head", "head-admin")
        self.owner = make_user("boss", "owner")
        self.session = make_session(self.admin)

    def complete_check(self, session=None):
        s = session or self.session
        anon = self.client_class()
        d = anon.post("/api/v1/claim", data=json.dumps({"code": s.code, "client": client_info()}),
                      content_type="application/json").json()
        payload = report_v2("REVIEW_REQUIRED", [evidence_item(1, "INDICATOR", "HIGH")],
                            reasons=[{"code": "review.indicator", "text": "x", "evidence": ["E1"]}])
        r = anon.post(f"/api/v1/sessions/{d['sessionId']}/report", data=gz(canonical(payload)),
                      content_type="application/json", HTTP_CONTENT_ENCODING="gzip",
                      HTTP_AUTHORIZATION=f"Bearer {d['token']}")
        self.assertEqual(r.status_code, 200, r.content)
        token = d["statusUrl"].rstrip("/").split("/")[-1]
        return CheckSession.objects.get(pk=s.pk), token

    def decide(self, s, decision, by):
        s.decision, s.decision_by = decision, by
        s.save(update_fields=["decision", "decision_by"])

    def test_claim_returns_a_private_status_link(self):
        s, token = self.complete_check()
        self.assertTrue(s.player_token_hash)
        self.assertNotIn(token, s.player_token_hash)
        r = self.client.get(f"/p/{token}/")
        self.assertContains(r, s.code)
        self.assertEqual(r["X-Robots-Tag"], "noindex, nofollow")
        self.assertNotContains(r, "decision_note")  # admin notes never reach the player page

    def test_unknown_tokens_are_404_and_throttled(self):
        for _ in range(30):
            self.assertEqual(self.client.get("/p/not-a-real-token/").status_code, 404)
        s, token = self.complete_check()
        self.assertEqual(self.client.get(f"/p/{token}/").status_code, 404, "guessing is throttled per IP")

    def test_player_can_export_own_report_and_request_deletion(self):
        s, token = self.complete_check()
        r = self.client.get(f"/p/{token}/report.json")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(json.loads(r.content)["schema"], "moon-evidence/2")
        self.client.post(f"/p/{token}/delete/", {"reason": "please remove"})
        self.assertEqual(DataRequest.objects.filter(session=s, status=DataRequest.OPEN).count(), 1)
        self.client.post(f"/p/{token}/delete/", {"reason": "again"})
        self.assertEqual(DataRequest.objects.filter(session=s).count(), 1, "one open request at a time")

    def test_appeal_only_after_an_appealable_decision(self):
        s, token = self.complete_check()
        statement = {"statement": "I did not use any cheat, the file is a game mod.", "contact": "discord"}
        self.client.post(f"/p/{token}/appeal/", statement)
        self.assertFalse(Appeal.objects.exists(), "no decision yet")
        self.decide(s, "BANNED", self.admin)
        self.client.post(f"/p/{token}/appeal/", statement)
        self.client.post(f"/p/{token}/appeal/", statement)
        self.assertEqual(Appeal.objects.filter(session=s).count(), 1, "one open appeal at a time")
        self.assertTrue(AuditEvent.objects.filter(action="appeal.filed").exists())

    def test_the_deciding_admin_cannot_resolve_the_appeal(self):
        s, token = self.complete_check()
        self.decide(s, "BANNED", self.head)
        self.client.post(f"/p/{token}/appeal/", {"statement": "This is a mistake, please look again."})
        appeal = Appeal.objects.get(session=s)
        self.client.force_login(self.head)
        self.client.post(f"/appeals/{appeal.pk}/resolve/", {"status": "OVERTURNED", "resolution": "I overturn it myself"})
        appeal.refresh_from_db()
        self.assertEqual(appeal.status, Appeal.OPEN, "four-eyes: decider cannot judge the appeal")
        self.client.force_login(self.owner)
        self.client.post(f"/appeals/{appeal.pk}/resolve/", {"status": "OVERTURNED", "resolution": "File is a known mod."})
        appeal.refresh_from_db()
        s.refresh_from_db()
        self.assertEqual((appeal.status, s.decision), (Appeal.OVERTURNED, "CLEARED"))
        self.assertEqual(s.decision_by, self.owner)

    def test_plain_admin_cannot_resolve_appeals(self):
        s, token = self.complete_check()
        self.decide(s, "BANNED", self.head)
        self.client.post(f"/p/{token}/appeal/", {"statement": "This is a mistake, please look again."})
        self.client.force_login(self.admin)
        r = self.client.post(f"/appeals/{Appeal.objects.get().pk}/resolve/", {"status": "UPHELD", "resolution": "fine by me"})
        self.assertEqual(r.status_code, 403)

    def test_deletion_request_handling(self):
        s, token = self.complete_check()
        self.client.post(f"/p/{token}/delete/", {"reason": "gdpr"})
        req = DataRequest.objects.get()
        self.client.force_login(self.head)  # head-admin holds checks.delete
        self.client.post(f"/requests/{req.pk}/handle/", {"status": "REFUSED", "note": ""})
        req.refresh_from_db()
        self.assertEqual(req.status, DataRequest.OPEN, "a refusal needs a reason")
        self.client.post(f"/requests/{req.pk}/handle/", {"status": "DONE", "note": ""})
        req.refresh_from_db()
        self.assertEqual(req.status, DataRequest.DONE)
        self.assertFalse(CheckSession.objects.filter(pk=s.pk).exists(), "the check and its evidence are gone")
        self.assertTrue(AuditEvent.objects.filter(action="data.deletion_done").exists())

    def test_reissued_player_link_invalidates_the_old_one(self):
        s, token = self.complete_check()
        self.client.force_login(self.admin)
        self.client.post(f"/checks/{s.pk}/player-link/")
        page = self.client.get(f"/checks/{s.pk}/")
        new_link = page.context["player_link"]
        self.assertIn("/p/", new_link)
        anon = self.client_class()
        self.assertEqual(anon.get(f"/p/{token}/").status_code, 404)
        self.assertEqual(anon.get(new_link.replace("http://testserver", "")).status_code, 200)

    def test_test_runs_are_labelled_in_the_queues(self):
        make_session(self.admin, is_test=True, status=CheckSession.COMPLETED, verdict="REVIEW_REQUIRED")
        self.client.force_login(self.admin)
        page = self.client.get("/")
        self.assertEqual(len(page.context["queues"]["decide"]), 1)
        self.assertEqual(len(page.context["queues"]["waiting"]), 1)
        self.assertContains(page, "badge test")

    def test_detail_shows_timeline_and_history(self):
        s, token = self.complete_check()
        self.client.force_login(self.admin)
        page = self.client.get(f"/checks/{s.pk}/")
        self.assertContains(page, "История проверки")
        self.assertContains(page, "check.completed")

    def test_player_forms_work_like_a_real_browser(self):
        """CSRF enforced and an Origin header sent, as Chrome does (regression: no-referrer => Origin: null)."""
        s, token = self.complete_check()
        self.decide(s, "BANNED", self.admin)
        browser = self.client_class(enforce_csrf_checks=True)
        page = browser.get(f"/p/{token}/")
        self.assertNotIn("no-referrer", page["Referrer-Policy"])
        csrf = page.context["csrf_token"]
        r = browser.post(f"/p/{token}/appeal/", {"csrfmiddlewaretoken": csrf,
                                                 "statement": "The flagged file is a single-player mod."},
                         HTTP_ORIGIN="http://testserver")
        self.assertEqual(r.status_code, 302, r.content[:200])
        self.assertEqual(Appeal.objects.filter(session=s).count(), 1)

    def test_status_page_is_russian_by_default_and_english_on_request(self):
        s, token = self.complete_check()
        ru = self.client.get(f"/p/{token}/")
        self.assertContains(ru, "Ваша проверка")
        self.assertContains(ru, "Нужна проверка администратором")
        self.assertContains(ru, 'lang="ru"')
        self.assertEqual(ru["Cache-Control"], "no-store")
        en = self.client.get(f"/p/{token}/", HTTP_ACCEPT_LANGUAGE="en-GB,en;q=0.9")
        self.assertContains(en, "Admin review needed")
        self.assertContains(self.client.get(f"/p/{token}/?lang=en"), "Your check")
        self.assertContains(ru, "E1", msg_prefix="the evidence id the player can cite in an appeal")

    def test_a_rejected_appeal_shows_why_in_the_players_language(self):
        s, token = self.complete_check()
        self.decide(s, "BANNED", self.admin)
        r = self.client.post(f"/p/{token}/appeal/?lang=ru", {"statement": "too short"})
        self.assertEqual(r.status_code, 400)
        self.assertContains(r, "Слишком коротко", status_code=400)
        self.assertContains(r, "too short", status_code=400, msg_prefix="the player's text is kept")
        r = self.client.post(f"/p/{token}/appeal/?lang=en", {"statement": "The flagged file is a single-player mod."})
        self.assertRedirects(r, f"/p/{token}/?lang=en&sent=appeal#appeals", fetch_redirect_response=False)
        self.assertContains(self.client.get(f"/p/{token}/?lang=en&sent=appeal"), "Appeal sent")

    def test_player_errors_do_not_show_the_admin_panel(self):
        r = self.client.get("/p/unknown-token/")
        self.assertContains(r, "Страница не найдена", status_code=404)
        self.assertNotContains(r, "Back to the panel", status_code=404)

    def test_onboarding_page_is_bilingual(self):
        self.assertContains(self.client.get("/download/"), "Как пройти проверку")
        self.assertContains(self.client.get("/download/?lang=en"), "How to take the check")
