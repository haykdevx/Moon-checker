from django.core.cache import cache
from django.core.management import call_command
from django.test import TestCase

from checks.models import CheckSession

from .helpers import make_session, make_user
from .test_player import no_2fa


class PanelLanguageTests(TestCase):
    def setUp(self):
        cache.clear()
        no_2fa()
        self.admin = make_user("adm", "admin")
        self.client.force_login(self.admin)

    def test_the_catalog_is_complete_and_compiled(self):
        call_command("moon_i18n", check=True)

    def test_panel_is_russian_by_default(self):
        page = self.client.get("/", HTTP_ACCEPT_LANGUAGE="en-US,en;q=0.9")
        self.assertContains(page, '<html lang="ru">')
        self.assertContains(page, "Новая проверка")
        self.assertEqual(page["Content-Language"], "ru")

    def test_switch_to_english_and_back(self):
        r = self.client.post("/language/", {"lang": "en", "next": "/checks/new/"})
        self.assertRedirects(r, "/checks/new/", fetch_redirect_response=False)
        self.assertContains(self.client.get("/checks/new/"), "Player&#x27;s nickname")
        self.client.post("/language/", {"lang": "ru", "next": "/"})
        self.assertContains(self.client.get("/checks/new/"), "Ник игрока")

    def test_switch_never_redirects_off_site(self):
        r = self.client.post("/language/", {"lang": "en", "next": "https://evil.example/"})
        self.assertEqual(r["Location"], "/")

    def test_finding_titles_follow_the_language(self):
        s = make_session(self.admin, status=CheckSession.COMPLETED, verdict="REVIEW_REQUIRED")
        s.findings.create(idx=0, severity="HIGH", kind="INDICATOR", category="FILES", module="files",
                          title="Файл совпал с сигнатурой чита / Cheat-signature file", evidence="C:\\x\\a.exe")
        ru = self.client.get(f"/checks/{s.pk}/")
        self.assertContains(ru, "Файл совпал с сигнатурой чита")
        self.assertNotContains(ru, "Cheat-signature file")
        self.client.cookies["moon_lang"] = "en"
        en = self.client.get(f"/checks/{s.pk}/")
        self.assertContains(en, "Cheat-signature file")

    def test_decision_in_one_click(self):
        s = make_session(self.admin, status=CheckSession.COMPLETED, verdict="REVIEW_REQUIRED")
        self.client.post(f"/checks/{s.pk}/decide/", {"decision": "BANNED", "note": "aim trainer? asked to recheck"})
        s.refresh_from_db()
        self.assertEqual((s.decision, s.decision_by), ("BANNED", self.admin))
        page = self.client.get(f"/checks/{s.pk}/")
        self.assertContains(page, "Снять решение")
        self.client.post(f"/checks/{s.pk}/decide/", {"decision": "", "note": ""})
        s.refresh_from_db()
        self.assertEqual(s.decision, "")

    def test_queues_group_the_work(self):
        make_session(self.admin, status=CheckSession.COMPLETED, verdict="REVIEW_REQUIRED")
        make_session(self.admin, status=CheckSession.SCANNING)
        make_session(self.admin)
        page = self.client.get("/")
        self.assertContains(page, "Ждут вашего решения")
        self.assertContains(page, "Идут сейчас")
        self.assertContains(page, "Ждут игрока")
        fragment = self.client.get("/?fragment=1")
        self.assertContains(fragment, 'data-any-open="1"')
        self.assertNotContains(fragment, "<html")
