import re
import time

from django.core.cache import cache
from django.test import TestCase

from accounts import policy, totp
from accounts.models import Invite, Role, User
from checks.models import CheckSession
from core.models import AuditEvent, SiteSettings

from .helpers import make_session, make_user

PW = "correct horse battery"


def no_2fa():
    s = SiteSettings.load()
    s.require_2fa = False
    s.save()


class LoginTests(TestCase):
    def setUp(self):
        cache.clear()
        no_2fa()
        self.user = make_user("shadow")

    def login(self, alias="shadow", password=PW):
        return self.client.post("/login/", {"username": alias, "password": password})

    def test_login_and_logout(self):
        r = self.login("SHADOW")  # alias is case-insensitive
        self.assertRedirects(r, "/", fetch_redirect_response=False)
        self.assertEqual(self.client.get("/").status_code, 200)
        self.client.post("/logout/")
        self.assertEqual(self.client.get("/").status_code, 302)

    def test_lockout_after_failures(self):
        for _ in range(5):
            self.login(password="wrong password")
        r = self.login()
        self.assertContains(r, "Too many failed attempts")
        self.assertTrue(AuditEvent.objects.filter(action="login.failed").exists())

    def test_disabled_user_cannot_login(self):
        self.user.is_active = False
        self.user.save()
        self.assertContains(self.login(), "Wrong alias or password")

    def test_totp_flow_with_replay_protection(self):
        secret = totp.new_secret()
        self.user.totp_secret, self.user.totp_enabled = secret, True
        self.user.save()
        r = self.login()
        self.assertRedirects(r, "/login/verify/", fetch_redirect_response=False)
        self.assertEqual(self.client.get("/").status_code, 302)  # not logged in yet
        code = totp._code_at(secret, int(time.time() // 30))
        r = self.client.post("/login/verify/", {"code": code})
        self.assertRedirects(r, "/", fetch_redirect_response=False)
        # the same code cannot be used again
        self.client.post("/logout/")
        self.login()
        r = self.client.post("/login/verify/", {"code": code})
        self.assertContains(r, "not valid")

    def test_recovery_code_works_once(self):
        self.user.totp_secret, self.user.totp_enabled = totp.new_secret(), True
        self.user.save()
        codes = totp.issue_recovery_codes(self.user)
        self.login()
        r = self.client.post("/login/verify/", {"code": codes[0].lower()})
        self.assertRedirects(r, "/", fetch_redirect_response=False)
        self.client.post("/logout/")
        self.login()
        self.assertContains(self.client.post("/login/verify/", {"code": codes[0]}), "not valid")

    def test_forced_2fa_enrollment(self):
        s = SiteSettings.load()
        s.require_2fa = True
        s.save()
        self.login()
        r = self.client.get("/")
        self.assertRedirects(r, "/account/2fa/", fetch_redirect_response=False)
        page = self.client.get("/account/2fa/")
        secret = re.search(r'id="totp-secret">([A-Z2-7]+)<', page.content.decode()).group(1)
        r = self.client.post("/account/2fa/", {"code": totp._code_at(secret, int(time.time() // 30))})
        self.assertRedirects(r, "/account/2fa/recovery/", fetch_redirect_response=False)
        self.assertContains(self.client.get("/account/2fa/recovery/"), "Save your recovery codes")
        self.assertEqual(self.client.get("/").status_code, 200)

    def test_security_headers(self):
        r = self.client.get("/login/")
        self.assertIn("script-src 'self'", r["Content-Security-Policy"])
        self.assertEqual(r["X-Frame-Options"], "DENY")


class RoleTests(TestCase):
    def setUp(self):
        cache.clear()
        no_2fa()
        self.owner = make_user("boss", "owner")
        self.head = make_user("head", "head-admin")
        self.admin = make_user("adm", "admin")
        self.observer = make_user("obs", "observer")

    def as_user(self, user):
        self.client.force_login(user)

    def test_policy_ranks(self):
        self.assertTrue(policy.can_manage_member(self.head, self.admin))
        self.assertFalse(policy.can_manage_member(self.head, self.owner))
        self.assertFalse(policy.can_manage_member(self.admin, self.observer))  # no team.manage
        slugs = set(policy.assignable_roles(self.head).values_list("slug", flat=True))
        self.assertNotIn("owner", slugs)
        self.assertNotIn("head-admin", slugs)
        self.assertIn("owner", set(policy.assignable_roles(self.owner).values_list("slug", flat=True)))

    def test_head_cannot_promote_to_own_rank(self):
        self.as_user(self.head)
        head_role = Role.objects.get(slug="head-admin")
        r = self.client.post(f"/team/m/adm/", {"role": head_role.pk, "display_name": "", "is_active": "on"})
        self.assertEqual(r.status_code, 200)  # form error, not saved
        self.admin.refresh_from_db()
        self.assertEqual(self.admin.role.slug, "admin")

    def test_head_cannot_touch_owner(self):
        self.as_user(self.head)
        r = self.client.post("/team/m/boss/reset-2fa/")
        self.assertEqual(r.status_code, 403)

    def test_last_owner_is_protected(self):
        self.as_user(self.owner)
        other = make_user("boss2", "owner")
        # boss2 may demote boss while boss2 remains an owner…
        self.client.force_login(other)
        admin_role = Role.objects.get(slug="admin")
        self.client.post("/team/m/boss/", {"role": admin_role.pk, "is_active": "on"})
        self.owner.refresh_from_db()
        self.assertEqual(self.owner.role.slug, "admin")
        # …but nobody can then remove the last owner (boss2 cannot target itself either)
        self.assertFalse(policy.can_manage_member(other, other))
        self.assertTrue(policy.would_orphan_owners(other, deactivate=True))

    def test_role_change_signs_member_out(self):
        self.client.force_login(self.admin)
        self.assertEqual(self.client.get("/").status_code, 200)
        other = self.client_class()
        other.force_login(self.head)
        trainee = Role.objects.get(slug="trainee")
        other.post("/team/m/adm/", {"role": trainee.pk, "is_active": "on"})
        self.assertEqual(self.client.get("/").status_code, 302)  # old session is dead

    def test_role_editor_cannot_grant_missing_permissions(self):
        self.as_user(self.head)
        # head-admin lacks settings.manage; granting it must be impossible
        r = self.client.post("/team/roles/new/", {"name": "Sneaky", "rank": 30, "color": "#123456",
                                                 "permissions": ["settings.manage"]})
        self.assertEqual(r.status_code, 403)  # head-admin has no roles.manage at all
        self.as_user(self.owner)
        r = self.client.post("/team/roles/new/", {"name": "Helper", "rank": 30, "color": "#123456",
                                                 "permissions": ["checks.create", "checks.view_all"]})
        self.assertRedirects(r, "/team/roles/", fetch_redirect_response=False)
        self.assertEqual(Role.objects.get(slug="helper").permissions, ["checks.create", "checks.view_all"])

    def test_invite_flow(self):
        self.as_user(self.head)
        trainee = Role.objects.get(slug="trainee")
        self.client.post("/team/invite/", {"role": trainee.pk, "note": "new guy", "hours": 24})
        link = self.client.get("/team/").context["flash_link"]["url"]
        token = link.rstrip("/").split("/")[-1]
        anon = self.client_class()
        r = anon.post(f"/join/{token}/", {"username": "Newbie", "display_name": "N", "new_password": "a long enough pw 1",
                                          "confirm": "a long enough pw 1"})
        self.assertRedirects(r, "/", fetch_redirect_response=False)
        u = User.objects.get(username="newbie")
        self.assertEqual((u.role.slug, u.created_by), ("trainee", self.head))
        self.assertEqual(anon.get(f"/join/{token}/").status_code, 404)  # single use

    def test_invite_dies_if_inviter_loses_rights(self):
        invite, token = Invite.issue(Invite.KIND_INVITE, self.head, role=Role.objects.get(slug="admin"))
        self.head.role = Role.objects.get(slug="admin")
        self.head.save()
        self.assertEqual(self.client.get(f"/join/{token}/").status_code, 404)

    def test_check_visibility(self):
        mine = make_session(self.admin)
        theirs = make_session(self.head)
        self.as_user(self.admin)
        self.assertEqual(self.client.get(f"/checks/{mine.pk}/").status_code, 200)
        self.assertEqual(self.client.get(f"/checks/{theirs.pk}/").status_code, 404)
        self.as_user(self.observer)
        self.assertEqual(self.client.get(f"/checks/{theirs.pk}/").status_code, 200)
        self.assertEqual(self.client.get("/checks/new/").status_code, 403)

    def test_decision_permissions(self):
        s = make_session(self.head, status=CheckSession.COMPLETED, verdict="CHEAT", score=100)
        self.as_user(self.observer)  # can see, cannot decide
        self.assertEqual(self.client.post(f"/checks/{s.pk}/decide/", {"decision": "BANNED"}).status_code, 403)
        self.as_user(self.owner)
        self.client.post(f"/checks/{s.pk}/decide/", {"decision": "BANNED", "note": "hash match"})
        s.refresh_from_db()
        self.assertEqual((s.decision, s.decision_by), ("BANNED", self.owner))

    def test_create_check_and_cancel(self):
        self.as_user(self.admin)
        r = self.client.post("/checks/new/", {"player_name": "Bob"})
        s = CheckSession.objects.get(player_name="Bob")
        self.assertRedirects(r, f"/checks/{s.pk}/", fetch_redirect_response=False)
        self.assertRegex(s.code, r"^[A-Z2-9]{4}-[A-Z2-9]{4}$")
        self.assertContains(self.client.get(f"/checks/{s.pk}/"), s.code)
        self.client.post(f"/checks/{s.pk}/cancel/")
        s.refresh_from_db()
        self.assertEqual(s.status, CheckSession.CANCELLED)

    def test_detail_renders_with_partial_client_info(self):
        s = make_session(self.admin, status=CheckSession.SCANNING, client={"hostname": "PC"}, progress_total=5)
        self.as_user(self.owner)
        self.assertContains(self.client.get(f"/checks/{s.pk}/"), "Scanning the player")

    def test_pages_render_for_owner(self):
        self.as_user(self.owner)
        for url in ["/", "/checks/new/", "/checks/search/?q=loader", "/team/", "/team/roles/", "/team/roles/new/",
                    "/team/m/adm/", "/audit/", "/settings/", "/account/", "/download/"]:
            self.assertEqual(self.client.get(url).status_code, 200, url)
