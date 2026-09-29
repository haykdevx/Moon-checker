"""
Review findings on accounts: role grants were checked by rank only, and a TOTP step (and a
recovery code) could be accepted twice by two stale copies of the same user.

The threaded tests run only on PostgreSQL (the production database): SQLite in tests is one
in-memory database without row locks, where concurrent writers fail instead of waiting.
Run them with POSTGRES_* set (docs/hardening-record.md has the command).
"""
import json
import threading
import time
from unittest import mock, skipUnless

from django.core.cache import cache
from django.db import connection
from django.test import Client, TestCase, TransactionTestCase

from accounts import policy, totp
from accounts.models import Invite, RecoveryCode, Role, User
from checks.models import CheckSession, Report
from core.models import SiteSettings

from .helpers import bind, canonical, claim_body, gz, make_session, make_user, report_v2


def no_2fa():
    s = SiteSettings.load()
    s.require_2fa = False
    s.save()


class PermissionBoundaryTests(TestCase):
    """A lower-ranked custom role may carry permissions the acting admin does not hold."""

    def setUp(self):
        cache.clear()
        no_2fa()
        self.owner = make_user("boss", "owner")
        self.head = make_user("head", "head-admin")          # rank 80, team.manage, no settings.manage
        self.admin = make_user("adm", "admin")
        self.tech_role = Role.objects.create(slug="panel-tech", name="Panel tech", rank=30,
                                             permissions=["checks.create", "settings.manage"])
        self.tech = make_user("tech", "panel-tech")
        self.client.cookies["moon_lang"] = "en"

    def test_policy_needs_rank_and_permissions(self):
        self.assertNotIn("panel-tech", set(policy.assignable_roles(self.head).values_list("slug", flat=True)))
        self.assertIn("trainee", set(policy.assignable_roles(self.head).values_list("slug", flat=True)))
        self.assertIn("panel-tech", set(policy.assignable_roles(self.owner).values_list("slug", flat=True)))
        self.assertFalse(policy.can_manage_member(self.head, self.tech), "lower rank, more permissions")
        self.assertTrue(policy.can_manage_member(self.head, self.admin))
        self.assertTrue(policy.can_manage_member(self.owner, self.tech))

    def test_invite_for_a_role_with_more_permissions_is_refused_over_http(self):
        self.client.force_login(self.head)
        self.client.post("/team/invite/", {"role": self.tech_role.pk, "hours": 24, "note": "x"})
        self.assertFalse(Invite.objects.filter(role=self.tech_role).exists())

    def test_promotion_into_such_a_role_is_refused_over_http(self):
        self.client.force_login(self.head)
        r = self.client.post("/team/m/adm/", {"role": self.tech_role.pk, "display_name": "", "is_active": "on"})
        self.assertEqual(r.status_code, 200)  # the form refuses the choice
        self.admin.refresh_from_db()
        self.assertEqual(self.admin.role.slug, "admin")

    def test_members_holding_more_permissions_cannot_be_taken_over(self):
        self.client.force_login(self.head)
        for action in ("reset-password", "reset-2fa", "signout"):
            r = self.client.post(f"/team/m/tech/{action}/")
            self.assertEqual(r.status_code, 403, action)
        self.assertFalse(Invite.objects.filter(user=self.tech).exists(), "no reset link was issued")
        r = self.client.post("/team/m/tech/", {"role": Role.objects.get(slug="trainee").pk, "display_name": "",
                                               "is_active": "on"})
        self.tech.refresh_from_db()
        self.assertEqual(self.tech.role.slug, "panel-tech")

    def test_an_invite_dies_when_its_role_gains_permissions_the_inviter_lacks(self):
        trainee = Role.objects.get(slug="trainee")
        invite, token = Invite.issue(Invite.KIND_INVITE, self.head, hours=24, role=trainee, note="")
        trainee.permissions = sorted(set(trainee.permissions) | {"settings.manage"})
        trainee.save()
        r = Client().get(f"/join/{token}/")
        self.assertEqual(r.status_code, 404)

    def test_a_role_editor_cannot_edit_a_role_with_permissions_they_lack(self):
        editor_role = Role.objects.create(slug="role-admin", name="Role admin", rank=70,
                                          permissions=["roles.manage", "team.view"])
        editor = make_user("editor", "role-admin")
        self.assertFalse(policy.can_edit_role(editor, self.tech_role))
        self.assertFalse(policy.can_edit_role(editor, Role.objects.get(slug="observer")),
                         "observer grants checks.view_all, which the editor does not hold")
        self.assertTrue(policy.can_edit_role(editor, Role.objects.get(slug="trainee")) is False,
                        "trainee grants checks.create, which the editor does not hold either")
        self.client.force_login(editor)
        r = self.client.post("/team/roles/panel-tech/", {"name": "Panel tech", "rank": 30, "color": "#123456",
                                                        "description": "", "permissions": ["checks.create"]})
        self.assertEqual(r.status_code, 403)
        self.tech_role.refresh_from_db()
        self.assertIn("settings.manage", self.tech_role.permissions)


class MfaAtomicityTests(TestCase):
    """Consumption is decided by the stored row, not by the copy of the user in memory."""

    def setUp(self):
        self.user = make_user("mfa")
        self.secret = totp.new_secret()
        User.objects.filter(pk=self.user.pk).update(totp_secret=self.secret, totp_enabled=True, totp_last_step=0)

    def code_now(self):
        return totp._code_at(self.secret, int(time.time() // totp.STEP))

    def test_two_stale_copies_accept_one_code_once(self):
        a, b = User.objects.get(pk=self.user.pk), User.objects.get(pk=self.user.pk)
        code = self.code_now()
        self.assertTrue(totp.verify_user(a, code))
        self.assertFalse(totp.verify_user(b, code), "b still believes no step was used")
        self.assertFalse(totp.verify_user(a, code))

    def test_a_code_from_a_reset_or_replaced_enrolment_is_refused(self):
        stale = User.objects.get(pk=self.user.pk)
        User.objects.filter(pk=self.user.pk).update(totp_enabled=False, totp_secret="")  # reset by a manager
        self.assertFalse(totp.verify_user(stale, self.code_now()))
        User.objects.filter(pk=self.user.pk).update(totp_enabled=True, totp_secret=totp.new_secret())  # re-enrolled
        self.assertFalse(totp.verify_user(stale, self.code_now()), "the old secret no longer counts")

    def test_a_recovery_code_works_once_even_from_stale_copies(self):
        codes = totp.issue_recovery_codes(User.objects.get(pk=self.user.pk))
        a, b = User.objects.get(pk=self.user.pk), User.objects.get(pk=self.user.pk)
        self.assertTrue(totp.use_recovery_code(a, codes[0]))
        self.assertFalse(totp.use_recovery_code(b, codes[0]))
        self.assertEqual(RecoveryCode.objects.filter(user=self.user, used_at__isnull=False).count(), 1)

    def test_recovery_codes_die_with_the_enrolment(self):
        codes = totp.issue_recovery_codes(User.objects.get(pk=self.user.pk))
        stale = User.objects.get(pk=self.user.pk)
        User.objects.filter(pk=self.user.pk).update(totp_enabled=False, totp_secret="")
        self.assertFalse(totp.use_recovery_code(stale, codes[1]))


def _race(n, fn):
    """Runs fn(i) in n threads released together; returns the results."""
    barrier, results = threading.Barrier(n), [None] * n

    def run(i):
        try:
            barrier.wait()
            results[i] = fn(i)
        finally:
            connection.close()

    threads = [threading.Thread(target=run, args=(i,)) for i in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(30)
    return results


@skipUnless(connection.vendor == "postgresql", "row-lock races need PostgreSQL (production database)")
class ConcurrencyTests(TransactionTestCase):
    """Exactly one of several simultaneous consumptions succeeds."""

    serialized_rollback = True  # the default roles come from a data migration; keep them between tests

    def setUp(self):
        cache.clear()
        no_2fa()

    def test_simultaneous_totp_logins_with_one_code(self):
        user = make_user("racer")
        secret = totp.new_secret()
        User.objects.filter(pk=user.pk).update(totp_secret=secret, totp_enabled=True, totp_last_step=0)
        code = totp._code_at(secret, int(time.time() // totp.STEP))
        results = _race(8, lambda i: totp.verify_user(User.objects.get(pk=user.pk), code))
        self.assertEqual(results.count(True), 1, results)

    def test_simultaneous_recovery_code_uses(self):
        user = make_user("racer2")
        User.objects.filter(pk=user.pk).update(totp_secret=totp.new_secret(), totp_enabled=True)
        code = totp.issue_recovery_codes(User.objects.get(pk=user.pk))[0]
        results = _race(8, lambda i: totp.use_recovery_code(User.objects.get(pk=user.pk), code))
        self.assertEqual(results.count(True), 1, results)

    def test_simultaneous_report_uploads_complete_the_check_once(self):
        admin = make_user("upl")
        s = make_session(admin)
        d = Client().post("/api/v1/claim", data=json.dumps(claim_body(s.code)), content_type="application/json").json()
        bodies = [gz(canonical(bind(report_v2("NO_EVIDENCE", check_id=f"MOON-260929-RACE{i}"), d))) for i in range(6)]

        def upload(i):
            return Client().post(f"/api/v1/sessions/{d['sessionId']}/report", data=bodies[i],
                                 content_type="application/json", HTTP_CONTENT_ENCODING="gzip",
                                 HTTP_AUTHORIZATION=f"Bearer {d['token']}").status_code
        results = _race(6, upload)
        self.assertEqual(results.count(200), 1, results)
        self.assertTrue(all(code == 409 for code in results if code != 200), results)
        self.assertEqual(Report.objects.filter(session_id=d["sessionId"]).count(), 1)
        self.assertEqual(CheckSession.objects.get(pk=d["sessionId"]).status, CheckSession.COMPLETED)

    def test_two_owners_demoting_each_other_leave_one_owner(self):
        a, b = make_user("owner-a", "owner"), make_user("owner-b", "owner")
        admin_role = Role.objects.get(slug="admin")
        real_count = policy.active_owner_count

        def slow_count():  # widen the gap between reading the owner count and writing
            n = real_count()
            time.sleep(0.3)
            return n

        def demote(i):
            actor, target = (a, b) if i == 0 else (b, a)
            c = Client()
            c.force_login(actor)
            return c.post(f"/team/m/{target.username}/", {"role": admin_role.pk, "display_name": "",
                                                          "is_active": "on"}).status_code
        with mock.patch.object(policy, "active_owner_count", slow_count):
            _race(2, demote)
        self.assertEqual(User.objects.filter(role__slug="owner", is_active=True).count(), 1)
