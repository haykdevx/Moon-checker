import gzip
import hashlib
import json
from datetime import timedelta

from django.core.cache import cache
from django.test import TestCase, override_settings
from django.utils import timezone

from checks import housekeeping, ingest
from checks.models import CheckSession, FindingRow, TrustedBuild
from core.models import SiteSettings

from .helpers import HASH, canonical, client_info, gz, make_session, make_user, report_payload


class ApiFlowTests(TestCase):
    def setUp(self):
        cache.clear()
        self.admin = make_user("shadow")
        self.session = make_session(self.admin)

    def claim(self, code=None, **client):
        return self.client.post("/api/v1/claim", data=json.dumps(
            {"code": code or self.session.code, "client": client_info(**client)}), content_type="application/json")

    def progress(self, sid, token, **body):
        body = {"done": 1, "total": 10, "module": "files", "counts": {"high": 2}, **body}
        return self.client.post(f"/api/v1/sessions/{sid}/progress", data=json.dumps(body),
                                content_type="application/json", HTTP_AUTHORIZATION=f"Bearer {token}")

    def upload(self, sid, token, raw, gzip_it=True, **headers):
        body = gz(raw) if gzip_it else raw
        extra = {"HTTP_AUTHORIZATION": f"Bearer {token}"}
        if gzip_it:
            extra["HTTP_CONTENT_ENCODING"] = "gzip"
        extra.update(headers)
        return self.client.post(f"/api/v1/sessions/{sid}/report", data=body,
                                content_type="application/json", **extra)

    def test_full_flow(self):
        r = self.claim(code=self.session.code.lower().replace("-", " "))
        self.assertEqual(r.status_code, 200, r.content)
        d = r.json()
        self.assertEqual(d["admin"]["alias"], "shadow")
        self.assertEqual(d["player"]["name"], "PlayerOne")
        sid, token = d["sessionId"], d["token"]
        s = CheckSession.objects.get(pk=sid)
        self.assertEqual(s.status, CheckSession.CONNECTED)
        self.assertNotIn(token, s.token_hash)  # only the hash is stored

        self.assertEqual(self.progress(sid, token).status_code, 200)
        s.refresh_from_db()
        self.assertEqual((s.status, s.progress_done, s.progress_total), (CheckSession.SCANNING, 1, 10))
        self.assertEqual(s.live_counts["high"], 2)

        raw = canonical(report_payload())
        r = self.upload(sid, token, raw, HTTP_X_MOON_SHA256=hashlib.sha256(raw).hexdigest())
        self.assertEqual(r.status_code, 200, r.content)
        self.assertEqual(r.json()["verificationCode"], ingest.verification_code(raw))
        s.refresh_from_db()
        self.assertEqual(s.status, CheckSession.COMPLETED)
        self.assertEqual((s.verdict, s.score, s.counts["critical"]), ("CHEAT", 100, 1))
        self.assertEqual(FindingRow.objects.filter(session=s).count(), 1)
        self.assertEqual(gzip.decompress(bytes(s.report.raw_gzip)), raw)
        keys = {f["key"] for f in s.flags}
        self.assertIn("fast", keys)        # finished instantly
        self.assertIn("build", keys)       # no trusted builds configured -> warn

        # a second upload is refused but tells the client its code
        r = self.upload(sid, token, raw)
        self.assertEqual(r.status_code, 409)
        self.assertEqual(r.json()["verificationCode"], s.verification_code)

    def test_code_is_single_use_and_expires(self):
        self.assertEqual(self.claim().status_code, 200)
        self.assertEqual(self.claim().json()["error"], "code_used")
        old = make_session(self.admin, expires_at=timezone.now() - timedelta(seconds=1))
        r = self.claim(code=old.code)
        self.assertEqual((r.status_code, r.json()["error"]), (410, "code_expired"))

    def test_bad_codes_are_throttled(self):
        for _ in range(10):
            self.assertEqual(self.claim(code="AAAA-AAAA").status_code, 404)
        r = self.claim()  # even the right code is refused now
        self.assertEqual(r.status_code, 429)

    def test_wrong_token_rejected(self):
        sid = self.claim().json()["sessionId"]
        self.assertEqual(self.progress(sid, "nope").status_code, 401)
        self.assertEqual(self.upload(sid, "x" * 43, b"{}").status_code, 401)

    def test_outdated_and_untrusted_clients(self):
        site = SiteSettings.load()
        site.min_checker_version = "2.0"
        site.save()
        self.assertEqual(self.claim().json()["error"], "checker_outdated")
        site.min_checker_version, site.block_untrusted_builds = "1.0", True
        site.save()
        self.assertEqual(self.claim().json()["error"], "untrusted_build")
        TrustedBuild.objects.create(sha256=HASH, label="1.1.0")
        self.assertEqual(self.claim().status_code, 200)

    def test_trust_flags(self):
        TrustedBuild.objects.create(sha256=HASH, label="official 1.1.0")
        d = self.claim().json()
        raw = canonical(report_payload(hostname="OTHER-PC", elevated=False, selfHash="ffffffffffff"))
        self.upload(d["sessionId"], d["token"], raw)
        s = CheckSession.objects.get(pk=d["sessionId"])
        levels = {f["key"]: f["level"] for f in s.flags}
        self.assertEqual(levels["build"], "ok")
        self.assertEqual(levels["identity"], "bad")
        self.assertEqual(levels["elevated"], "bad")
        self.assertEqual(levels["binary"], "bad")
        self.assertEqual(s.trust, "bad")

    def test_replayed_report_is_flagged(self):
        d1 = self.claim().json()
        raw = canonical(report_payload())
        self.upload(d1["sessionId"], d1["token"], raw)
        s2 = make_session(self.admin)
        d2 = self.claim(code=s2.code).json()
        self.upload(d2["sessionId"], d2["token"], raw)
        s2.refresh_from_db()
        self.assertIn("replay", {f["key"] for f in s2.flags if f["level"] == "bad"})

    def test_malformed_reports_rejected(self):
        d = self.claim().json()
        sid, token = d["sessionId"], d["token"]
        self.assertEqual(self.upload(sid, token, b"not json").status_code, 400)
        bad = report_payload()
        bad["verdict"] = "TOTALLY_CLEAN"
        self.assertEqual(self.upload(sid, token, canonical(bad)).status_code, 422)
        self.assertEqual(self.upload(sid, token, b"\x1f\x8b garbage", gzip_it=False,
                                     HTTP_CONTENT_ENCODING="gzip").status_code, 400)
        raw = canonical(report_payload())
        self.assertEqual(self.upload(sid, token, raw, HTTP_X_MOON_SHA256="0" * 64).status_code, 400)
        self.assertEqual(CheckSession.objects.get(pk=sid).status, CheckSession.CONNECTED)

    @override_settings(MOON_MAX_REPORT_BYTES=10_000)
    def test_decompression_bomb_rejected(self):
        d = self.claim().json()
        r = self.upload(d["sessionId"], d["token"], b"{" + b" " * 5_000_000 + b"}")
        self.assertEqual(r.status_code, 413)

    def test_cancelled_session_refuses_everything(self):
        d = self.claim().json()
        CheckSession.objects.filter(pk=d["sessionId"]).update(status=CheckSession.CANCELLED)
        r = self.progress(d["sessionId"], d["token"])
        self.assertEqual((r.status_code, r.json()["error"]), (410, "cancelled"))
        r = self.upload(d["sessionId"], d["token"], canonical(report_payload()))
        self.assertEqual(r.status_code, 410)

    def test_housekeeping_abandons_and_revives(self):
        d = self.claim().json()
        self.progress(d["sessionId"], d["token"])
        CheckSession.objects.filter(pk=d["sessionId"]).update(last_seen_at=timezone.now() - timedelta(minutes=30))
        _, abandoned = housekeeping.expire_and_abandon()
        self.assertEqual(abandoned, 1)
        self.assertEqual(self.progress(d["sessionId"], d["token"], done=5).status_code, 200)
        s = CheckSession.objects.get(pk=d["sessionId"])
        self.assertEqual((s.status, s.interruptions), (CheckSession.SCANNING, 1))

    def test_idle_connected_player_is_not_abandoned_early(self):
        d = self.claim().json()
        CheckSession.objects.filter(pk=d["sessionId"]).update(claimed_at=timezone.now() - timedelta(minutes=10),
                                                              last_seen_at=timezone.now() - timedelta(minutes=10))
        _, abandoned = housekeeping.expire_and_abandon()
        self.assertEqual(abandoned, 0)  # still within the 30 min code TTL
        self.progress(d["sessionId"], d["token"])
        self.assertEqual(CheckSession.objects.get(pk=d["sessionId"]).interruptions, 0)

    def test_housekeeping_expires_unused_codes(self):
        CheckSession.objects.filter(pk=self.session.pk).update(expires_at=timezone.now() - timedelta(minutes=1))
        expired, _ = housekeeping.expire_and_abandon()
        self.assertEqual(expired, 1)

    def test_ping(self):
        self.assertEqual(self.client.get("/api/v1/ping").json()["api"], 1)


class VerificationCodeParity(TestCase):
    def test_matches_java_integrity_short_code(self):
        # Integrity.shortCode(bytes "abc") with key moon-cs2-2026::integrity::v1, computed by the Java checker
        import hmac
        mac = hmac.new(b"moon-cs2-2026::integrity::v1", b"abc", hashlib.sha256).hexdigest().upper()
        self.assertEqual(ingest.verification_code(b"abc"), f"{mac[:4]}-{mac[4:8]}-{mac[8:10]}")
