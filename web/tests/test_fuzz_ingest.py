"""
Robustness of report ingestion (POST /api/v1/sessions/<id>/report) against malformed uploads.

A valid moon-evidence/2 report is mutated 300 times from a fixed seed and each mutation is
uploaded to a freshly claimed session. Every upload must end in exactly one of two states:

* accepted: 200, the report is stored and the session is COMPLETED;
* rejected: 4xx, nothing is stored and the session is still CONNECTED.

A 5xx is a failure. Each mutation also says what the report contract (checks/ingest.py) requires:
breaking a required key, a fixed type or an enumerated value must be rejected; changing optional
or free-text content must be accepted (clipped or normalised). Only nesting deeper than the JSON
parser's stack is left to the server ("either"), as long as it ends in one of the two states.
"""
import copy
import gzip
import hashlib
import json
import random
from collections import Counter
from dataclasses import dataclass, field

from django.core.cache import cache
from django.test import TestCase, override_settings

from checks.models import CheckSession, FindingRow, Report

from .helpers import canonical, client_info, evidence_item, make_session, make_user, report_payload, report_v2

SEED = 20260928
N = 300
# MOON_MAX_UPLOAD_BYTES / MOON_MAX_REPORT_BYTES are lowered for the run (defaults 16 MiB / 48 MiB)
# so that bodies over the limits stay cheap to build; the checks are the same code paths.
UPLOAD_LIMIT = 256 * 1024
REPORT_LIMIT = 768 * 1024

ACCEPT, REJECT, EITHER = "accept", "reject", "either"

# ---- the moon-evidence/2 contract, as paths ("*" = any list index) ----------------------------
SECTIONS = ("session", "collector", "environment", "consent", "coverage", "assurance", "verdict")
REQUIRED = {("schema",), ("evidence",), *((s,) for s in SECTIONS), ("session", "checkId"),
            ("evidence", "*", "id"), ("evidence", "*", "kind"), ("evidence", "*", "severity"),
            ("evidence", "*", "title"), ("coverage", "modules"), ("assurance", "level"), ("verdict", "outcome")}
TYPED = {**{(s,): dict for s in SECTIONS}, ("evidence",): list, ("evidence", "*"): dict,
         ("evidence", "*", "title"): str, ("coverage", "modules"): dict, ("coverage", "required"): list,
         ("coverage", "required", "*"): str, ("assurance", "reasons"): list, ("verdict", "reasons"): list,
         ("verdict", "reasons", "*"): dict, ("verdict", "reasons", "*", "evidence"): list,
         ("verdict", "reasons", "*", "evidence", "*"): str}
ENUMS = {("schema",), ("session", "checkId"), ("evidence", "*", "id"), ("evidence", "*", "kind"),
         ("evidence", "*", "severity"), ("assurance", "level"), ("verdict", "outcome"),
         ("verdict", "reasons", "*", "evidence", "*")}

SENTINEL = "__fuzz_sentinel__"
JUNK = [None, 0, -7, 2.5, True, "", "text", [], ["x"], {}, {"k": "v"}]
BAD_NUMBERS = [-1, -2 ** 63, 2 ** 64, 10 ** 30, 1e308, -1e308, float("nan"), float("inf"), float("-inf"), 0.5, -0.0]
BAD_UTF8 = [b"\xff", b"\xfe\xff", b"\xc3\x28", b"\x80abc", b"\xf8\x88\x80\x80\x80", b"\xe2\x82", b"\xc0\xaf",
            b"\xed\xa0\x80"]  # the last is a UTF-8-encoded surrogate, which Python's own JSON reader lets through


@dataclass
class Case:
    kind: str
    what: str
    body: bytes
    expect: str
    encoding: str = "gzip"
    headers: dict = field(default_factory=dict)


def baseline():
    payload = report_v2("REVIEW_REQUIRED",
                        [evidence_item(1), evidence_item(2, "CONTEXT", "INFO", module="steam"),
                         evidence_item(3, "CONFIGURATION", "LOW", module="environment")],
                        reasons=[{"code": "review.indicator", "text": "Indicator needs review: Sample loader",
                                  "evidence": ["E1"]}])
    payload["assurance"] = {"level": "REDUCED", "reasons": [{"code": "config.environment:sample", "text": "x"}]}
    return payload


def shape(path):
    return tuple("*" if isinstance(p, int) else p for p in path)


def dotted(path):
    return ".".join(str(p) for p in path) or "<root>"


def nodes(obj, path=()):
    """Every (path, value) below ``obj``."""
    items = obj.items() if isinstance(obj, dict) else enumerate(obj) if isinstance(obj, list) else ()
    for k, v in items:
        yield path + (k,), v
        yield from nodes(v, path + (k,))


def put(obj, path, value):
    for p in path[:-1]:
        obj = obj[p]
    obj[path[-1]] = value


def json_type(v):
    if v is None:
        return "null"
    if isinstance(v, bool):
        return "bool"
    if isinstance(v, (int, float)):
        return "number"
    return {str: "string", list: "array", dict: "object"}[type(v)]


def text_leaves(p, untyped=False):
    """Strings the contract only clips: not enumerated (and, with ``untyped``, not type-checked)."""
    return [q for q, v in nodes(p) if isinstance(v, str) and shape(q) not in ENUMS
            and not (untyped and shape(q) in TYPED)]


def encode(payload):
    try:
        return json.dumps(payload, ensure_ascii=False).encode()
    except UnicodeEncodeError:  # lone surrogates can only travel as \u escapes
        return json.dumps(payload).encode()


def json_case(kind, what, expect, payload=None, raw=None, encoding="gzip", headers=None):
    raw = encode(payload) if raw is None else raw
    body = gzip.compress(raw, mtime=0) if encoding == "gzip" else raw
    if len(raw) > REPORT_LIMIT or len(body) > UPLOAD_LIMIT:
        expect = REJECT  # over the size limits whatever it contains
    return Case(kind, what, body, expect, encoding, headers or {})


# ---- mutations ----------------------------------------------------------------------------------

def m_delete_key(rnd, p):
    path = rnd.choice([q for q, _ in nodes(p) if isinstance(q[-1], str)])
    del_from = p
    for k in path[:-1]:
        del_from = del_from[k]
    del del_from[path[-1]]
    return json_case("delete-key", dotted(path), REJECT if shape(path) in REQUIRED else ACCEPT, p)


def m_wrong_type(rnd, p):
    path, value = rnd.choice(list(nodes(p)))
    new = rnd.choice([j for j in JUNK if json_type(j) != json_type(value)])
    put(p, path, copy.deepcopy(new))
    s = shape(path)
    bad = s in ENUMS or (s in TYPED and not isinstance(new, TYPED[s]))
    return json_case("wrong-type", f"{dotted(path)} = {new!r}", REJECT if bad else ACCEPT, p)


def m_huge_string(rnd, p):
    path = rnd.choice([q for q, v in nodes(p) if isinstance(v, str)])
    n = rnd.choice([5_000, 60_000, 300_000, 900_000])
    alphabet = rnd.choice(["A", "abcdefghijklmnopqrstuvwxyz0123456789", "Жж"])
    text = (alphabet * n)[:n] if rnd.random() < 0.5 else "".join(rnd.choices(alphabet, k=n))
    put(p, path, text)
    return json_case("huge-string", f"{dotted(path)} = {n} chars", REJECT if shape(path) in ENUMS else ACCEPT, p)


def m_bad_number(rnd, p):
    leaves = [q for q, v in nodes(p) if not isinstance(v, (dict, list))]
    numeric = [q for q, v in nodes(p) if isinstance(v, (bool, int, float))]
    path = rnd.choice(numeric if rnd.random() < 0.5 else leaves)
    new = rnd.choice(BAD_NUMBERS)
    put(p, path, new)
    s = shape(path)
    return json_case("bad-number", f"{dotted(path)} = {new!r}", REJECT if s in ENUMS or s in TYPED else ACCEPT, p)


def m_wrong_ids(rnd, p):
    ev = p["evidence"]
    i = rnd.randrange(len(ev))
    variant = rnd.choice(["swap", "lower", "int", "zero-based", "duplicate", "skip", "padded", "leading-zero",
                          "no-prefix", "newline"])
    if variant == "swap":
        ev[0]["id"], ev[1]["id"] = ev[1]["id"], ev[0]["id"]
    elif variant == "lower":
        ev[i]["id"] = ev[i]["id"].lower()
    elif variant == "int":
        ev[i]["id"] = i + 1
    elif variant == "zero-based":
        for j, e in enumerate(ev):
            e["id"] = f"E{j}"
    elif variant == "duplicate":
        ev[1]["id"] = "E1"
    elif variant == "skip":
        for j, e in enumerate(ev):
            e["id"] = f"E{j + 2 if j else 1}"
    elif variant == "padded":
        ev[i]["id"] = f" E{i + 1}"
    elif variant == "leading-zero":
        ev[i]["id"] = f"E0{i + 1}"
    elif variant == "no-prefix":
        ev[i]["id"] = str(i + 1)
    else:
        ev[i]["id"] = f"E{i + 1}\n"
    return json_case("evidence-ids", f"{variant}: {[e['id'] for e in ev]!r}", REJECT, p)


def m_unknown_value(rnd, p):
    target = rnd.choice(["kind", "severity", "level", "outcome", "checkId", "module-state"])
    i = rnd.randrange(len(p["evidence"]))
    if target == "kind":
        new = rnd.choice(["PROOF", "indicator", "", "INDICATOR ", "Detection", "ИНДИКАТОР", [], {}, ["INDICATOR"], None, 3])
        p["evidence"][i]["kind"] = new
    elif target == "severity":
        new = rnd.choice(["EXTREME", "high", "", "HIGH\u0000", "Critical", [], {}, ["HIGH"], None, 4])
        p["evidence"][i]["severity"] = new
    elif target == "level":
        new = rnd.choice(["PERFECT", "standard", "", [], None])
        p["assurance"]["level"] = new
    elif target == "outcome":
        new = rnd.choice(["CLEAN", "CHEAT", "no_evidence", "", [], {}, None, 0])
        p["verdict"]["outcome"] = new
    elif target == "checkId":
        new = rnd.choice(["MOON-260928-ABCD\n", "moon-260928-abcd", "MOON-\u0662\u0666\u0660\u0669\u0662\u0668-ABCD",
                          "MOON-2609-ABCD", "MOON-260928-ABCDEFGHI", " MOON-260928-ABCD", "MOON-260928-AB\u0000D"])
        p["session"]["checkId"] = new
    else:  # an unknown collector state is recorded as ERROR, not refused
        module = rnd.choice(sorted(p["coverage"]["modules"]))
        new = rnd.choice(["DONE", "ok", "", [], {}, None, 1])
        p["coverage"]["modules"][module] = new
        return json_case("unknown-value", f"coverage.modules.{module} = {new!r}", ACCEPT, p)
    return json_case("unknown-value", f"{target} = {new!r}", REJECT, p)


def m_deep_nesting(rnd, p):
    depth = rnd.choice([10, 900, 30_000, 300_000])
    opener, closer = rnd.choice([("[", "]"), ('{"a":', "}")])
    nested = (opener * depth + "0" + closer * depth).encode()
    where = rnd.random()
    if where < 0.4:                                  # where a fixed value belongs
        path = rnd.choice([q for q, _ in nodes(p) if shape(q) in ENUMS])
        expect = REJECT
    elif where < 0.7:                                # where free text belongs
        path = rnd.choice(text_leaves(p, untyped=True))
        expect = ACCEPT if depth <= 900 else EITHER
    else:                                            # an unknown key anywhere
        parent = rnd.choice([()] + [q for q, v in nodes(p) if isinstance(v, dict)])
        path = parent + ("junk",)
        expect = ACCEPT if depth <= 900 else EITHER
    put(p, path, SENTINEL)
    raw = encode(p).replace(f'"{SENTINEL}"'.encode(), nested)
    return json_case("deep-nesting", f"{dotted(path)} nested {depth} deep ({opener})", expect, raw=raw)


def m_non_utf8(rnd, p):
    path = rnd.choice(text_leaves(p))
    seq = rnd.choice(BAD_UTF8)
    put(p, path, SENTINEL)
    raw = encode(p).replace(SENTINEL.encode(), b"x" + seq + b"y")
    encoding = rnd.choice(["gzip", "gzip", ""])
    return json_case("non-utf8", f"{dotted(path)} contains {seq!r}", REJECT, raw=raw, encoding=encoding)


def m_lone_surrogate(rnd, p):
    path = rnd.choice(text_leaves(p))
    put(p, path, rnd.choice(["\ud800", "x\udfffy", "\udc80\udc80\udc80", "ok\ud83d"]))
    return json_case("lone-surrogate", f"{dotted(path)} holds an unpaired surrogate escape", ACCEPT, p)


def m_gzip_damage(rnd, p):
    z = gzip.compress(encode(p), mtime=0)
    variant = rnd.choice(["truncated", "bit-flip", "empty", "header-only", "plain-json-declared-gzip"])
    if variant == "truncated":
        body = z[:rnd.randrange(0, len(z))]
    elif variant == "bit-flip":
        at = rnd.randrange(10, len(z))  # past the header's timestamp/OS bytes, which gzip does not check
        body = z[:at] + bytes([z[at] ^ (1 << rnd.randrange(8))]) + z[at + 1:]
    elif variant == "empty":
        body = b""
    elif variant == "header-only":
        body = z[:10]
    else:
        body = encode(p)
    return Case("gzip-damage", variant, body, REJECT)


def m_size(rnd, p):
    variant = rnd.choice(["bomb", "at-limit", "one-over", "wire-over", "identity-over"])
    if variant == "bomb":  # a few KB on the wire, far over the limit once inflated
        raw = b'{"schema":"moon-evidence/2","pad":"' + b"0" * (REPORT_LIMIT + rnd.randrange(1, 4 * REPORT_LIMIT)) + b'"}'
        return Case("size", f"gzip bomb ({len(raw)} bytes inflated)", gzip.compress(raw, mtime=0), REJECT)
    if variant in ("at-limit", "one-over"):
        p["pad"] = ""
        p["pad"] = "x" * (REPORT_LIMIT - len(encode(p)) + (1 if variant == "one-over" else 0))
        return json_case("size", f"report {variant} ({len(encode(p))} bytes)",
                         ACCEPT if variant == "at-limit" else REJECT, p)
    if variant == "wire-over":
        body = gzip.compress(b"{}", mtime=0)[:10] + rnd.randbytes(UPLOAD_LIMIT + rnd.randrange(1, 5000))
        return Case("size", f"{len(body)} bytes on the wire", body, REJECT)
    p["pad"] = "y" * (UPLOAD_LIMIT + rnd.randrange(1, 5000))
    return json_case("size", "identity body over the upload limit", REJECT, p, encoding="")


def m_envelope(rnd, p):
    variant = rnd.choice(["identity", "br", "deflate", "gzip, br", "checksum-ok", "checksum-mismatch",
                          "top-level-list", "top-level-string", "null", "empty-object", "legacy-schema"])
    if variant == "identity":
        return json_case("envelope", variant, ACCEPT, p, encoding="")
    if variant in ("br", "deflate", "gzip, br"):
        return Case("envelope", f"Content-Encoding: {variant}", gzip.compress(encode(p), mtime=0), REJECT, variant)
    if variant.startswith("checksum"):
        raw = encode(p)
        digest = hashlib.sha256(raw if variant == "checksum-ok" else raw + b" ").hexdigest()
        return json_case("envelope", variant, ACCEPT if variant == "checksum-ok" else REJECT, raw=raw,
                         headers={"HTTP_X_MOON_SHA256": digest})
    if variant == "legacy-schema":  # v2 sections under the v1 schema name
        p["schema"] = "moon-check/1"
        return json_case("envelope", variant, REJECT, p)
    doc = {"top-level-list": [p], "top-level-string": "report", "null": None, "empty-object": {}}[variant]
    return json_case("envelope", variant, REJECT, raw=json.dumps(doc).encode())


def m_benign(rnd, p):
    variant = rnd.choice(["pristine", "shuffled", "extra-keys", "unicode", "many-evidence", "pretty", "nul"])
    if variant == "shuffled":
        def shuffle(o):
            if isinstance(o, dict):
                items = list(o.items())
                rnd.shuffle(items)
                return {k: shuffle(v) for k, v in items}
            return [shuffle(v) for v in o] if isinstance(o, list) else o
        p = shuffle(p)
    elif variant == "extra-keys":
        for parent in rnd.sample([()] + [q for q, v in nodes(p) if isinstance(v, dict)], 3):
            put(p, parent + (f"x-extra-{rnd.randrange(1000)}",), rnd.choice(JUNK))
    elif variant == "unicode":
        for path in rnd.sample(text_leaves(p), 3):
            put(p, path, rnd.choice(["Проверка игрока", "🌙 moon", "שלום", "C:\\Users\\Игрок\\Загрузки\\файл.exe"]))
    elif variant == "many-evidence":
        k = rnd.choice([100, 1000, 2500])
        p["evidence"] = [evidence_item(i + 1) for i in range(k)]
        p["verdict"]["reasons"][0]["evidence"] = [f"E{i + 1}" for i in range(k)]
    elif variant == "pretty":
        return json_case("benign", variant, ACCEPT, raw=json.dumps(p, indent=2).encode())
    elif variant == "nul":
        for path in rnd.sample(text_leaves(p), 2):
            put(p, path, "before\u0000after")
    return json_case("benign", variant, ACCEPT, p)


MUTATIONS = [m_delete_key, m_wrong_type, m_huge_string, m_bad_number, m_wrong_ids, m_unknown_value, m_deep_nesting,
             m_non_utf8, m_lone_surrogate, m_gzip_damage, m_size, m_envelope, m_benign]


@override_settings(MOON_MAX_UPLOAD_BYTES=UPLOAD_LIMIT, MOON_MAX_REPORT_BYTES=REPORT_LIMIT)
class IngestFuzzTests(TestCase):
    maxDiff = None

    def setUp(self):
        self.admin = make_user("fuzz")
        self.client.raise_request_exception = False  # a crash must show up as a 5xx, not abort the run

    def claim(self):
        cache.clear()  # 300 claims from one address would trip the per-IP limits
        session = make_session(self.admin)
        r = self.client.post("/api/v1/claim", data=json.dumps({"code": session.code, "client": client_info()}),
                             content_type="application/json")
        self.assertEqual(r.status_code, 200, r.content)
        return r.json()["sessionId"], r.json()["token"]

    def upload(self, sid, token, case):
        headers = {"HTTP_AUTHORIZATION": f"Bearer {token}", **case.headers}
        if case.encoding:
            headers["HTTP_CONTENT_ENCODING"] = case.encoding
        return self.client.post(f"/api/v1/sessions/{sid}/report", data=case.body,
                                content_type="application/json", **headers)

    def test_mutated_reports_are_stored_only_when_valid(self):
        rnd = random.Random(SEED)
        base = baseline()
        server_errors, stored_invalid, lost_valid, wrong_answer = [], [], [], []
        expected, outcome = Counter(), Counter()
        for i in range(N):
            case = MUTATIONS[i % len(MUTATIONS)](rnd, copy.deepcopy(base))
            expected[case.expect] += 1
            sid, token = self.claim()
            r = self.upload(sid, token, case)
            s = CheckSession.objects.get(pk=sid)
            stored = Report.objects.filter(session=s).exists() or FindingRow.objects.filter(session=s).exists()
            label = f"#{i} {case.kind}: {case.what} -> HTTP {r.status_code}"
            outcome["accepted" if r.status_code == 200 else f"HTTP {r.status_code}"] += 1
            if r.status_code >= 500:
                server_errors.append(label)
            if r.status_code == 200 and not (stored and s.status == CheckSession.COMPLETED):
                lost_valid.append(label)
            if r.status_code != 200 and (stored or s.status != CheckSession.CONNECTED):
                stored_invalid.append(label)
            if (case.expect == ACCEPT and r.status_code != 200) or \
                    (case.expect == REJECT and not 400 <= r.status_code < 500):
                wrong_answer.append(f"{label} (contract: {case.expect})")

        report = f"expected {dict(expected)}, got {dict(outcome)}"
        self.assertEqual(server_errors, [], report)
        self.assertEqual(stored_invalid, [], report)
        self.assertEqual(lost_valid, [], report)
        self.assertEqual(wrong_answer, [], report)
        self.assertEqual(sum(expected.values()), N)
        # fixed by the seed (docs/validation.md); how the "either" cases end depends on the parser's stack
        self.assertEqual(dict(expected), {ACCEPT: 122, REJECT: 172, EITHER: 6}, report)

    def test_legacy_v1_with_unhashable_values_is_rejected_not_a_crash(self):
        cases = ((lambda p: p.update(verdict={"outcome": "CHEAT"}), 422),
                 (lambda p: p["findings"][0].update(severity=["HIGH"]), 422),
                 (lambda p: p["modules"].update(files=["OK"]), 200))  # an unknown collector state becomes ERROR
        for mutate, status in cases:
            sid, token = self.claim()
            payload = report_payload()
            mutate(payload)
            r = self.upload(sid, token, Case("v1", "", gzip.compress(canonical(payload)), REJECT))
            self.assertEqual(r.status_code, status, r.content)
        self.assertEqual(Report.objects.get(session_id=sid).modules["files"], "ERROR")


class ReplayTests(TestCase):
    """A delivered report cannot be replaced, and a session token opens nothing but its own session."""

    def setUp(self):
        cache.clear()
        self.admin = make_user("replay")

    def claim(self):
        session = make_session(self.admin)
        d = self.client.post("/api/v1/claim", data=json.dumps({"code": session.code, "client": client_info()}),
                             content_type="application/json").json()
        return d["sessionId"], d["token"]

    def upload(self, sid, token, payload):
        return self.client.post(f"/api/v1/sessions/{sid}/report", data=gzip.compress(canonical(payload)),
                                content_type="application/json", HTTP_CONTENT_ENCODING="gzip",
                                HTTP_AUTHORIZATION=f"Bearer {token}")

    def progress(self, sid, token):
        return self.client.post(f"/api/v1/sessions/{sid}/progress", data=json.dumps({"done": 1, "total": 9}),
                                content_type="application/json", HTTP_AUTHORIZATION=f"Bearer {token}")

    def test_completed_session_keeps_its_first_report(self):
        sid, token = self.claim()
        self.assertEqual(self.upload(sid, token, report_v2("NO_EVIDENCE")).status_code, 200)
        first = Report.objects.get(session_id=sid)
        forged = report_v2("VALIDATED_DETECTION", [evidence_item(1, "DETECTION", "CRITICAL")],
                           check_id="MOON-260928-ZZZZ")
        r = self.upload(sid, token, forged)
        self.assertEqual((r.status_code, r.json()["error"]), (409, "already_completed"))
        s = CheckSession.objects.get(pk=sid)
        self.assertEqual((s.status, s.verdict, s.client_check_id), (CheckSession.COMPLETED, "NO_EVIDENCE",
                                                                    "MOON-260928-ABCD"))
        self.assertEqual(Report.objects.filter(session=s).get().sha256, first.sha256)
        self.assertEqual(FindingRow.objects.filter(session=s).count(), 0)
        # nor can the finished session's token reopen it through the progress endpoint
        r = self.progress(sid, token)
        self.assertEqual((r.status_code, r.json()["error"]), (409, "already_completed"))
        self.assertEqual(CheckSession.objects.get(pk=sid).status, CheckSession.COMPLETED)

    def test_a_token_only_opens_its_own_session(self):
        sid_a, token_a = self.claim()
        sid_b, _ = self.claim()
        self.assertEqual(self.upload(sid_b, token_a, report_v2("NO_EVIDENCE")).status_code, 401)
        self.assertEqual(self.progress(sid_b, token_a).status_code, 401)
        b = CheckSession.objects.get(pk=sid_b)
        self.assertEqual((b.status, b.progress_total), (CheckSession.CONNECTED, 0))
        self.assertFalse(Report.objects.filter(session=b).exists())
        # and the token still works where it belongs
        self.assertEqual(self.upload(sid_a, token_a, report_v2("NO_EVIDENCE")).status_code, 200)
