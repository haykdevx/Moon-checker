"""
Keeps the Russian translation catalog in step with the code, without GNU gettext.

    python manage.py moon_i18n            # extract, merge into locale/ru/.../django.po, compile django.mo
    python manage.py moon_i18n --check    # fail if anything is untranslated or the catalog is stale

Strings come from templates ({% translate %}, {% blocktranslate %}, found through Django's
own templatize, so the msgids are exactly the ones Django looks up) and from Python calls
to gettext / gettext_lazy / ngettext / pgettext (and their `_` alias). Translations already
in the catalog are kept; strings the code no longer uses are dropped.
"""
import ast
import io
import struct
import tokenize
from pathlib import Path

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError
from django.utils.translation.template import templatize

APPS = ("accounts", "checks", "core", "moonpanel")
LANG = "ru"
PLURAL_FORMS = ("nplurals=3; plural=(n%10==1 && n%100!=11 ? 0 : n%10>=2 && n%10<=4 && "
                "(n%100<10 || n%100>=20) ? 1 : 2);")
HEADER = ("Content-Type: text/plain; charset=UTF-8\n"
          "Language: ru\n"
          f"Plural-Forms: {PLURAL_FORMS}\n")
SINGULAR = {"gettext", "gettext_lazy", "gettext_noop", "_", "_t", "N_"}
PLURAL = {"ngettext", "ngettext_lazy"}
CONTEXT = {"pgettext", "pgettext_lazy"}


class Entry:
    def __init__(self, msgid, plural=None, context=None):
        self.msgid, self.plural, self.context = msgid, plural, context
        self.msgstr = [""] * (3 if plural else 1)
        self.refs = set()

    @property
    def key(self):
        return (self.context, self.msgid)

    def translated(self):
        return all(s for s in self.msgstr)


# ---- extraction ---------------------------------------------------------------------------

def _calls_in_tokens(source):
    """(function name, [string args]) for every gettext-style call in Python-like source."""
    # templatize output is not indented like Python; only the call tokens matter
    source = "\n".join(line.lstrip() for line in source.splitlines())
    toks = [t for t in tokenize.generate_tokens(io.StringIO(source).readline)
            if t.type not in (tokenize.NL, tokenize.NEWLINE, tokenize.COMMENT, tokenize.INDENT, tokenize.DEDENT)]
    names = SINGULAR | PLURAL | CONTEXT
    for i, t in enumerate(toks):
        if t.type == tokenize.NAME and t.string in names and i + 1 < len(toks) and toks[i + 1].string == "(":
            args, j, current = [], i + 2, []
            while j < len(toks) and toks[j].string != ")":
                if toks[j].type == tokenize.STRING:
                    current.append(ast.literal_eval(toks[j].string))
                elif toks[j].string == ",":
                    args.append("".join(current) if current else None)
                    current = []
                j += 1
            args.append("".join(current) if current else None)
            yield t.string, args, t.start[0]


def _entry(name, args):
    if name in SINGULAR and args and args[0]:
        return Entry(args[0])
    if name in PLURAL and len(args) >= 2 and args[0] and args[1]:
        return Entry(args[0], plural=args[1])
    if name in CONTEXT and len(args) >= 2 and args[0] and args[1]:
        return Entry(args[1], context=args[0])
    return None


def extract(base):
    found = {}

    def add(entry, ref):
        if entry is None:
            return
        found.setdefault(entry.key, entry).refs.add(ref)

    for tpl in sorted((base / "templates").rglob("*.html")):
        rel = tpl.relative_to(base).as_posix()
        for name, args, line in _calls_in_tokens(templatize(tpl.read_text(encoding="utf-8"), origin=str(tpl))):
            add(_entry(name, args), rel)
    for app in APPS:
        for py in sorted((base / app).rglob("*.py")):
            if "migrations" in py.parts or "management" in py.parts:
                continue
            rel = py.relative_to(base).as_posix()
            tree = ast.parse(py.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                fn = node.func.id if isinstance(node.func, ast.Name) else (
                    node.func.attr if isinstance(node.func, ast.Attribute) else None)
                if fn not in SINGULAR | PLURAL | CONTEXT:
                    continue
                args = [a.value if isinstance(a, ast.Constant) and isinstance(a.value, str) else None
                        for a in node.args]
                add(_entry(fn, args), rel)
    return found


# ---- .po reading / writing ----------------------------------------------------------------

def _unquote(s):
    return ast.literal_eval(s)


def _quote(s):
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n").replace("\t", "\\t") + '"'


def read_po(path):
    entries = {}
    if not path.exists():
        return entries
    cur, field = {}, None

    def flush():
        if "msgid" in cur and cur["msgid"]:
            e = Entry(cur["msgid"], cur.get("msgid_plural"), cur.get("msgctxt"))
            if e.plural:
                e.msgstr = [cur.get(f"msgstr[{i}]", "") for i in range(3)]
            else:
                e.msgstr = [cur.get("msgstr", "")]
            entries[e.key] = e
        cur.clear()

    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line:
            flush()
            field = None
            continue
        if line.startswith("#"):
            continue
        if line.startswith('"'):
            cur[field] = cur.get(field, "") + _unquote(line)
            continue
        key, _, value = line.partition(" ")
        if key == "msgctxt" and "msgid" in cur:
            flush()
        field = key
        cur[field] = _unquote(value)
    flush()
    return entries


def write_po(path, entries):
    out = ['msgid ""', 'msgstr ""']
    out += [_quote(line + "\n") for line in HEADER.rstrip("\n").split("\n")]
    for e in sorted(entries.values(), key=lambda x: (min(x.refs) if x.refs else "", x.msgid, x.context or "")):
        out.append("")
        for ref in sorted(e.refs):
            out.append(f"#: {ref}")
        if e.context:
            out.append(f"msgctxt {_quote(e.context)}")
        out.append(f"msgid {_quote(e.msgid)}")
        if e.plural:
            out.append(f"msgid_plural {_quote(e.plural)}")
            for i, s in enumerate(e.msgstr):
                out.append(f"msgstr[{i}] {_quote(s)}")
        else:
            out.append(f"msgstr {_quote(e.msgstr[0])}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(out) + "\n", encoding="utf-8")


def compile_mo(entries):
    """GNU .mo bytes (the layout of CPython's Tools/i18n/msgfmt.py)."""
    pairs = {b"": HEADER.encode("utf-8")}
    for e in entries.values():
        if not e.translated():
            continue
        key = e.msgid if not e.plural else e.msgid + "\x00" + e.plural
        if e.context:
            key = e.context + "\x04" + key
        pairs[key.encode("utf-8")] = "\x00".join(e.msgstr).encode("utf-8")
    keys = sorted(pairs)
    ids = strs = b""
    offsets = []
    for k in keys:
        offsets.append((len(ids), len(k), len(strs), len(pairs[k])))
        ids += k + b"\0"
        strs += pairs[k] + b"\0"
    n = len(keys)
    keystart = 7 * 4 + 16 * n
    valuestart = keystart + len(ids)
    koffsets, voffsets = [], []
    for o1, l1, o2, l2 in offsets:
        koffsets += [l1, o1 + keystart]
        voffsets += [l2, o2 + valuestart]
    return (struct.pack("Iiiiiii", 0x950412de, 0, n, 7 * 4, 7 * 4 + n * 8, 0, 0)
            + struct.pack(f"{len(koffsets)}i", *koffsets) + struct.pack(f"{len(voffsets)}i", *voffsets)
            + ids + strs)


class Command(BaseCommand):
    help = "Extract translatable strings, merge them into the Russian catalog and compile it."

    def add_arguments(self, parser):
        parser.add_argument("--check", action="store_true",
                            help="Fail if a string is untranslated or the catalog / .mo is out of date.")

    def handle(self, *args, check=False, **options):
        base = Path(settings.BASE_DIR)
        po = base / "locale" / LANG / "LC_MESSAGES" / "django.po"
        mo = po.with_suffix(".mo")
        found = extract(base)
        existing = read_po(po)
        merged = {}
        for key, e in found.items():
            old = existing.get(key)
            if old is not None and old.plural == e.plural:
                e.msgstr = old.msgstr
            merged[key] = e
        missing = sorted(e.msgid for e in merged.values() if not e.translated())
        obsolete = sorted(k[1] for k in existing if k not in merged)
        mo_bytes = compile_mo(merged)
        if check:
            problems = []
            if missing:
                problems.append(f"{len(missing)} untranslated: " + "; ".join(repr(m) for m in missing[:15]))
            if obsolete:
                problems.append(f"{len(obsolete)} obsolete in django.po: " + "; ".join(repr(m) for m in obsolete[:10]))
            if not mo.exists() or mo.read_bytes() != mo_bytes:
                problems.append("django.mo is not compiled from the current catalog")
            if problems:
                raise CommandError("Translation catalog out of date — run `python manage.py moon_i18n`.\n"
                                   + "\n".join(problems))
            self.stdout.write(f"catalog ok: {len(merged)} strings")
            return
        write_po(po, merged)
        mo.write_bytes(mo_bytes)
        self.stdout.write(f"{len(merged)} strings, {len(missing)} untranslated, {len(obsolete)} dropped")
        for m in missing:
            self.stdout.write(f"  untranslated: {m!r}")
