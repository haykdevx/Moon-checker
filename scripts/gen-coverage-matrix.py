#!/usr/bin/env python3
"""Renders docs/coverage-matrix.md from src/main/resources/coverage.json (the single source)."""
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent


def cell(text):
    return str(text).replace("|", "\\|").replace("\n", " ")


def render(catalog):
    out = ["# Coverage matrix", "",
           f"Generated from `src/main/resources/coverage.json` (version {catalog['version']}) by "
           "`scripts/gen-coverage-matrix.py`. Do not edit by hand.", "",
           catalog["note"], "",
           "## Collectors", "",
           "| Collector | Windows | Linux | Required | Privileges | Evidence sources | Evidence kinds | Detection window "
           "| Legitimate lookalikes | Blind spots | Tests |",
           "|---|---|---|---|---|---|---|---|---|---|---|"]
    for m in catalog["modules"]:
        out.append("| " + " | ".join([
            f"**{cell(m['name'])}** (`{m['id']}`)",
            "yes" if "windows" in m["platforms"] else "—",
            "yes" if "linux" in m["platforms"] else "—",
            "yes" if m["required"] else "no (context)",
            cell(m["privileges"]),
            cell("; ".join(m["sources"])),
            cell("; ".join(m["kinds"])),
            cell(m["window"]),
            cell(m["lookalikes"]),
            cell(m["blindSpots"]),
            cell(", ".join(m["tests"]) or "none — collector-level tests missing"),
        ]) + " |")
    out += ["", "## Named rules", "", "| Rule | Kind | Meaning | Legitimate lookalikes | Limits |", "|---|---|---|---|---|"]
    for r in catalog["rules"]:
        out.append(f"| `{r['id']}` | {r['kind']} | {cell(r['meaning'])} | {cell(r['lookalikes'])} | {cell(r['limits'])} |")
    return "\n".join(out) + "\n"


if __name__ == "__main__":
    catalog = json.loads((ROOT / "src/main/resources/coverage.json").read_text(encoding="utf-8"))
    target = ROOT / "docs/coverage-matrix.md"
    text = render(catalog)
    if "--check" in sys.argv:
        sys.exit(0 if target.exists() and target.read_text(encoding="utf-8") == text else
                 "docs/coverage-matrix.md is out of date: run scripts/gen-coverage-matrix.py")
    target.write_text(text, encoding="utf-8")
    print(f"wrote {target}")
