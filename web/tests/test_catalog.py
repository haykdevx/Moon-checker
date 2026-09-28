import json
import pathlib
import subprocess
import sys
import unittest

from django.test import SimpleTestCase

from checks.views import CATALOG_PATH, load_catalog

REPO = pathlib.Path(__file__).resolve().parents[2]
SOURCE = REPO / "src" / "main" / "resources" / "coverage.json"


class CatalogTests(SimpleTestCase):
    def test_catalog_has_modules_and_rules(self):
        catalog = load_catalog()
        self.assertGreaterEqual(len(catalog["modules"]), 17)
        self.assertTrue(any(r["kind"] == "DETECTION" for r in catalog["rules"]))

    @unittest.skipUnless(SOURCE.exists(), "checker sources not present (e.g. inside the image)")
    def test_panel_copy_matches_the_checker(self):
        self.assertEqual(json.loads(SOURCE.read_text(encoding="utf-8")),
                         json.loads(CATALOG_PATH.read_text(encoding="utf-8")),
                         "web/checks/data/coverage.json must be a copy of src/main/resources/coverage.json")

    @unittest.skipUnless(SOURCE.exists(), "checker sources not present")
    def test_coverage_matrix_doc_is_current(self):
        r = subprocess.run([sys.executable, str(REPO / "scripts" / "gen-coverage-matrix.py"), "--check"],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr or r.stdout)
