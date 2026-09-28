"""
The checker (ru.moon.checker.core.VerdictEngine) and the panel (checks.policy) must give the same
outcome for the same evidence and coverage: the panel recomputes every uploaded report's outcome
and flags a disagreement as tampering, so a drift between the two would flag honest reports.

spec/policy-golden.json holds 1000 random scenarios with the outcome the Java engine gave
(ValidationCorpusTest, seed 20260928; see docs/validation.md). This test replays them through
the Python policy.
"""
import json
import unittest

from django.conf import settings
from django.test import SimpleTestCase

from checks import policy

GOLDEN = settings.BASE_DIR.parent / "spec" / "policy-golden.json"


@unittest.skipUnless(GOLDEN.exists(), "spec/policy-golden.json is not present (the panel image ships only web/)")
class PolicyGoldenTests(SimpleTestCase):
    def test_panel_policy_agrees_with_the_checker_on_every_golden_scenario(self):
        scenarios = json.loads(GOLDEN.read_text(encoding="utf-8"))
        self.assertEqual(len(scenarios), 1000)
        disagree = []
        for i, sc in enumerate(scenarios):
            cov = dict(sc["coverage"])
            cov["rulesOk"] = policy.rules_ok(sc["rules"])
            got = policy.expected_outcome(sc["evidence"], cov)
            if got != sc["outcome"]:
                disagree.append(f"#{i}: checker {sc['outcome']}, panel {got}")
        agree = len(scenarios) - len(disagree)
        self.assertEqual(disagree, [], f"{agree}/{len(scenarios)} golden scenarios agree")
        self.assertEqual(agree, 1000)

    def test_every_outcome_is_exercised(self):
        scenarios = json.loads(GOLDEN.read_text(encoding="utf-8"))
        self.assertEqual({sc["outcome"] for sc in scenarios}, set(policy.OUTCOMES))
