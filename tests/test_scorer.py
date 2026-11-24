"""Tests for the scorer and the scoring rules (thresholds, context rules, taxonomy)."""

import pytest

from app.scoring.rules import ScoringRules


@pytest.mark.parametrize(
    ("score", "action"),
    [(0, "ALLOW"), (30, "ALLOW"), (30.5, "ALLOW"), (31, "WARN"), (49, "WARN"), (49.9, "WARN"), (50, "BLOCK"), (100, "BLOCK")],
)
def test_threshold_boundaries(score, action):
    assert ScoringRules.get_risk_level(score)["action"] == action


def test_threshold_arguments_override_class_defaults():
    assert ScoringRules.get_risk_level(60, warn=40, block=70)["action"] == "WARN"
    assert ScoringRules.get_risk_level(35, warn=40, block=70)["action"] == "ALLOW"


def test_risk_thresholds_derived_from_constants():
    assert ScoringRules.RISK_THRESHOLDS["medium"]["min"] == ScoringRules.WARN_THRESHOLD
    assert ScoringRules.RISK_THRESHOLDS["high"]["min"] == ScoringRules.BLOCK_THRESHOLD
