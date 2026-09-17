from django.test import SimpleTestCase
from analyzer.scoring_engine import (
    compute_score,
    detect_scam_patterns,
    score_to_level,
    get_certainty,
)

class ScoringEngineTests(SimpleTestCase):
    def test_score_to_level(self):
        self.assertEqual(score_to_level(10), "Safe")
        self.assertEqual(score_to_level(20), "Low")
        self.assertEqual(score_to_level(45), "Medium")
        self.assertEqual(score_to_level(70), "High")
        self.assertEqual(score_to_level(90), "Critical")

    def test_get_certainty(self):
        self.assertEqual(get_certainty(15, 50), "UNCERTAIN — input quality too low for reliable analysis")
        self.assertEqual(get_certainty(40, 45), "LOW_CONFIDENCE — borderline result, provide clearer input")
        self.assertEqual(get_certainty(90, 80), "CONFIDENT")

    def test_compute_score_basic(self):
        # High confidence, no risk elements should yield 0
        score, breakdown = compute_score(
            llm_score=0,
            pattern_score=0,
            flags_score=0,
            confidence=100
        )
        self.assertEqual(score, 0)
        self.assertEqual(breakdown["llm_score"], 0)
        
        # High confidence, full risk elements
        score, breakdown = compute_score(
            llm_score=80,
            pattern_score=50,
            flags_score=30,
            confidence=100
        )
        # weights at 100 confidence: llm: 0.55, flags: 0.25, patterns: 0.20
        # expected raw: 0.55 * 80 + 0.25 * 30 + 0.20 * 50 = 44 + 7.5 + 10 = 61.5 -> round(61.5) = 62
        self.assertEqual(score, 62)

    def test_compute_score_clamping(self):
        # LLM score > 100 or pattern score > 70 should be clamped appropriately
        score, breakdown = compute_score(
            llm_score=150,
            pattern_score=100, # should clamp pattern score to 70
            flags_score=120,
            confidence=100
        )
        # LLM = 100, Pattern = 70, Flags = 100
        # raw: 0.55 * 100 + 0.25 * 100 + 0.20 * 70 = 55 + 25 + 14 = 94
        self.assertEqual(score, 94)

    def test_compute_score_low_confidence_regression(self):
        # Low confidence (< 40) should regress towards 25
        score, breakdown = compute_score(
            llm_score=80,
            pattern_score=50,
            flags_score=30,
            confidence=20 # < 40
        )
        # w = weights for confidence 20: llm: 0.20, flags: 0.40, patterns: 0.40
        # conf_penalty = (100 - 20) * 0.10 = 8.0
        # raw_before_regression = 0.20 * 80 + 0.40 * 30 + 0.40 * 50 - 8 = 16 + 12 + 20 - 8 = 40
        # regression formula: raw = raw * cf + 25 * (1 - cf) where cf = 20 / 100 = 0.2
        # raw = 40 * 0.2 + 25 * 0.8 = 8 + 20 = 28
        self.assertEqual(score, 28)

    def test_compute_score_url(self):
        # is_url = True
        score, breakdown = compute_score(
            llm_score=85,
            pattern_score=40,
            url_rule_score=50,
            confidence=90,
            is_url=True
        )
        # formula: 0.50 * llm + 0.20 * url_rule + 0.20 * pattern - conf_penalty
        # conf_penalty = (100 - 90) * 0.10 = 1.0
        # raw = 0.50 * 85 + 0.20 * 50 + 0.20 * 40 - 1.0 = 42.5 + 10 + 8 - 1 = 59.5 -> round(59.5) = 60
        self.assertEqual(score, 60)

    def test_detect_scam_patterns_basic(self):
        score, matched, categories = detect_scam_patterns("your account is suspended immediately")
        self.assertTrue("Fear & Intimidation" in categories or "Fear" in categories)
        self.assertIn("Urgency & Time Pressure", categories)
        self.assertTrue(score > 0)

    def test_detect_scam_patterns_adversarial(self):
        # Leetspeak detection: URG3NT -> urgent
        score, matched, categories = detect_scam_patterns("URG3NT! please act immediately")
        self.assertIn("Urgency & Time Pressure", categories)
        
        # Zero-width spaces should be removed and matched
        score_zw, matched_zw, categories_zw = detect_scam_patterns("u\u200brgent")
        self.assertIn("Urgency & Time Pressure", categories_zw)

    def test_detect_scam_patterns_multi_hit(self):
        # Repeated words should weight more but cap
        score1, _, _ = detect_scam_patterns("urgent")
        score2, _, _ = detect_scam_patterns("urgent urgent")
        score3, _, _ = detect_scam_patterns("urgent urgent urgent")
        self.assertTrue(score2 > score1)
        self.assertEqual(score3, score2) # capped at 2 hits per pattern
