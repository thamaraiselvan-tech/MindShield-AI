"""
MindShield AI — Scoring Engine
================================
Multi-factor, confidence-aware, adaptive scoring system.

Formula (text/OCR/audio):
  final = w_llm*llm + w_flags*flags + w_patterns*patterns + conf_penalty

Formula (URL):
  final = 0.5*llm + 0.2*url_rules + 0.2*patterns + 0.1*conf_penalty

Key design decisions:
- Adaptive weights: low confidence → trust LLM less
- Confidence penalty: only applied when actual uncertainty exists (not for text)
- Pattern cap: capped at 70 to prevent domination over LLM
- Multi-hit patterns: repeated occurrences weighted more (capped at 2x)
- Normalization: all inputs clamped to 0-100 before use
- Score breakdown: returned for full transparency
"""

import re
import logging

logger = logging.getLogger(__name__)

# =========================
# SCAM PATTERN LIBRARY
# =========================

SCAM_PATTERNS = [
    # Urgency triggers
    (r'\burgent\b',                                          12, "Urgency: 'urgent'"),
    (r'\bact now\b',                                         12, "Urgency: 'act now'"),
    (r'\blimited (time|offer)\b',                            10, "Urgency: 'limited offer'"),
    (r'\bexpires? (soon|today)\b',                           10, "Urgency: expiry pressure"),
    (r'\bimmediately\b',                                      8, "Urgency: 'immediately'"),
    (r'\blast chance\b',                                     10, "Urgency: 'last chance'"),
    (r'\bdo not (ignore|delay)\b',                            8, "Urgency: ignore/delay warning"),

    # Fear triggers
    (r'\byour account.{0,20}(suspend|block|terminat)',       15, "Fear: account suspension threat"),
    (r'\byour (device|computer|phone).{0,20}(infect|hack|virus)', 15, "Fear: device threat"),
    (r'\b(security|suspicious).{0,20}(alert|warning|breach)', 12, "Fear: security alert"),
    (r'\byou.{0,10}(won|selected|chosen|eligible)',          10, "False reward claim"),

    # False authority
    (r'\b(rbi|sebi|government|pm|cbi|income tax).{0,30}(notice|alert|warning)', 18, "False authority: government claim"),
    (r'\b(microsoft|amazon|apple|google).{0,20}(support|alert|warning)',         15, "False authority: tech brand"),
    (r'\bverify.{0,20}(account|identity|details)',                                12, "Verification scam"),

    # Financial scams
    (r'\bfree money\b',                                      18, "Financial scam: 'free money'"),
    (r'\b(lottery|prize).{0,20}(won|claim|collect)',         18, "Lottery/prize scam"),
    (r'\binvest.{0,20}(guaranteed|100%).{0,20}(return|profit)', 20, "Investment scam: guaranteed returns"),
    (r'\bsend.{0,20}(money|upi|payment).{0,20}(to claim|to receive)', 20, "Advance fee scam"),
    (r'\b(otp|pin|password).{0,20}(share|send|give)',        20, "Credential phishing"),
    (r'\bclick.{0,20}link\b',                                10, "Suspicious link prompt"),

    # Misinformation markers
    (r'\b(they|government|media).{0,20}(hiding|don.t want|secret)',    12, "Conspiracy marker"),
    (r'\bshare.{0,20}before.{0,20}(delete|remove|banned)',             15, "Share-before-deletion pressure"),
    (r'\b(scientists?|doctors?|experts?).{0,20}(silenced|suppressed)', 12, "Suppressed expert claim"),
    (r'\b(cure|treat).{0,20}(cancer|covid|diabetes).{0,20}(instant|secret|hidden)', 18, "Medical misinformation"),
]


def detect_scam_patterns(text):
    """
    Run scam pattern detection on text.
    Multi-hit: repeated occurrences add extra weight (capped at 2x per pattern).
    Pattern score capped at 70 to prevent dominating LLM signal.

    Returns: (total_score 0-70, list of matched descriptions)
    """
    if not text:
        return 0, []

    text_lower = text.lower()
    total = 0
    matched = []

    for pattern, weight, label in SCAM_PATTERNS:
        hits = len(re.findall(pattern, text_lower))
        if hits > 0:
            # Multi-hit: cap at 2x weight
            total += weight * min(hits, 2)
            matched.append(label)

    # Cap at 70 — patterns alone should never push to High without LLM confirmation
    total = min(total, 70)
    return total, matched


# =========================
# ADAPTIVE WEIGHTS
# =========================

def get_adaptive_weights(confidence):
    """
    Adapt component weights based on input confidence.
    Low confidence (bad OCR, short audio) → trust LLM less, patterns more.

    Example:
        confidence=90 → llm=0.55, flags=0.25, patterns=0.20
        confidence=25 → llm=0.20, flags=0.40, patterns=0.40
    """
    if confidence >= 75:
        return {"llm": 0.55, "flags": 0.25, "patterns": 0.20}
    elif confidence >= 50:
        return {"llm": 0.45, "flags": 0.30, "patterns": 0.25}
    elif confidence >= 30:
        return {"llm": 0.30, "flags": 0.35, "patterns": 0.35}
    else:
        return {"llm": 0.20, "flags": 0.40, "patterns": 0.40}


# =========================
# NORMALIZE INPUT
# =========================

def normalize(value, name="value"):
    """Clamp any score to valid 0-100 range. Prevents broken modules from corrupting results."""
    try:
        v = float(value)
        if not (0 <= v <= 100):
            logger.warning(f"Score out of range: {name}={v}, clamping to 0-100")
        return max(0.0, min(100.0, v))
    except (TypeError, ValueError):
        logger.warning(f"Invalid score value for {name}: {value!r}, defaulting to 0")
        return 0.0


# =========================
# MAIN SCORING FUNCTION
# =========================

def compute_score(llm_score, pattern_score, flags_score=0,
                  url_rule_score=0, confidence=100, is_url=False,
                  use_conf_penalty=True):
    """
    Unified weighted scoring for all input types.

    Args:
        llm_score:        0-100 from LLM fake_probability
        pattern_score:    0-100 from scam pattern detection (auto-capped at 70)
        flags_score:      0-100 from rule-based content flags
        url_rule_score:   0-100 URL-specific domain/structure signals
        confidence:       0-100 input quality (OCR/audio reliability)
        is_url:           use URL-specific fixed formula
        use_conf_penalty: False for direct text (no OCR uncertainty)

    Returns:
        (final_score 0-100, breakdown dict)
    """
    # Normalize all inputs
    llm_score      = normalize(llm_score, "llm_score")
    pattern_score  = normalize(min(pattern_score, 70), "pattern_score")  # cap at 70
    flags_score    = normalize(flags_score, "flags_score")
    url_rule_score = normalize(url_rule_score, "url_rule_score")
    confidence     = normalize(confidence, "confidence")

    # Confidence penalty: only when actual uncertainty exists
    # text input always passes confidence=100, so penalty=0
    conf_penalty = (100 - confidence) * 0.10 if (use_conf_penalty and confidence < 100) else 0

    if is_url:
        # URL: fixed formula — explainable and consistent
        raw = (
            0.50 * llm_score +
            0.20 * url_rule_score +
            0.20 * pattern_score +
            0.10 * conf_penalty * 10  # normalize penalty to same scale
        )
        weights_used = {"llm": 0.50, "url_rules": 0.20, "patterns": 0.20, "conf_penalty": 0.10}
    else:
        # Adaptive weights based on confidence
        w = get_adaptive_weights(confidence)
        raw = (
            w["llm"]      * llm_score +
            w["flags"]    * flags_score +
            w["patterns"] * pattern_score +
            conf_penalty
        )
        weights_used = w

        # Low confidence: pull toward uncertain neutral (50)
        if confidence < 40:
            cf = confidence / 100.0
            raw = raw * cf + 50 * (1 - cf)

    final = max(0, min(100, round(raw)))

    breakdown = {
        "llm_score":      round(llm_score),
        "pattern_score":  round(pattern_score),
        "flags_score":    round(flags_score),
        "url_rule_score": round(url_rule_score),
        "confidence":     round(confidence),
        "conf_penalty":   round(conf_penalty, 2),
        "weights":        weights_used,
        "raw_before_clamp": round(raw, 2),
    }

    logger.debug(f"Score breakdown: {breakdown} → final={final}")
    return final, breakdown


# =========================
# LEVEL + CERTAINTY
# =========================

def score_to_level(score):
    if score < 20:   return "No Significant Risk"
    elif score < 40: return "Low"
    elif score < 70: return "Medium"
    else:            return "High"


def get_certainty(confidence, score):
    """
    Return certainty state based on input confidence and score stability.
    Helps system communicate its own reliability to users and judges.

    Returns one of: CONFIDENT | LOW_CONFIDENCE | UNCERTAIN
    """
    if confidence < 30:
        return "UNCERTAIN — input quality too low for reliable analysis"
    if confidence < 50 and 30 <= score <= 60:
        return "LOW_CONFIDENCE — borderline result, provide clearer input"
    return "CONFIDENT"


# =========================
# URL RULE SCORE
# =========================

def compute_url_rule_score_from_domain(domain_info, structure_flags, flag_weights):
    """
    Compute a 0-100 rule score purely from URL/domain signals.
    Used as url_rule_score input to compute_score().
    """
    score = 0

    if not domain_info.get("is_https"):          score += 8
    if domain_info.get("suspicious_tld"):         score += 20
    if domain_info.get("subdomain_spoof"):        score += 35
    if domain_info.get("homoglyph_attack"):       score += 35

    age = domain_info.get("domain_age_days")
    if age is not None:
        if age < 90:    score += 20
        elif age < 365: score += 8

    for flag in (structure_flags or []):
        score += flag_weights.get(flag, 5)

    return max(0, min(100, score))
