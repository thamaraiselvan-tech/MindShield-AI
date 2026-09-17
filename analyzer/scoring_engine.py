"""
MindShield AI — Scoring Engine
================================
Multi-factor, confidence-aware, adaptive scoring system
specialized for psychological manipulation detection.

Formula (text/OCR/audio):
  final = w_llm*llm + w_flags*flags + w_patterns*patterns + conf_penalty

Formula (URL):
  final = 0.50*llm + 0.20*url_rules + 0.20*patterns + 0.10*conf_penalty

Key design decisions:
- Single scoring authority: ONLY compute_score() produces final scores
- Adaptive weights: low confidence → trust LLM less
- Confidence penalty: only applied when actual uncertainty exists (not for text)
- Pattern cap: capped at 70 to prevent domination over LLM
- Multi-hit patterns: repeated occurrences weighted more (capped at 2x)
- Normalization: all inputs clamped to 0-100 before use
- Score breakdown: returned for full transparency
- Unicode/leetspeak normalization for adversarial resistance

Privacy: All scoring is stateless — no data is persisted.
"""

import re
import unicodedata
import logging

logger = logging.getLogger(__name__)

# =========================
# TEXT NORMALIZATION (Adversarial resistance)
# =========================

# Leetspeak mapping for common evasion patterns
LEETSPEAK_MAP = {
    '0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's',
    '6': 'g', '7': 't', '8': 'b', '9': 'g', '@': 'a',
}

def normalize_text_for_patterns(text):
    """
    Normalize text to catch adversarial evasion:
    - Remove zero-width characters (U+200B, U+200C, U+200D, U+FEFF, etc.)
    - Normalize unicode (NFKD) to catch homoglyphs
    - Decode leetspeak per-word (FR33 M0NEY → free money)
    Returns both original lowercase and normalized version for matching.
    """
    if not text:
        return "", ""

    text_lower = text.lower()

    # Remove zero-width characters
    zero_width = re.compile(r'[\u200b\u200c\u200d\u2060\ufeff\u00ad]')
    normalized = zero_width.sub('', text_lower)

    # Unicode normalize (catches Cyrillic а→a, Greek ο→o, etc.)
    normalized = unicodedata.normalize('NFKD', normalized)
    normalized = normalized.encode('ascii', 'ignore').decode('ascii')

    # Leetspeak decode: apply per-word to preserve word boundaries
    # Split on non-alphanumeric, decode each token, rejoin with spaces
    tokens = re.split(r'([^a-z0-9]+)', normalized)
    decoded_tokens = []
    for token in tokens:
        if re.match(r'^[a-z0-9]+$', token):
            decoded = ''.join(LEETSPEAK_MAP.get(c, c) for c in token)
            decoded_tokens.append(decoded)
        else:
            decoded_tokens.append(token)
    normalized = ''.join(decoded_tokens)

    return text_lower, normalized


# =========================
# PSYCHOLOGICAL MANIPULATION PATTERN LIBRARY
# Organized by manipulation category
# =========================

SCAM_PATTERNS = [
    # ── FEAR & INTIMIDATION ──
    (r'\byour account.{0,20}(suspend|block|terminat|clos|restrict|lock)',
     15, "Fear: account suspension/closure threat", "Fear & Intimidation"),
    (r'\byour (device|computer|phone|system).{0,20}(infect|hack|virus|compromis|breach)',
     15, "Fear: device/system threat", "Fear & Intimidation"),
    (r'\b(security|suspicious).{0,20}(alert|warning|breach|issue|incident)',
     12, "Fear: security alert language", "Fear & Intimidation"),
    (r'\b(legal|police|arrest|lawsuit|court).{0,20}(action|notice|proceedings)',
     15, "Fear: legal threat", "Fear & Intimidation"),
    (r'\b(penalty|fine|consequence).{0,10}(if|unless|failure)',
     12, "Fear: penalty/consequence threat", "Fear & Intimidation"),
    (r'\byou will (lose|forfeit|miss)',
     10, "Fear: loss aversion trigger", "Fear & Intimidation"),
    (r'\bfailure to (comply|respond|act|verify)',
     12, "Fear: compliance pressure", "Fear & Intimidation"),

    # ── URGENCY & TIME PRESSURE ──
    (r'\burgent\b', 12, "Urgency: word 'urgent'", "Urgency & Time Pressure"),
    (r'\bact now\b', 12, "Urgency: 'act now'", "Urgency & Time Pressure"),
    (r'\blimited (time|offer|period|spots?)\b', 10, "Urgency: 'limited offer'", "Urgency & Time Pressure"),
    (r'\bexpires? (soon|today|tonight|tomorrow)\b', 10, "Urgency: expiry pressure", "Urgency & Time Pressure"),
    (r'\bimmediately\b', 10, "Urgency: 'immediately'", "Urgency & Time Pressure"),
    (r'\blast chance\b', 10, "Urgency: 'last chance'", "Urgency & Time Pressure"),
    (r'\bdo not (ignore|delay|wait)\b', 10, "Urgency: ignore/delay warning", "Urgency & Time Pressure"),
    (r'\b(within|before|only)\s+\d+\s*(hour|minute|day|hr|min)', 10, "Urgency: specific time deadline", "Urgency & Time Pressure"),
    (r'\bhurry\b', 8, "Urgency: 'hurry'", "Urgency & Time Pressure"),
    (r'\b(don.t|do not) miss (out|this)\b', 8, "Urgency: FOMO trigger", "Urgency & Time Pressure"),
    (r'\btoday only\b', 10, "Urgency: 'today only'", "Urgency & Time Pressure"),

    # ── AUTHORITY EXPLOITATION ──
    (r'\b(rbi|sebi|government|pm|cbi|income tax|irs|fbi|cia).{0,30}(notice|alert|warning|order)',
     18, "False authority: government impersonation", "Authority Exploitation"),
    (r'\b(microsoft|amazon|apple|google|paypal|netflix).{0,20}(support|alert|warning|team|department)',
     15, "False authority: tech brand impersonation", "Authority Exploitation"),
    (r'\bverify.{0,20}(account|identity|details|information)',
     12, "Authority: verification demand", "Authority Exploitation"),
    (r'\b(official|authorized|certified)\s+(notice|communication|message)',
     12, "Authority: false official status", "Authority Exploitation"),
    (r'\b(doctor|expert|scientist|professor|specialist)\s+(recommend|confirm|prove|discover)',
     10, "Authority: expert endorsement claim", "Authority Exploitation"),
    (r'\bcustomer (service|support|care).{0,15}(contact|call|reach)',
     8, "Authority: fake customer service", "Authority Exploitation"),

    # ── SOCIAL PROOF MANIPULATION ──
    (r'\b(million|thousand|hundred)s?\s+(of\s+)?(people|users|customers|members)\b',
     8, "Social proof: inflated user numbers", "Social Proof Manipulation"),
    (r'\beveryone\s+(is|has been|knows)\b',
     8, "Social proof: everyone is doing it", "Social Proof Manipulation"),
    (r'\b(join|joining)\s+\d+[\+k]?\s*(others|people|members)',
     8, "Social proof: join the crowd", "Social Proof Manipulation"),
    (r'\b(rated|reviewed|trusted)\s+by\s+\d+',
     6, "Social proof: rating/trust claim", "Social Proof Manipulation"),

    # ── EMOTIONAL EXPLOITATION ──
    (r'\byou.{0,10}(won|selected|chosen|eligible|lucky)',
     10, "Emotional: false reward/selection", "Emotional Exploitation"),
    (r'\b(help|save|rescue|donate).{0,20}(child|dying|sick|starving|poor)',
     10, "Emotional: sympathy exploitation", "Emotional Exploitation"),
    (r'\b(share|forward).{0,15}(if you care|show you care|love|heart)',
     10, "Emotional: guilt for not sharing", "Emotional Exploitation"),
    (r'\b(only you|specially for you|just for you)\b',
     8, "Emotional: false exclusivity", "Emotional Exploitation"),
    (r'\b(congratulations?|congrats)\b.{0,30}(won|winner|selected|lucky)',
     12, "Emotional: false congratulations", "Emotional Exploitation"),

    # ── SCARCITY TACTICS ──
    (r'\b(only|just)\s+\d+\s*(left|remaining|available|spots?)',
     10, "Scarcity: limited availability", "Scarcity Tactics"),
    (r'\b(exclusive|vip|premium)\s+(access|offer|deal|invitation)',
     8, "Scarcity: false exclusivity", "Scarcity Tactics"),
    (r'\b(selling|going) fast\b',
     6, "Scarcity: selling fast pressure", "Scarcity Tactics"),

    # ── FINANCIAL SCAMS ──
    (r'\bfree money\b', 18, "Financial scam: 'free money'", "Reciprocity Trap"),
    (r'\b(lottery|prize).{0,20}(won|claim|collect)', 18, "Financial: lottery/prize scam", "Emotional Exploitation"),
    (r'\binvest.{0,20}(guaranteed|100%).{0,20}(return|profit)', 20, "Financial: guaranteed returns scam", "Information Manipulation"),
    (r'\bsend.{0,20}(money|upi|payment).{0,20}(to claim|to receive)', 20, "Financial: advance fee scam", "Reciprocity Trap"),
    (r'\b(otp|pin|password|cvv).{0,20}(share|send|give|enter|provide)', 20, "Phishing: credential request", "Authority Exploitation"),
    (r'\bclick.{0,20}(link|here|below|button)\b', 10, "Suspicious link prompt", "Urgency & Time Pressure"),
    (r'\b(double|triple|10x).{0,10}(your|the)\s*(money|investment|bitcoin|crypto)',
     18, "Financial: multiplication scam", "Information Manipulation"),

    # ── GASLIGHTING ──
    (r'\byou (never|always|don.t remember|forgot|are wrong|are confused)',
     12, "Gaslighting: reality questioning", "Gaslighting"),
    (r'\b(nobody|no one) (believes?|will believe|cares?|supports?)\s+you',
     15, "Gaslighting: isolation tactic", "Gaslighting"),
    (r'\bthat (never|didn.t) happen',
     12, "Gaslighting: event denial", "Gaslighting"),
    (r'\byou.re (being|too) (dramatic|sensitive|paranoid|crazy|emotional|irrational)',
     15, "Gaslighting: dismissing feelings", "Gaslighting"),

    # ── INFORMATION MANIPULATION ──
    (r'\b(they|government|media|big pharma|doctors?|experts?|scientists?).{0,25}(hiding|don.t want|doesn.t want|secret|cover.?up|suppress|won.t tell)',
     12, "Conspiracy: hidden truth claim", "Information Manipulation"),
    (r'\bshare.{0,20}before.{0,20}(delete|remove|banned|censor)',
     15, "Misinformation: share-before-deletion", "Information Manipulation"),
    (r'\b(scientists?|doctors?|experts?).{0,20}(silenced|suppressed|censored)',
     12, "Misinformation: suppressed expert claim", "Information Manipulation"),
    (r'\b(cure|treat).{0,20}(cancer|covid|diabetes|aids).{0,20}(instant|secret|hidden|miracle)',
     18, "Medical misinformation: miracle cure", "Information Manipulation"),
    (r'\b(secret|hidden|miracle|ancient)\s+(cure|remedy|treatment|formula)',
     15, "Medical misinformation: secret cure claim", "Information Manipulation"),
    (r'\b(exposed|revealed|leaked|whistleblower)',
     6, "Information: sensational reveal language", "Information Manipulation"),
    (r'\b(mainstream media|msm|fake news).{0,15}(won.t|doesn.t|refuse)',
     10, "Information: media distrust seeding", "Information Manipulation"),
    (r'\bbreaking\b.{0,30}(secret|revealed|exposed|truth|shocking)',
     10, "Information: sensational breaking claim", "Information Manipulation"),

    # ── IDENTITY DECEPTION ──
    (r'\bdear (valued |esteemed )?(customer|user|member|client|sir|madam)',
     8, "Deception: generic salutation", "Identity Deception"),
    (r'\bfrom.{0,10}(the desk|office) of\b',
     10, "Deception: fake official origin", "Identity Deception"),

    # ═══════════════════════════════════════════
    # NEW: MODERN SCAM PATTERNS (2024-2026)
    # ═══════════════════════════════════════════

    # ── CRYPTO / NFT SCAMS ──
    (r'\b(airdrop|whitelist|mint)\s+(now|today|live|open)\b',
     15, "Crypto scam: airdrop/mint urgency", "Scarcity Tactics"),
    (r'\bconnect\s+(your\s+)?wallet\b',
     15, "Crypto scam: wallet connection request", "Authority Exploitation"),
    (r'\b(crypto|bitcoin|btc|eth|ethereum).{0,20}(giveaway|double|free|airdrop)',
     18, "Crypto scam: fake giveaway", "Reciprocity Trap"),
    (r'\b(nft|token).{0,20}(exclusive|limited|rare|sell.{0,5}out)',
     10, "Crypto scam: NFT scarcity pressure", "Scarcity Tactics"),
    (r'\bseed\s*phrase\b', 20, "Crypto scam: seed phrase theft", "Authority Exploitation"),
    (r'\b(defi|yield|staking).{0,15}(guaranteed|risk.?free|100%)',
     18, "Crypto scam: guaranteed DeFi returns", "Information Manipulation"),

    # ── QR CODE SCAMS ──
    (r'\bscan\s+(this\s+)?qr\s*(code)?\b',
     10, "QR scam: scan QR code prompt", "Urgency & Time Pressure"),
    (r'\bqr\s*code.{0,20}(pay|payment|transfer|verify)',
     15, "QR scam: QR payment request", "Authority Exploitation"),

    # ── ROMANCE / RELATIONSHIP SCAMS ──
    (r'\b(stuck|stranded)\s+(abroad|overseas|at\s+airport|in\s+another\s+country)',
     15, "Romance scam: stranded abroad", "Emotional Exploitation"),
    (r'\bsend\s+money\s+for\s+(ticket|visa|hospital|treatment|bail)',
     18, "Romance scam: money for emergency", "Emotional Exploitation"),
    (r'\b(love|miss)\s+you.{0,20}(send|transfer|need).{0,20}(money|\$|₹)',
     18, "Romance scam: emotional money request", "Emotional Exploitation"),
    (r'\binheritance.{0,20}(claim|share|split|transfer)',
     15, "Romance/advance fee: inheritance scam", "Reciprocity Trap"),

    # ── JOB / INCOME SCAMS ──
    (r'\b(work\s+from\s+home|wfh).{0,20}(earn|income|salary|₹|\$)',
     12, "Job scam: work from home earnings", "Emotional Exploitation"),
    (r'\b(no\s+experience|no\s+qualification|no\s+degree).{0,15}(needed|required)',
     10, "Job scam: unrealistic requirements", "Information Manipulation"),
    (r'\bearn\s+₹?\$?\d+[,\d]*\s*(per|a|every|\/)\s*(day|hour|week)',
     12, "Job scam: unrealistic income claims", "Information Manipulation"),
    (r'\b(data\s+entry|typing|copy\s*paste).{0,20}(job|earn|income|₹|\$)',
     10, "Job scam: data entry money promise", "Information Manipulation"),
    (r'\b(registration|joining)\s+fee\b',
     15, "Job scam: upfront fee demand", "Reciprocity Trap"),

    # ── TECH SUPPORT SCAMS ──
    (r'\byour\s+(computer|pc|device)\s+(has\s+been\s+)?sending\s+(virus|error)',
     15, "Tech support scam: fake virus alert", "Fear & Intimidation"),
    (r'\bcall\s+(this|our|the)\s+(number|helpline|support)',
     8, "Tech support scam: call prompt", "Authority Exploitation"),
    (r'\b(remote\s+access|anydesk|teamviewer).{0,15}(install|download|allow)',
     18, "Tech support scam: remote access request", "Authority Exploitation"),
    (r'\b(windows|microsoft|apple)\s+(detected|found).{0,15}(virus|malware|threat)',
     15, "Tech support scam: fake OS alert", "Fear & Intimidation"),

    # ── IMPERSONATION VIA MESSAGING ──
    (r'\bhi\s+(mom|dad|mum|papa|amma)\b.{0,20}(lost|broke|new)\s+(my\s+)?phone',
     15, "Impersonation: family member phone scam", "Identity Deception"),
    (r'\bthis\s+is\s+(your|my)\s+(son|daughter|child|kid)\b',
     12, "Impersonation: family identity claim", "Identity Deception"),
    (r'\b(whatsapp|telegram|signal).{0,15}(hacked|compromised|locked)',
     12, "Impersonation: account hack claim", "Fear & Intimidation"),

    # ── DEEPFAKE / AI-GENERATED CONTENT INDICATORS ──
    (r'\b(this\s+video\s+proves?|watch\s+this\s+video).{0,20}(shocking|unbelievable|must\s+see)',
     10, "AI content: sensational video claim", "Information Manipulation"),
    (r'\b(celebrity|pm|president|minister).{0,20}(endorses?|recommends?|uses?).{0,20}(product|pill|supplement)',
     15, "Deepfake: fake celebrity endorsement", "Authority Exploitation"),

    # ═══════════════════════════════════════════
    # BASIC HINDI / HINGLISH PATTERNS
    # ═══════════════════════════════════════════

    (r'\b(jaldi|turant|abhi)\s+(karo|kijiye|bhejo)\b',
     10, "Hindi urgency: immediate action demand", "Urgency & Time Pressure"),
    (r'\b(paisa|paise|rupay|rupee).{0,15}(bhejo|transfer|send)\b',
     15, "Hindi financial: money transfer request", "Reciprocity Trap"),
    (r'\b(otp|pin)\s+(batao|bhejo|do|dijiye)\b',
     20, "Hindi phishing: OTP/PIN request", "Authority Exploitation"),
    (r'\b(lottery|inam|prize|inaam).{0,15}(jeeta|mila|won|lagi)\b',
     15, "Hindi scam: lottery/prize claim", "Emotional Exploitation"),
    (r'\b(khata|account)\s+(band|block|suspend)\b',
     15, "Hindi fear: account block threat", "Fear & Intimidation"),
    (r'\blink\s+par\s+(click|tap)\s+(karo|kijiye|karein)\b',
     12, "Hindi scam: click link demand", "Urgency & Time Pressure"),
    (r'\bfree\s+(me|mein)\s+(milega|paiye|pao)\b',
     10, "Hindi scam: free offer bait", "Reciprocity Trap"),
]


def detect_scam_patterns(text):
    """
    Run psychological manipulation pattern detection on text.
    Multi-hit: repeated occurrences add extra weight (capped at 2x per pattern).
    Pattern score capped at 70 to prevent dominating LLM signal.

    Uses both original and normalized text for adversarial resistance.

    Returns: (total_score 0-70, list of matched descriptions, dict of category counts)
    """
    if not text:
        return 0, [], {}

    text_lower, text_normalized = normalize_text_for_patterns(text)
    total = 0
    matched = []
    categories = {}

    for pattern, weight, label, category in SCAM_PATTERNS:
        # Check both original and normalized text
        hits_original = len(re.findall(pattern, text_lower))
        hits_normalized = len(re.findall(pattern, text_normalized))
        hits = max(hits_original, hits_normalized)

        if hits > 0:
            total += weight * min(hits, 2)
            matched.append(label)
            categories[category] = categories.get(category, 0) + 1

    total = min(total, 70)
    return total, matched, categories


# =========================
# ADAPTIVE WEIGHTS
# =========================

def get_adaptive_weights(confidence):
    """
    Adapt component weights based on input confidence.
    Low confidence (bad OCR, short audio) → trust LLM less, patterns more.
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
    """Clamp any score to valid 0-100 range."""
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
# Single scoring authority — all final scores go through here.
# =========================

def compute_score(llm_score, pattern_score, flags_score=0,
                  url_rule_score=0, confidence=100, is_url=False,
                  use_conf_penalty=True):
    """
    Unified weighted scoring for all input types.
    This is the ONLY function that produces final risk scores.
    Returns: (final_score 0-100, breakdown dict)
    """
    llm_score      = normalize(llm_score, "llm_score")
    pattern_score  = normalize(min(pattern_score, 70), "pattern_score")
    flags_score    = normalize(flags_score, "flags_score")
    url_rule_score = normalize(url_rule_score, "url_rule_score")
    confidence     = normalize(confidence, "confidence")

    conf_penalty = (100 - confidence) * 0.10 if (use_conf_penalty and confidence < 100) else 0

    if is_url:
        # URL formula: LLM dominant, URL rules and patterns support
        # conf_penalty subtracts confidence-based uncertainty
        raw = (
            0.50 * llm_score +
            0.20 * url_rule_score +
            0.20 * pattern_score -
            0.10 * conf_penalty * 10
        )
        weights_used = {"llm": 0.50, "url_rules": 0.20, "patterns": 0.20, "conf_penalty": -0.10}
    else:
        w = get_adaptive_weights(confidence)
        raw = (
            w["llm"]      * llm_score +
            w["flags"]    * flags_score +
            w["patterns"] * pattern_score -
            conf_penalty
        )
        weights_used = w

        # Low confidence: regress toward LOW risk (25), not MEDIUM (50)
        # This prevents safe content with poor OCR from being falsely flagged
        if confidence < 40:
            cf = confidence / 100.0
            raw = raw * cf + 25 * (1 - cf)

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
    if score < 15:   return "Safe"
    elif score < 35: return "Low"
    elif score < 60: return "Medium"
    elif score < 80: return "High"
    else:            return "Critical"


def get_certainty(confidence, score):
    """
    Return certainty state based on input confidence and score stability.
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
