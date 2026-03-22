from rest_framework.decorators import api_view, throttle_classes
from rest_framework.throttling import AnonRateThrottle
from rest_framework.response import Response
from rest_framework import status
import logging
import re

from .llm_engine import analyze_with_llm
from .ocr_engine import extract_text_from_image
from .audio_engine import transcribe_audio
from .url_engine import analyze_url_input
from .scoring_engine import (
    detect_scam_patterns,
    compute_score,
    score_to_level,
    get_certainty,
    compute_url_rule_score_from_domain,
)

def _score(llm, pat, flags=0, url=0, conf=100, is_url=False, use_penalty=True):
    """Wrapper: unpacks (score, breakdown) tuple from compute_score."""
    score, breakdown = compute_score(llm, pat, flags, url, conf, is_url, use_penalty)
    return score, breakdown

logger = logging.getLogger(__name__)

MAX_IMAGE_SIZE = 5  * 1024 * 1024
MAX_AUDIO_SIZE = 20 * 1024 * 1024

ALLOWED_IMAGE_TYPES = {"image/jpeg", "image/png", "image/webp", "image/gif"}
ALLOWED_AUDIO_TYPES = {"audio/mpeg", "audio/mp3", "audio/wav", "audio/ogg",
                        "audio/mp4", "audio/x-m4a", "video/mp4"}

FLAG_WEIGHTS = {
    "ip_address_used":             18,
    "subdomain_spoof":             25,
    "homoglyph_attack":            25,
    "suspicious_keyword_bank":     12,
    "suspicious_keyword_login":    12,
    "suspicious_keyword_verify":   12,
    "suspicious_keyword_password": 12,
    "suspicious_keyword_account":  10,
    "suspicious_keyword_update":    8,
    "suspicious_keyword_urgent":   10,
    "suspicious_keyword_free":      6,
    "suspicious_keyword_winner":   10,
    "suspicious_keyword_secure":    6,
    "suspicious_keyword_confirm":   6,
    "excessive_subdomains":        10,
    "very_long_url":                4,
}


# =========================
# RESPONSE HELPERS
# =========================

def success(data):
    return Response(data, status=status.HTTP_200_OK)


def error(message, code=status.HTTP_400_BAD_REQUEST):
    return Response({"error": message}, status=code)


# =========================
# CONTENT CLEANER
# =========================

def clean_scraped_content(text):
    if not text:
        return ""
    text = re.sub(r'\n{3,}', '\n\n', text)
    text = re.sub(r'[ \t]{3,}', ' ', text)
    lines = [l.strip() for l in text.splitlines()
             if l.strip() and (len(l.strip()) >= 20 or any(c.isdigit() for c in l))]
    return "\n".join(lines)[:3000].strip()


# =========================
# CONFIDENCE CALCULATOR
# =========================

def calc_ocr_confidence(char_count):
    if char_count >= 200: return 90
    elif char_count >= 100: return 75
    elif char_count >= 50:  return 55
    elif char_count >= 20:  return 35
    else:                   return 15

def calc_audio_confidence(char_count):
    if char_count >= 200: return 90
    elif char_count >= 100: return 75
    elif char_count >= 50:  return 55
    elif char_count >= 20:  return 40
    else:                   return 20


# =========================
# SYSTEM FLAGS BUILDER
# Transparent list of all signals that triggered the score
# =========================

def build_system_flags(domain_info=None, structure_flags=None,
                        scam_matches=None, red_flags=None,
                        ocr_quality=None, audio_quality=None):
    flags = []

    if domain_info:
        if not domain_info.get("is_https"):
            flags.append("No HTTPS — insecure connection")
        if domain_info.get("suspicious_tld"):
            flags.append("High-risk domain extension (.xyz, .click, etc.)")
        if domain_info.get("trusted_domain"):
            flags.append("Domain is from a known trusted source")
        if domain_info.get("subdomain_spoof"):
            flags.append(f"Subdomain spoof: {domain_info.get('spoof_reason', '')}")
        if domain_info.get("homoglyph_attack"):
            flags.append(f"Lookalike domain: {domain_info.get('homoglyph_reason', '')}")
        age = domain_info.get("domain_age_days")
        if age is not None:
            if age < 90:    flags.append(f"Very new domain ({age} days old)")
            elif age < 365: flags.append(f"Relatively new domain ({age} days old)")

    for flag in (structure_flags or []):
        label = {
            "ip_address_used":      "Raw IP address in URL",
            "very_long_url":        "Unusually long URL",
            "excessive_subdomains": "Excessive subdomains",
            "subdomain_spoof":      "Subdomain impersonation",
            "homoglyph_attack":     "Lookalike characters in domain",
        }.get(flag)
        if label:
            flags.append(label)
        elif flag.startswith("suspicious_keyword_"):
            flags.append(f"Suspicious URL keyword: '{flag.replace('suspicious_keyword_', '')}'")

    for m in (scam_matches or []):
        if m not in flags:
            flags.append(m)

    for rf in (red_flags or []):
        if rf and rf not in flags:
            flags.append(rf)

    if ocr_quality == "very_low":
        flags.append("Very little text extracted — result may be unreliable")
    elif ocr_quality == "low":
        flags.append("Limited text from image — partial analysis")

    if audio_quality == "very_low":
        flags.append("Very little speech detected — result may be unreliable")
    elif audio_quality == "low":
        flags.append("Short transcription — limited analysis")

    return flags


def build_system_reason(domain_info, structure_flags, score):
    parts = []
    if domain_info:
        if not domain_info.get("is_https"):        parts.append("No HTTPS")
        if domain_info.get("suspicious_tld"):       parts.append("High-risk TLD")
        if domain_info.get("trusted_domain"):       parts.append("Trusted source")
        if domain_info.get("subdomain_spoof"):      parts.append(domain_info.get("spoof_reason","Subdomain spoof"))
        if domain_info.get("homoglyph_attack"):     parts.append(domain_info.get("homoglyph_reason","Homoglyph"))
        age = domain_info.get("domain_age_days")
        if age is not None:
            parts.append(f"Domain age: {age} days")
    for f in (structure_flags or []):
        if f == "ip_address_used":      parts.append("Raw IP")
        elif f == "very_long_url":      parts.append("Long URL")
        elif f == "excessive_subdomains": parts.append("Excess subdomains")
        elif f.startswith("suspicious_keyword_"):
            parts.append(f"Keyword: {f.replace('suspicious_keyword_','')}")
    return " | ".join(parts) if parts else "No structural red flags"


# =========================
# MAIN VIEW
# =========================

@api_view(['POST'])
@throttle_classes([AnonRateThrottle])
def analyze_multimodal(request):
    """
    MindShield AI — Multimodal fake/manipulation detector.
    Scoring: adaptive weighted formula across all input types.
    """
    try:
        text  = request.data.get("text")
        url   = request.data.get("url")
        image = request.FILES.get("image")
        audio = request.FILES.get("audio")

        if not any([text, url, image, audio]):
            return error("No input provided. Send text, url, image, or audio.")
        if url and not url.startswith(("http://", "https://")):
            return error("Invalid URL. Must start with http:// or https://")

        # =========================
        # TEXT
        # =========================
        if text:
            content = text.strip()
            if not content:
                return error("Empty text input.")

            pattern_score, scam_matches = detect_scam_patterns(content)
            result = analyze_with_llm(content)

            llm_score = result.get("fake_probability", 0)
            flags_score = min(len(result.get("red_flags", [])) * 10, 30)
            # Text: no OCR penalty — confidence always 100, use_penalty=False
            final_score, breakdown = _score(llm_score, pattern_score, flags_score,
                                            conf=100, use_penalty=False)
            certainty = get_certainty(100, final_score)

            result["input_type"]      = "text"
            result["fake_probability"] = final_score
            result["risk_level"]      = score_to_level(final_score)
            result["certainty"]       = certainty
            result["pattern_score"]   = pattern_score
            result["llm_score"]       = llm_score
            result["score_breakdown"] = breakdown
            result["system_flags"]    = build_system_flags(
                scam_matches=scam_matches,
                red_flags=result.get("red_flags", [])
            )
            return success(result)

        # =========================
        # URL
        # =========================
        elif url:
            url_data        = analyze_url_input(url)
            domain_info     = url_data["domain_info"]
            structure_flags = url_data["structure_flags"]
            content         = clean_scraped_content(url_data["content"])
            title           = url_data["title"]

            if not content:
                content = f"Title: {title}\nDomain: {domain_info.get('domain','')}"

            pattern_score, scam_matches = detect_scam_patterns(content)
            result = analyze_with_llm(content)

            llm_score = result.get("fake_probability", 0)

            # URL rule score from domain signals
            url_rule_score = compute_url_rule_score_from_domain(domain_info, structure_flags, FLAG_WEIGHTS)

            # Trusted domain caps rule score
            if domain_info.get("trusted_domain"):
                url_rule_score = min(url_rule_score, 15)

            final_score, breakdown = _score(llm_score, pattern_score,
                                              url=url_rule_score, conf=100,
                                              is_url=True, use_penalty=False)

            # Trusted domain hard cap
            if domain_info.get("trusted_domain"):
                final_score = min(final_score, 30)

            final_level = score_to_level(final_score)
            certainty   = get_certainty(100, final_score)

            result["input_type"]          = "url"
            result["domain_analysis"]     = domain_info
            result["url_structure_flags"] = structure_flags
            result["extraction_method"]   = url_data["extraction_method"]
            result["extraction_status"]   = url_data["extraction_status"]
            result["llm_score"]           = llm_score
            result["url_rule_score"]      = url_rule_score
            result["pattern_score"]       = pattern_score
            result["fake_probability"]    = final_score
            result["final_risk_score"]    = final_score
            result["final_risk_level"]    = final_level
            result["risk_level"]          = final_level
            result["certainty"]           = certainty
            result["score_breakdown"]     = breakdown
            result["system_reason"]       = build_system_reason(domain_info, structure_flags, final_score)
            result["system_flags"]        = build_system_flags(
                domain_info=domain_info,
                structure_flags=structure_flags,
                scam_matches=scam_matches,
                red_flags=result.get("red_flags", [])
            )
            return success(result)

        # =========================
        # IMAGE (OCR)
        # =========================
        elif image:
            if image.size > MAX_IMAGE_SIZE:
                return error("Image too large. Max 5MB.")
            if hasattr(image, "content_type") and image.content_type not in ALLOWED_IMAGE_TYPES:
                return error("Invalid image type. Allowed: JPEG, PNG, WEBP, GIF.")

            content = extract_text_from_image(image)
            if not content:
                return error("Could not extract text from image.")

            confidence  = calc_ocr_confidence(len(content))
            ocr_quality = "good" if confidence >= 75 else "low" if confidence >= 35 else "very_low"
            certainty   = get_certainty(confidence, 50)

            pattern_score, scam_matches = detect_scam_patterns(content)
            result = analyze_with_llm(content)

            llm_score   = result.get("fake_probability", 0)
            flags_score = min(len(result.get("red_flags", [])) * 10, 30)
            # OCR: apply confidence penalty since input reliability varies
            final_score, breakdown = _score(llm_score, pattern_score, flags_score,
                                            conf=confidence, use_penalty=True)
            certainty = get_certainty(confidence, final_score)

            result["input_type"]      = "image"
            result["extracted_text"]  = content
            result["ocr_char_count"]  = len(content)
            result["ocr_confidence"]  = confidence
            result["ocr_quality"]     = ocr_quality
            result["llm_score"]       = llm_score
            result["pattern_score"]   = pattern_score
            result["fake_probability"]= final_score
            result["risk_level"]      = score_to_level(final_score)
            result["certainty"]       = certainty
            result["score_breakdown"] = breakdown
            result["system_reason"]   = (
                f"OCR quality: {ocr_quality} ({len(content)} chars) | "
                f"Confidence: {confidence}%"
            )
            result["system_flags"]    = build_system_flags(
                scam_matches=scam_matches,
                red_flags=result.get("red_flags", []),
                ocr_quality=ocr_quality
            )
            return success(result)

        # =========================
        # AUDIO (WHISPER)
        # =========================
        elif audio:
            if audio.size > MAX_AUDIO_SIZE:
                return error("Audio too large. Max 20MB.")
            if hasattr(audio, "content_type") and audio.content_type not in ALLOWED_AUDIO_TYPES:
                return error("Invalid audio type. Allowed: MP3, WAV, OGG, M4A.")

            content = transcribe_audio(audio)
            if not content:
                return error("Could not transcribe audio.")

            confidence    = calc_audio_confidence(len(content))
            audio_quality = "good" if confidence >= 75 else "low" if confidence >= 40 else "very_low"

            pattern_score, scam_matches = detect_scam_patterns(content)
            result = analyze_with_llm(content)

            llm_score   = result.get("fake_probability", 0)
            flags_score = min(len(result.get("red_flags", [])) * 10, 30)
            # Audio: apply confidence penalty since transcription quality varies
            final_score, breakdown = _score(llm_score, pattern_score, flags_score,
                                            conf=confidence, use_penalty=True)
            certainty = get_certainty(confidence, final_score)

            result["input_type"]       = "audio"
            result["transcription"]    = content
            result["audio_char_count"] = len(content)
            result["audio_confidence"] = confidence
            result["audio_quality"]    = audio_quality
            result["llm_score"]        = llm_score
            result["pattern_score"]    = pattern_score
            result["fake_probability"] = final_score
            result["risk_level"]       = score_to_level(final_score)
            result["certainty"]        = certainty
            result["score_breakdown"]  = breakdown
            result["system_reason"]    = (
                f"Audio quality: {audio_quality} ({len(content)} chars) | "
                f"Confidence: {confidence}%"
            )
            result["system_flags"]     = build_system_flags(
                scam_matches=scam_matches,
                red_flags=result.get("red_flags", []),
                audio_quality=audio_quality
            )
            return success(result)

    except Exception as e:
        logger.error("Unhandled error in analyze_multimodal", exc_info=True)
        return Response(
            {"error": "Internal server error. Please try again."},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )
