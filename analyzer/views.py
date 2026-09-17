"""
MindShield AI — Views
======================
Privacy-first: No data is persisted. All processing is in-memory.
User content is processed once and immediately discarded.

Scoring: All final scores go through compute_score() — single authority.
"""

from rest_framework.decorators import api_view, throttle_classes
from rest_framework.throttling import AnonRateThrottle
from rest_framework.response import Response
from rest_framework import status
from django.shortcuts import render
from django.http import JsonResponse, StreamingHttpResponse
import logging
import re
import json
import asyncio

from .agents import run_multi_agent_pipeline
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
# FRONTEND VIEW
# =========================

def index(request):
    """Serve the MindShield AI frontend."""
    return render(request, "index.html")


def health_check(request):
    """Health check endpoint for deployment monitoring."""
    return JsonResponse({"status": "healthy", "service": "MindShield AI"})


# =========================
# RESPONSE HELPERS
# =========================

def success(data):
    return Response(data, status=status.HTTP_200_OK)


def error(message, code=status.HTTP_400_BAD_REQUEST):
    return Response({"error": message}, status=code)


# =========================
# CONTENT CLEANER
# Less aggressive: keeps shorter lines that may contain manipulation signals
# =========================

def clean_scraped_content(text):
    """
    Clean scraped web content for analysis.
    Less aggressive filtering — preserves short but meaningful lines.
    """
    if not text:
        return ""
    text = re.sub(r'\n{3,}', '\n\n', text)
    text = re.sub(r'[ \t]{3,}', ' ', text)
    lines = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        # Keep lines with at least 5 chars that contain letters
        # (previously required 20 chars — too aggressive)
        if len(stripped) >= 5 and re.search(r'[a-zA-Z]', stripped):
            lines.append(stripped)
        # Also keep short lines with digits (prices, dates, etc.)
        elif any(c.isdigit() for c in stripped) and len(stripped) >= 3:
            lines.append(stripped)
    return "\n".join(lines)[:3000].strip()


# =========================
# CONFIDENCE CALCULATORS
# Used as fallback when real confidence is unavailable
# =========================

def calc_ocr_confidence_fallback(char_count):
    """Fallback confidence based on char count — used when real OCR confidence unavailable."""
    if char_count >= 200: return 85
    elif char_count >= 100: return 70
    elif char_count >= 50:  return 50
    elif char_count >= 20:  return 30
    else:                   return 15

def calc_audio_confidence_fallback(char_count):
    """Fallback confidence based on char count — used when real Whisper confidence unavailable."""
    if char_count >= 200: return 85
    elif char_count >= 100: return 70
    elif char_count >= 50:  return 50
    elif char_count >= 20:  return 35
    else:                   return 15


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
# MERGE PATTERN CATEGORIES WITH LLM TACTICS
# =========================

def merge_tactics(llm_tactics, pattern_categories):
    """
    Merge LLM-detected tactics with pattern-matched categories.
    Avoids duplicates. Adds pattern-only categories if LLM missed them.
    """
    tactics = list(llm_tactics) if llm_tactics else []
    existing_names = {t.get("tactic", "").lower() for t in tactics}

    for category, count in (pattern_categories or {}).items():
        if category.lower() not in existing_names:
            tactics.append({
                "tactic": category,
                "description": f"Pattern-based detection found {count} indicator(s) matching this category.",
                "severity": "medium" if count >= 2 else "low",
                "evidence": "Detected via automated pattern matching",
            })

    return tactics


def generate_offline_fallback(text, input_type, metadata=None):
    """
    Generate a high-fidelity offline fallback result using only regex patterns
    when the Gemini API quota is fully exhausted.
    """
    # Run regex pattern detection
    pattern_score, scam_matches, pattern_cats = detect_scam_patterns(text)
    
    # Use compute_score as single authority (llm_score=0 in offline mode, flags_score boosted)
    flags_score = 15 if pattern_score > 0 else 0
    final_score, _ = compute_score(
        llm_score=0,
        pattern_score=pattern_score,
        flags_score=flags_score,
        confidence=30 if pattern_score > 0 else 100,
        use_conf_penalty=False
    )
    if pattern_score > 0:
        final_score = max(final_score, min(pattern_score + 15, 85))
        
    final_level = score_to_level(final_score)
    
    # Generate generic plain explanations based on detected categories
    detected_list = list(pattern_cats.keys())
    if not detected_list:
        explanation_en = "No suspicious psychological manipulation patterns were detected in the text."
        recommendation_en = "The content appears safe. However, always exercise caution when sharing personal information online."
        explanation_ta = "இந்த உரையில் சந்தேகத்திற்கிடமான எந்தவொரு ஏமாற்று தந்திரங்களும் கண்டறியப்படவில்லை."
        recommendation_ta = "இந்த உள்ளடக்கம் பாதுகாப்பானதாகத் தோன்றுகிறது. இருப்பினும், ஆன்லைனில் தனிப்பட்ட தகவல்களைப் பகிரும்போது எப்போதும் எச்சரிக்கையுடன் செயல்படவும்."
    else:
        explanation_en = f"Offline Analysis: Detected indicators of psychological manipulation ({', '.join(detected_list)}). These patterns are commonly used to bypass logical reasoning and pressure you."
        recommendation_en = "Do not act on the instructions. Verify the sender's identity through official channels and avoid clicking any links."
        explanation_ta = f"ஆஃப்லைன் பகுப்பாய்வு: மனநல கையாளுதல் தந்திரங்கள் கண்டறியப்பட்டுள்ளன ({', '.join(detected_list)}). இவை உங்களை அவசரப்படுத்தவும் ஏமாற்றவும் பயன்படுத்தப்படும் தந்திரங்களாகும்."
        recommendation_ta = "இதன் அடிப்படையில் எந்த நடவடிக்கையும் எடுக்க வேண்டாம். அதிகாரப்பூர்வ வழிகள் மூலம் அனுப்புநரைச் சரிபார்த்து, இணைப்புகளைச் சொடுக்குவதைத் தவிர்க்கவும்."

    # Build tactics list
    tactics = []
    for cat, count in pattern_cats.items():
        tactics.append({
            "tactic": cat,
            "description": f"Offline Engine found {count} indicator(s) matching this category.",
            "severity": "high" if final_score >= 60 else "medium" if final_score >= 35 else "low",
            "evidence": "Detected via local signature matching"
        })

    # Ingestion metadata fallback
    words = text.split()
    tone = "urgent" if "urgent" in text.lower() or "immediately" in text.lower() else "neutral"
    
    # Map pattern categories to 3D dimensions for local scanning
    emotional_score = 0
    deception_score = 0
    coercion_score = 0

    for cat, count in pattern_cats.items():
        weight = min(count * 20, 60) # base weight per category hit
        
        if cat in ["Emotional Exploitation", "Reciprocity Trap"]:
            emotional_score += weight * 1.5
        elif cat in ["Identity Deception", "Information Manipulation", "Social Proof Manipulation"]:
            deception_score += weight * 1.5
        elif cat in ["Fear & Intimidation", "Urgency & Time Pressure"]:
            coercion_score += weight * 1.5
        elif cat == "Gaslighting":
            emotional_score += weight
            coercion_score += weight
        elif cat == "Authority Exploitation":
            deception_score += weight
            coercion_score += weight
        elif cat == "Scarcity Tactics":
            emotional_score += weight
            coercion_score += int(weight * 0.5)

    # Add background contribution from the overall pattern score to smooth out the 3D gauges
    if pattern_score > 0:
        emotional_score = max(emotional_score, int(pattern_score * 0.3))
        deception_score = max(deception_score, int(pattern_score * 0.4))
        coercion_score = max(coercion_score, int(pattern_score * 0.3))

    # Clamp each dimension between 0 and 100
    emotional_score = min(int(emotional_score), 100)
    deception_score = min(int(deception_score), 100)
    coercion_score = min(int(coercion_score), 100)

    breakdown = {
        "llm_score": 0,
        "pattern_score": pattern_score,
        "flags_score": 0,
        "url_rule_score": 0,
        "confidence": 100,
        "conf_penalty": 0,
        "weights": {"offline": 1.0},
        "raw_before_clamp": final_score,
        "emotional_manipulation": emotional_score,
        "deception": deception_score,
        "coercion": coercion_score
    }

    result = {
        "input_type": input_type,
        "manipulation_detected": len(pattern_cats) > 0,
        "overall_credibility": "Authentic" if final_score < 15 else "Suspicious" if final_score < 60 else "Manipulative" if final_score < 80 else "Highly Dangerous",
        "fake_probability": final_score,
        "risk_level": final_level,
        "certainty": "OFFLINE_MODE",
        "manipulation_tactics": tactics,
        "red_flags": detected_list,
        "plain_english_explanation": explanation_en,
        "recommendation": recommendation_en,
        "explanation": "Result generated by the offline rule engine due to temporary cloud AI unavailability.",
        "tamil_explanation": explanation_ta,
        "tamil_recommendation": recommendation_ta,
        "ingestion_metadata": {
            "tone": tone,
            "length": len(words),
            "language": "English",
            "sender_context": "offline scan"
        },
        "score_breakdown": breakdown,
        "source": "MindShield Offline Pattern Engine (Fail-safe Mode)"
    }
    
    if metadata:
        result.update(metadata)
        
    return result


def stream_pipeline(content, input_type, metadata=None, force_offline=False):
    """Run the async generator run_multi_agent_pipeline in a synchronous generator."""
    if force_offline:
        import time
        # Yield simulated timeline steps for local scan
        yield json.dumps({"status": "ingesting", "message": "Offline Mode: Reading text..."}) + "\n"
        time.sleep(0.2)
        yield json.dumps({"status": "ingested", "message": "Offline Mode: Text loaded."}) + "\n"
        time.sleep(0.1)
        yield json.dumps({"status": "detecting", "message": "Offline Mode: Running local pattern matching..."}) + "\n"
        time.sleep(0.2)
        yield json.dumps({"status": "detected", "message": "Offline Mode: Regex matching complete."}) + "\n"
        time.sleep(0.1)
        yield json.dumps({"status": "scoring", "message": "Offline Mode: Scoring threat levels..."}) + "\n"
        time.sleep(0.2)
        yield json.dumps({"status": "scored", "message": "Offline Mode: Risk scoring complete."}) + "\n"
        time.sleep(0.1)
        yield json.dumps({"status": "shielding", "message": "Offline Mode: Formulating recommendations..."}) + "\n"
        time.sleep(0.2)
        yield json.dumps({"status": "shielded", "message": "Offline Mode: Translation complete."}) + "\n"
        time.sleep(0.1)

        fallback_res = generate_offline_fallback(content, input_type, metadata)
        yield json.dumps({
            "status": "complete",
            "result": fallback_res
        }) + "\n"
        return

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    async_gen = run_multi_agent_pipeline(content, input_type=input_type, metadata=metadata)
    
    pipeline_failed = False
    
    try:
        while True:
            try:
                event = loop.run_until_complete(async_gen.__anext__())
                yield json.dumps(event) + "\n"
            except StopAsyncIteration:
                break
    except Exception as e:
        logger.warning(f"Multi-agent pipeline failed (falling back to offline scan): {e}")
        pipeline_failed = True
    finally:
        loop.close()
        
    if pipeline_failed:
        # Yield transition event
        yield json.dumps({
            "status": "shielding",
            "message": "Cloud API unavailable. Switching to Offline Pattern Signature Engine..."
        }) + "\n"
        
        import time
        # Brief pause for visual transition in UI
        time.sleep(1.2)
        
        # Generate offline result
        fallback_res = generate_offline_fallback(content, input_type, metadata)
        
        yield json.dumps({
            "status": "complete",
            "result": fallback_res
        }) + "\n"


# =========================
# MAIN VIEW
# Single scoring authority: compute_score() is the ONLY final scorer.
# =========================

@api_view(['POST'])
@throttle_classes([AnonRateThrottle])
def analyze_multimodal(request):
    """
    MindShield AI — Multimodal psychological manipulation detector.
    Privacy: all input is processed in-memory and never stored.
    """
    try:
        text  = request.data.get("text")
        url   = request.data.get("url")
        image = request.FILES.get("image")
        audio = request.FILES.get("audio")
        offline_mode = request.data.get("offline_mode") == "true" or request.data.get("offline_mode") is True

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
            if len(content) < 5:
                return error("Text too short for analysis. Minimum 5 characters required.")
            if len(content) > 8000:
                return error("Text exceeds maximum limit of 8,000 characters.")

            return StreamingHttpResponse(
                stream_pipeline(content, input_type="text", force_offline=offline_mode),
                content_type="application/x-ndjson"
            )

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

            url_rule_score = compute_url_rule_score_from_domain(domain_info, structure_flags, FLAG_WEIGHTS)
            if domain_info.get("trusted_domain"):
                url_rule_score = min(url_rule_score, 15)

            metadata = {
                "domain_analysis": domain_info,
                "url_structure_flags": structure_flags,
                "extraction_method": url_data["extraction_method"],
                "extraction_status": url_data["extraction_status"],
                "url_rule_score": url_rule_score,
                "system_reason": build_system_reason(domain_info, structure_flags, 0),
            }

            return StreamingHttpResponse(
                stream_pipeline(content, input_type="url", metadata=metadata, force_offline=offline_mode),
                content_type="application/x-ndjson"
            )

        # =========================
        # IMAGE (OCR)
        # =========================
        elif image:
            if image.size > MAX_IMAGE_SIZE:
                return error("Image too large. Max 5MB.")
            if hasattr(image, "content_type") and image.content_type not in ALLOWED_IMAGE_TYPES:
                return error("Invalid image type. Allowed: JPEG, PNG, WEBP, GIF.")

            # extract_text_from_image now returns (text, real_confidence)
            ocr_result = extract_text_from_image(image)

            # Handle both old (string) and new (tuple) return format
            if isinstance(ocr_result, tuple):
                content, real_confidence = ocr_result
            else:
                content = ocr_result
                real_confidence = calc_ocr_confidence_fallback(len(content)) if content else 0

            if not content:
                return error("Could not extract text from image.")

            confidence = real_confidence
            ocr_quality = "good" if confidence >= 75 else "low" if confidence >= 35 else "very_low"

            metadata = {
                "extracted_text": content,
                "ocr_char_count": len(content),
                "ocr_confidence": confidence,
                "ocr_quality": ocr_quality,
                "system_reason": f"OCR quality: {ocr_quality} ({len(content)} chars) | Word confidence: {confidence}%"
            }

            return StreamingHttpResponse(
                stream_pipeline(content, input_type="image", metadata=metadata, force_offline=offline_mode),
                content_type="application/x-ndjson"
            )

        # =========================
        # AUDIO (WHISPER)
        # =========================
        elif audio:
            if audio.size > MAX_AUDIO_SIZE:
                return error("Audio too large. Max 20MB.")
            if hasattr(audio, "content_type") and audio.content_type not in ALLOWED_AUDIO_TYPES:
                return error("Invalid audio type. Allowed: MP3, WAV, OGG, M4A.")

            # transcribe_audio now returns (text, real_confidence)
            audio_result = transcribe_audio(audio)

            # Handle both old (string) and new (tuple) return format
            if isinstance(audio_result, tuple):
                content, real_confidence = audio_result
            else:
                content = audio_result
                real_confidence = calc_audio_confidence_fallback(len(content)) if content else 0

            if not content:
                return error("Could not transcribe audio.")

            confidence    = real_confidence
            audio_quality = "good" if confidence >= 75 else "low" if confidence >= 40 else "very_low"

            metadata = {
                "transcription": content,
                "audio_char_count": len(content),
                "audio_confidence": confidence,
                "audio_quality": audio_quality,
                "system_reason": f"Audio quality: {audio_quality} ({len(content)} chars) | Speech confidence: {confidence}%"
            }

            return StreamingHttpResponse(
                stream_pipeline(content, input_type="audio", metadata=metadata, force_offline=offline_mode),
                content_type="application/x-ndjson"
            )

    except Exception as e:
        logger.error("Unhandled error in analyze_multimodal", exc_info=True)
        return Response(
            {"error": "Internal server error. Please try again."},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )
