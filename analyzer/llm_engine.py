import os
import json
import re
import logging
import time
import hashlib

try:
    from google import genai as genai_new
    from google.genai import types as genai_types
    GENAI_AVAILABLE = True
    GENAI_V2 = True
except ImportError:
    try:
        import google.generativeai as genai
        GENAI_AVAILABLE = True
        GENAI_V2 = False
    except ImportError:
        genai = None
        genai_new = None
        GENAI_AVAILABLE = False
        GENAI_V2 = False

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

logger = logging.getLogger(__name__)

# =========================
# CONFIG
# =========================
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "").strip()
OLLAMA_URL     = os.getenv("OLLAMA_URL", "http://localhost:11434/api/generate")
OLLAMA_MODEL   = os.getenv("OLLAMA_MODEL", "llama3")
OLLAMA_TIMEOUT = int(os.getenv("OLLAMA_TIMEOUT", "40"))
MAX_RETRIES    = 2

if GEMINI_API_KEY and GENAI_AVAILABLE:
    if not GENAI_V2:
        genai.configure(api_key=GEMINI_API_KEY)
    logger.info("Gemini configured successfully.")

# =========================
# IN-MEMORY CACHE (privacy-safe, no persistence)
# =========================
_cache = {}
MAX_CACHE_SIZE = 100

def _cache_key(text):
    """SHA256 hash for cache key — safer than MD5."""
    return hashlib.sha256(text.encode()).hexdigest()

def _cache_get(text):
    return _cache.get(_cache_key(text))

def _cache_set(text, result):
    global _cache
    if len(_cache) >= MAX_CACHE_SIZE:
        keys = list(_cache.keys())
        for k in keys[:MAX_CACHE_SIZE // 2]:
            del _cache[k]
    _cache[_cache_key(text)] = result

# =========================
# MANIPULATION TAXONOMY
# =========================
MANIPULATION_TACTICS = {
    "Fear & Intimidation": "Threats, consequences, loss aversion to bypass rational thinking",
    "Urgency & Time Pressure": "Artificial deadlines, 'act now' pressure to prevent deliberation",
    "Authority Exploitation": "Impersonation of officials, brands, or experts to build false trust",
    "Social Proof Manipulation": "Fake testimonials, manufactured consensus, bandwagon pressure",
    "Emotional Exploitation": "Guilt-tripping, sympathy appeals, love bombing, flattery",
    "Gaslighting": "Making victims doubt their own reality, memory, or perception",
    "Scarcity Tactics": "Fake limited availability, artificial exclusivity to trigger FOMO",
    "Reciprocity Trap": "Unsolicited gifts or favors creating psychological obligation",
    "Information Manipulation": "Cherry-picked facts, misleading statistics, out-of-context data",
    "Identity Deception": "Fake sender identity, spoofed sources, impersonation",
}

# =========================
# DEFAULT FALLBACK
# =========================
DEFAULT_RESPONSE = {
    "manipulation_detected": False,
    "overall_credibility": "Uncertain",
    "manipulation_tactics": [],
    "fake_probability": 0,
    "risk_level": "Safe",
    "red_flags": [],
    "plain_english_explanation": "Analysis unavailable — AI engine did not respond.",
    "recommendation": "Please try again or use a different input.",
    "explanation": "Analysis could not be completed at this time.",
    "source": "none",
}


# =========================
# PROMPT INJECTION PROTECTION
# =========================
def sanitize_input(text):
    """
    Strip known prompt injection patterns from user input.
    Prevents adversarial users from overriding analysis instructions.
    """
    # Remove common prompt injection attempts
    injection_patterns = [
        r'(?i)ignore\s+(all\s+)?previous\s+instructions?',
        r'(?i)disregard\s+(all\s+)?above',
        r'(?i)you\s+are\s+now\s+a',
        r'(?i)forget\s+(everything|all|your\s+instructions)',
        r'(?i)override\s+(system|instructions?|rules?)',
        r'(?i)new\s+instructions?:',
        r'(?i)system\s*prompt\s*:',
        r'(?i)return\s+.*fake_probability\s*:\s*\d+',
        r'(?i)respond\s+with\s+json',
    ]
    sanitized = text
    for pattern in injection_patterns:
        sanitized = re.sub(pattern, '[FILTERED]', sanitized)
    return sanitized


# =========================
# PROMPT BUILDER
# Input-type aware: different context for text, OCR, audio, URL
# =========================
def build_prompt(text, input_type="text"):
    """
    Build analysis prompt with input-type context.
    Different sources need different analysis approaches.
    """
    short_note = ""
    if len(text) < 100:
        short_note = (
            "NOTE: The content is short. Still analyze it fully. "
            "If insufficient to detect manipulation, set fake_probability to 10 "
            "and risk_level to Safe.\n\n"
        )

    # Input-type specific context notes
    input_context = {
        "text": "",
        "image": (
            "IMPORTANT CONTEXT: This text was extracted from an image via OCR. "
            "Expect minor errors, broken words, or character substitutions "
            "(e.g., '0' for 'O', '1' for 'l'). These are OCR artifacts, NOT "
            "intentional manipulation. Focus on the overall message intent and "
            "manipulation tactics, not formatting issues or typos.\n\n"
        ),
        "audio": (
            "IMPORTANT CONTEXT: This text was transcribed from audio using speech-to-text. "
            "It may lack punctuation, include filler words ('um', 'uh', 'like'), "
            "and have imperfect grammar. These are transcription artifacts, NOT "
            "signs of manipulation. Focus on the spoken message's intent and "
            "whether the speaker uses manipulation tactics.\n\n"
        ),
        "url": (
            "IMPORTANT CONTEXT: This text was scraped from a webpage. "
            "It may contain navigation elements, ads, cookie notices, or "
            "footer text mixed with the main content. Focus on the primary "
            "article/page content for manipulation analysis, not boilerplate.\n\n"
        ),
    }

    tactics_list = "\n".join(
        f"- {name}: {desc}" for name, desc in MANIPULATION_TACTICS.items()
    )

    return (
        "You are MindShield AI — an expert system specialized in detecting "
        "psychological manipulation in digital media.\n\n"
        "YOUR EXPERTISE COVERS THESE MANIPULATION TACTICS:\n"
        f"{tactics_list}\n\n"
        + input_context.get(input_type, "") +
        short_note +
        "ANALYZE the following content for ALL psychological manipulation tactics, "
        "misinformation, scam patterns, and credibility issues.\n\n"
        "CONTENT:\n"
        f"\"{text}\"\n\n"
        "Return ONLY valid JSON (no other text):\n"
        "{\n"
        "  \"manipulation_detected\": <true or false>,\n"
        "  \"overall_credibility\": <\"Authentic\" or \"Suspicious\" or \"Manipulative\" or \"Highly Dangerous\">,\n"
        "  \"fake_probability\": <integer 0-100>,\n"
        "  \"risk_level\": <\"Safe\" or \"Low\" or \"Medium\" or \"High\" or \"Critical\">,\n"
        "  \"manipulation_tactics\": [\n"
        "    {\n"
        "      \"tactic\": \"<exact tactic name from the list above>\",\n"
        "      \"description\": \"<1-2 sentences: HOW this tactic is used in the content>\",\n"
        "      \"severity\": \"<low or medium or high>\",\n"
        "      \"evidence\": \"<exact quote from content that shows this tactic>\"\n"
        "    }\n"
        "  ],\n"
        "  \"red_flags\": <array of specific warning signs found>,\n"
        "  \"plain_english_explanation\": \"<2-4 sentences in simple everyday language explaining WHAT the content is trying to do to the reader and WHY they should be careful. Write as if explaining to a non-technical family member>\",\n"
        "  \"recommendation\": \"<1-2 sentences of specific actionable advice>\",\n"
        "  \"explanation\": \"<detailed technical analysis, minimum 3 sentences>\"\n"
        "}\n\n"
        "RULES:\n"
        "- If manipulation_detected is true, you MUST list at least one tactic\n"
        "- Each tactic MUST have evidence quoted from the content\n"
        "- plain_english_explanation must be understandable by anyone\n"
        "- Be precise: do NOT flag legitimate content as manipulative\n"
        "- For authentic content, set fake_probability below 20 and explain why it is trustworthy"
    )


# =========================
# JSON EXTRACTOR
# =========================
def extract_json(text):
    if not text:
        return None

    text = text.strip()

    try:
        return json.loads(text)
    except Exception:
        pass

    cleaned = re.sub(r"```(?:json)?|```", "", text).strip()
    try:
        return json.loads(cleaned)
    except Exception:
        pass

    match = re.search(r'\{[^{}]*\}', text, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(0))
        except Exception:
            pass

    match = re.search(r'\{.*\}', text, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(0))
        except Exception:
            pass

    logger.warning("Could not extract JSON from LLM response.")
    return None


# =========================
# VALIDATE & NORMALISE
# No artificial score inflation — raw LLM values preserved
# =========================
VALID_CREDIBILITY = {"Authentic", "Suspicious", "Manipulative", "Highly Dangerous", "Uncertain"}
VALID_RISK = {"Safe", "Low", "Medium", "High", "Critical"}

def validate(data):
    """
    Validate and normalize LLM response.
    Preserves raw fake_probability — no artificial inflation.
    Scoring is handled exclusively by compute_score() in scoring_engine.py.
    """
    if not isinstance(data, dict):
        return DEFAULT_RESPONSE.copy()

    out = DEFAULT_RESPONSE.copy()
    out["manipulation_detected"] = bool(data.get("manipulation_detected", False))

    # Overall credibility
    cred = str(data.get("overall_credibility", "Uncertain")).strip()
    out["overall_credibility"] = cred if cred in VALID_CREDIBILITY else "Uncertain"

    # Manipulation tactics (structured field)
    tactics = data.get("manipulation_tactics", [])
    if isinstance(tactics, list):
        valid_tactics = []
        for t in tactics:
            if isinstance(t, dict) and "tactic" in t:
                valid_tactics.append({
                    "tactic": str(t.get("tactic", "")),
                    "description": str(t.get("description", "")),
                    "severity": str(t.get("severity", "medium")).lower(),
                    "evidence": str(t.get("evidence", "")),
                })
        out["manipulation_tactics"] = valid_tactics
    else:
        out["manipulation_tactics"] = []

    # Legacy fields
    mt = data.get("manipulation_type", [])
    out["manipulation_type"] = mt if isinstance(mt, list) else []

    rf = data.get("red_flags", [])
    out["red_flags"] = rf if isinstance(rf, list) else []

    # Fake probability — preserve raw LLM value, just clamp to 0-100
    try:
        out["fake_probability"] = max(0, min(100, int(data.get("fake_probability", 0))))
    except (TypeError, ValueError):
        out["fake_probability"] = 0

    # Risk level
    rl = str(data.get("risk_level", "Safe")).strip()
    out["risk_level"] = rl if rl in VALID_RISK else "Safe"

    # Credibility status (legacy compat)
    cs = str(data.get("credibility_status", "")).strip()
    if cs in ("Real", "Fake", "Uncertain"):
        out["credibility_status"] = cs

    # Explanations
    explanation = str(data.get("explanation", "")).strip()
    out["explanation"] = explanation if len(explanation) > 10 else "No detailed explanation provided."

    plain = str(data.get("plain_english_explanation", "")).strip()
    out["plain_english_explanation"] = plain if len(plain) > 10 else out["explanation"]

    recommendation = str(data.get("recommendation", "")).strip()
    out["recommendation"] = recommendation if len(recommendation) > 5 else "Exercise caution with this content."

    # Preserve metadata
    for key in ("source", "response_time", "cached"):
        if key in data:
            out[key] = data[key]

    # Minimal consistency: if LLM says manipulation_detected but gave 0 probability,
    # set a baseline. This is the ONLY adjustment — no cascading inflation.
    if out["manipulation_detected"] and out["fake_probability"] == 0:
        risk_to_prob = {"Safe": 5, "Low": 20, "Medium": 55, "High": 80, "Critical": 95}
        out["fake_probability"] = risk_to_prob.get(out["risk_level"], 30)

    return out


# =========================
# ENGINE: GEMINI
# =========================
def analyze_with_gemini(prompt):
    if not GEMINI_API_KEY or not GENAI_AVAILABLE:
        return None

    for attempt in range(MAX_RETRIES):
        try:
            start = time.time()

            if GENAI_V2:
                client = genai_new.Client(api_key=GEMINI_API_KEY)
                response = client.models.generate_content(
                    model="gemini-2.0-flash",
                    contents=prompt,
                    config=genai_types.GenerateContentConfig(
                        temperature=0.0,
                        max_output_tokens=1024
                    )
                )
                response_text = response.text
            else:
                model = genai.GenerativeModel("gemini-2.0-flash")
                generation_config = genai.types.GenerationConfig(
                    temperature=0.0,
                    max_output_tokens=1024
                )
                response = model.generate_content(prompt, generation_config=generation_config)
                response_text = response.text

            elapsed = round(time.time() - start, 2)
            parsed = extract_json(response_text)

            if parsed:
                parsed["source"] = "Gemini (gemini-2.0-flash)"
                parsed["response_time"] = elapsed
                logger.info(f"Gemini responded in {elapsed}s (attempt {attempt+1})")
                return parsed

            logger.warning(f"Gemini unparseable response (attempt {attempt+1})")

        except Exception as e:
            logger.error(f"Gemini error (attempt {attempt+1}): {e}")

    return None


# =========================
# ENGINE: OLLAMA
# =========================
def analyze_with_ollama(prompt):
    if not REQUESTS_AVAILABLE:
        return None

    for attempt in range(MAX_RETRIES):
        try:
            start = time.time()
            response = requests.post(
                OLLAMA_URL,
                json={
                    "model": OLLAMA_MODEL,
                    "prompt": prompt,
                    "stream": False,
                    "temperature": 0.0,
                    "options": {"num_predict": 1024, "stop": ["\n\n\n"]}
                },
                timeout=OLLAMA_TIMEOUT
            )
            response.raise_for_status()
            elapsed = round(time.time() - start, 2)
            raw = response.json().get("response", "")

            parsed = extract_json(raw)
            if parsed:
                parsed["source"] = f"Ollama ({OLLAMA_MODEL})"
                parsed["response_time"] = elapsed
                logger.info(f"Ollama responded in {elapsed}s (attempt {attempt+1})")
                return parsed

            logger.warning(f"Ollama unparseable response (attempt {attempt+1})")

        except Exception as e:
            logger.error(f"Ollama error (attempt {attempt+1}): {e}")

    return None


# =========================
# MAIN ENTRY POINT
# =========================
def analyze_with_llm(text, input_type="text"):
    """
    Analyze text for psychological manipulation and misinformation.
    Priority: Cache → Gemini → Ollama → Default fallback
    Privacy: all processing in-memory, nothing persisted.

    Returns raw validated LLM output — scoring is handled by compute_score().
    """
    if not text or not text.strip():
        return {**DEFAULT_RESPONSE, "explanation": "No content provided."}

    text = text.strip()
    was_truncated = len(text) > 4000
    text = text[:4000]

    # Sanitize against prompt injection
    sanitized = sanitize_input(text)

    # 1. Cache check
    cached = _cache_get(sanitized)
    if cached:
        logger.info("Cache hit — returning cached result.")
        return {**cached, "cached": True}

    prompt = build_prompt(sanitized, input_type=input_type)

    # 2. Try Gemini
    result = analyze_with_gemini(prompt)
    if result:
        validated = validate(result)
        if was_truncated:
            validated["truncation_warning"] = (
                "Content was truncated to 4000 characters. "
                "Manipulation patterns beyond that point were not analyzed."
            )
        _cache_set(sanitized, validated)
        return validated

    # 3. Try Ollama
    result = analyze_with_ollama(prompt)
    if result:
        validated = validate(result)
        if was_truncated:
            validated["truncation_warning"] = (
                "Content was truncated to 4000 characters. "
                "Manipulation patterns beyond that point were not analyzed."
            )
        _cache_set(sanitized, validated)
        return validated

    # 4. Short text fallback
    if len(text) < 80:
        logger.warning(f"Short text ({len(text)} chars) — returning low-risk default.")
        return {
            **DEFAULT_RESPONSE,
            "fake_probability": 10,
            "overall_credibility": "Uncertain",
            "risk_level": "Safe",
            "plain_english_explanation": (
                "The content was too short for a thorough analysis. "
                "Please provide more text or a clearer image for accurate results."
            ),
            "recommendation": "Provide more content for a reliable analysis.",
            "explanation": (
                "The extracted content was too short to perform a full manipulation analysis. "
                "Short fragments lack enough context to reliably detect psychological tactics."
            ),
            "source": "fallback — insufficient content"
        }

    # 5. All failed
    logger.error("All LLM engines failed after retries.")
    return {
        **DEFAULT_RESPONSE,
        "plain_english_explanation": (
            "We couldn't complete the analysis right now. "
            "This doesn't mean the content is safe — please try again shortly."
        ),
        "recommendation": "Try again in a moment. If the issue persists, check your connection.",
        "explanation": (
            "Analysis could not be completed. "
            "Locally: ensure Ollama is running with 'ollama serve'. "
            "On Render: set GEMINI_API_KEY in environment variables."
        ),
        "source": "none — all engines failed"
    }
