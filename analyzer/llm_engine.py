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
# CACHE
# =========================
_cache = {}
MAX_CACHE_SIZE = 100

def _cache_key(text):
    return hashlib.md5(text.encode()).hexdigest()

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
# DEFAULT FALLBACK
# =========================
DEFAULT_RESPONSE = {
    "manipulation_detected": False,
    "manipulation_type": [],
    "fake_probability": 0,
    "credibility_status": "Uncertain",
    "risk_level": "Low",
    "explanation": "Analysis unavailable — AI engine did not respond.",
    "source": "none"
}

# =========================
# PROMPT BUILDER
# Structured prompt for consistent JSON output
# =========================
def build_prompt(text):
    short_note = ""
    if len(text) < 100:
        short_note = (
            "NOTE: The content is short. Still analyze it and return JSON. "
            "If there is not enough content to detect manipulation, "
            "set fake_probability to 10 and risk_level to Low.\n\n"
        )

    return (
        "You are MindShield AI — a security analysis system.\n"
        "You MUST respond with ONLY a valid JSON object. No other text.\n\n"
        + short_note +
        "Analyze the following content for:\n"
        "1. Psychological manipulation (fear, urgency, false authority, gaslighting)\n"
        "2. Fake or misleading information (misinformation, propaganda, scams)\n\n"
        "CONTENT:\n"
        f"\"{text}\"\n\n"
        "Return ONLY this JSON with your real analysis values:\n"
        "{\n"
        "  \"manipulation_detected\": <true or false>,\n"
        "  \"manipulation_type\": <array of strings, empty if none>,\n"
        "  \"fake_probability\": <integer 0-100, where 0=real and 100=fake>,\n"
        "  \"credibility_status\": <\"Real\" or \"Fake\" or \"Uncertain\">,\n"
        "  \"risk_level\": <\"Low\" or \"Medium\" or \"High\">,\n"
        "  \"red_flags\": <array of specific red flags found, empty if none>,\n"
        "  \"explanation\": <detailed explanation, minimum 2 sentences>\n"
        "}"
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
# =========================
def validate(data):
    if not isinstance(data, dict):
        return DEFAULT_RESPONSE.copy()

    out = DEFAULT_RESPONSE.copy()
    out["manipulation_detected"] = bool(data.get("manipulation_detected", False))

    mt = data.get("manipulation_type", [])
    out["manipulation_type"] = mt if isinstance(mt, list) else []

    # New: red_flags field
    rf = data.get("red_flags", [])
    out["red_flags"] = rf if isinstance(rf, list) else []

    try:
        out["fake_probability"] = max(0, min(100, int(data.get("fake_probability", 0))))
    except (TypeError, ValueError):
        out["fake_probability"] = 0

    cs = str(data.get("credibility_status", "Uncertain")).strip()
    out["credibility_status"] = cs if cs in ("Real", "Fake", "Uncertain") else "Uncertain"

    rl = str(data.get("risk_level", "Low")).strip()
    out["risk_level"] = rl if rl in ("Low", "Medium", "High") else "Low"

    explanation = str(data.get("explanation", "")).strip()
    out["explanation"] = explanation if len(explanation) > 10 else "No explanation provided."

    for key in ("source", "response_time", "cached"):
        if key in data:
            out[key] = data[key]

    # =========================
    # CONSISTENCY FIX
    # If risk_level=High but fake_probability=0, LLM filled template default
    # Infer fake_probability from risk_level
    # =========================
    risk_to_prob = {"Low": 20, "Medium": 55, "High": 85}
    if out["fake_probability"] == 0 and out["risk_level"] in ("Medium", "High"):
        out["fake_probability"] = risk_to_prob[out["risk_level"]]
    if out["manipulation_detected"] and out["fake_probability"] < 30:
        out["fake_probability"] = max(out["fake_probability"], 40)

    return out

# =========================
# WEIGHTED SCORING
# Combines LLM score with rule signals for final probability
# score = 0.7 * llm_score + 0.3 * rule_signals
# =========================
def weighted_score(llm_fake_prob, manipulation_detected, red_flags_count, risk_level):
    """
    Professional weighted scoring instead of raw LLM output.
    LLM score = 70% weight, rule signals = 30% weight.
    """
    rule_score = 0

    if manipulation_detected:
        rule_score += 40

    rule_score += min(red_flags_count * 10, 30)

    risk_bonus = {"Low": 0, "Medium": 10, "High": 20}
    rule_score += risk_bonus.get(risk_level, 0)

    rule_score = min(rule_score, 100)

    final = round(0.7 * llm_fake_prob + 0.3 * rule_score)
    return max(0, min(100, final))

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
                # New google-genai package
                client = genai_new.Client(api_key=GEMINI_API_KEY)
                response = client.models.generate_content(
                    model="gemini-1.5-flash",
                    contents=prompt,
                    config=genai_types.GenerateContentConfig(
                        temperature=0.1,
                        max_output_tokens=512
                    )
                )
                response_text = response.text
            else:
                # Old google-generativeai package (fallback)
                model = genai.GenerativeModel("gemini-1.5-flash")
                generation_config = genai.types.GenerationConfig(
                    temperature=0.1,
                    max_output_tokens=512
                )
                response = model.generate_content(prompt, generation_config=generation_config)
                response_text = response.text

            elapsed = round(time.time() - start, 2)
            parsed = extract_json(response_text)

            if parsed:
                parsed["source"] = "Gemini (gemini-1.5-flash)"
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
                    "options": {"num_predict": 512, "stop": ["\n\n\n"]}
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
def analyze_with_llm(text):
    """
    Analyze text for manipulation and misinformation.
    Priority: Cache → Gemini → Ollama → Default fallback
    Uses weighted scoring: 70% LLM + 30% rule signals
    """
    if not text or not text.strip():
        return {**DEFAULT_RESPONSE, "explanation": "No content provided."}

    text = text.strip()[:3000]

    # 1. Cache check
    cached = _cache_get(text)
    if cached:
        logger.info("Cache hit — returning cached result.")
        return {**cached, "cached": True}

    prompt = build_prompt(text)

    # 2. Try Gemini
    result = analyze_with_gemini(prompt)
    if result:
        validated = validate(result)
        # Apply weighted scoring
        validated["fake_probability"] = weighted_score(
            validated["fake_probability"],
            validated["manipulation_detected"],
            len(validated.get("red_flags", [])),
            validated["risk_level"]
        )
        _cache_set(text, validated)
        return validated

    # 3. Try Ollama
    result = analyze_with_ollama(prompt)
    if result:
        validated = validate(result)
        validated["fake_probability"] = weighted_score(
            validated["fake_probability"],
            validated["manipulation_detected"],
            len(validated.get("red_flags", [])),
            validated["risk_level"]
        )
        _cache_set(text, validated)
        return validated

    # 4. Short text fallback
    if len(text) < 80:
        logger.warning(f"Short text ({len(text)} chars) — returning low-risk default.")
        return {
            **DEFAULT_RESPONSE,
            "fake_probability": 10,
            "credibility_status": "Uncertain",
            "risk_level": "Low",
            "explanation": (
                "The extracted content was too short to perform a full analysis. "
                "Please provide a clearer image or more text for accurate results."
            ),
            "source": "fallback — insufficient content"
        }

    # 5. All failed
    logger.error("All LLM engines failed after retries.")
    return {
        **DEFAULT_RESPONSE,
        "explanation": (
            "Analysis could not be completed. "
            "Locally: ensure Ollama is running with 'ollama serve'. "
            "On Render: set GEMINI_API_KEY in environment variables."
        ),
        "source": "none — all engines failed"
    }
