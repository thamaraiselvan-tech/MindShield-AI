import os
import json
import logging
import asyncio
import copy
import uuid
from dotenv import load_dotenv
from google.adk import Agent
from google.adk.runners import InMemoryRunner
from google.genai import types

logger = logging.getLogger(__name__)

# Ensure env variables are loaded (useful if running independently)
load_dotenv(os.path.join(os.path.dirname(os.path.dirname(__file__)), ".env"))

# Check for API key
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "").strip()

# =====================================================================
# AGENT DEFINITIONS
# =====================================================================

# Model to use
MODELS_POOL = ["gemini-2.5-flash-lite", "gemini-2.5-flash", "gemini-2.0-flash", "gemini-1.5-flash"]
CURRENT_MODEL = "gemini-2.5-flash-lite"
MODEL_NAME = CURRENT_MODEL

# Agent 1 — Ingestion Agent
# Cleans, chunks, and structures input, extracting metadata
ingestion_agent = Agent(
    name="ingestion_agent",
    model=MODEL_NAME,
    instruction=(
        "You are the MindShield Ingestion Agent. Your task is to analyze raw text input, "
        "clean it of unnecessary spacing or artifacts, and extract metadata.\n\n"
        "Metadata to extract:\n"
        "- tone: Tone of the message (e.g., urgent, friendly, defensive, informative, aggressive)\n"
        "- length: Word count of the text\n"
        "- language: The primary language of the text (e.g., English, Tamil, Hindi, Hinglish)\n"
        "- sender_context: The inferred sender context or source (e.g., bank alert, family message, unknown support, spam ad)\n\n"
        "Return the output STRICTLY as a JSON object with these exact keys:\n"
        "{\n"
        "  \"cleaned_text\": \"<cleaned version of the input text>\",\n"
        "  \"tone\": \"<tone of the text>\",\n"
        "  \"length\": <integer word count>,\n"
        "  \"language\": \"<language name>\",\n"
        "  \"sender_context\": \"<sender context details>\"\n"
        "}\n\n"
        "Do not wrap your output in markdown. Just return raw JSON."
    )
)

# Agent 2 — Pattern Detection Agent
# Analyzes text for specific psychological manipulation tactics
pattern_detection_agent = Agent(
    name="pattern_detection_agent",
    model=MODEL_NAME,
    instruction=(
        "You are the MindShield Pattern Detection Agent. Your task is to analyze text for psychological manipulation tactics.\n\n"
        "Tactics to look for:\n"
        "1. Gaslighting: Making the victim doubt their own memory, perception, sanity, or reality.\n"
        "2. Fear/Urgency: Threatening consequences, account closure, legal action, or using artificial deadlines to force action.\n"
        "3. False Authority: Impersonating official entities, brands, government bodies, or experts.\n"
        "4. Guilt-Tripping & Emotional Exploitation: Appealing to pity, family duties, love bombing, or building emotional debt.\n"
        "5. Love Bombing & Isolation: Showering with false affection or trying to isolate the user from others.\n"
        "6. Phishing/Social Engineering: Deceptive requests for credentials, money transfers, or scanning QR codes.\n\n"
        "Return the output STRICTLY as a JSON object with these exact keys:\n"
        "{\n"
        "  \"manipulation_detected\": <true or false>,\n"
        "  \"detected_patterns\": [\n"
        "    {\n"
        "      \"tactic\": \"<Gaslighting | Fear/Urgency | False Authority | Guilt-Tripping | Love Bombing | Phishing>\",\n"
        "      \"description\": \"<1-2 sentences: how this tactic is applied in the text>\",\n"
        "      \"severity\": \"<low | medium | high>\",\n"
        "      \"evidence\": \"<exact quote from the input text showing this tactic>\"\n"
        "    }\n"
        "  ]\n"
        "}\n\n"
        "If no manipulation is detected, set manipulation_detected to false and leave detected_patterns empty.\n"
        "Do not wrap your output in markdown. Just return raw JSON."
    )
)

# Agent 3 — Risk Scoring Agent
# Takes pattern detection output and assigns multi-dimensional risk scores
risk_scoring_agent = Agent(
    name="risk_scoring_agent",
    model=MODEL_NAME,
    instruction=(
        "You are the MindShield Risk Scoring Agent. Your task is to assign severity risk scores (0-100) across 3 dimensions "
        "based on the patterns detected by the Pattern Detection Agent:\n\n"
        "Dimensions:\n"
        "1. Emotional Manipulation: Guilt-tripping, love bombing, pity appeals, fear triggers.\n"
        "2. Deception: Fake identities, brand impersonation, false authority, lies.\n"
        "3. Coercion: Demands, urgent action warnings, pressure, gaslighting.\n\n"
        "Formulate a detailed risk report. Calculate an overall risk score from 0-100. "
        "Assign a risk level: Safe (0-14), Low (15-34), Medium (35-59), High (60-79), Critical (80-100).\n\n"
        "Return the output STRICTLY as a JSON object with these exact keys:\n"
        "{\n"
        "  \"scores\": {\n"
        "    \"emotional_manipulation\": <integer 0-100>,\n"
        "    \"deception\": <integer 0-100>,\n"
        "    \"coercion\": <integer 0-100>\n"
        "  },\n"
        "  \"overall_risk_score\": <integer 0-100>,\n"
        "  \"risk_level\": \"<Safe | Low | Medium | High | Critical>\",\n"
        "  \"rationale\": \"<1-2 sentences explaining why the scores were assigned>\"\n"
        "}\n\n"
        "Do not wrap your output in markdown. Just return raw JSON."
    )
)

# Agent 4 — Explanation & Shield Agent
# Generates plain-language explanations and suggestions in English and Tamil
explanation_shield_agent = Agent(
    name="explanation_shield_agent",
    model=MODEL_NAME,
    instruction=(
        "You are the MindShield Explanation and Shield Agent. Your task is to explain the detected manipulation tactics "
        "and provide protective guidelines on how the user should shield themselves.\n\n"
        "You must output this in BOTH English and Tamil (using Gemini's multilingual capabilities). Make the translation "
        "highly natural, accurate, and easy to understand for laypeople.\n\n"
        "Return the output STRICTLY as a JSON object with these exact keys:\n"
        "{\n"
        "  \"english\": {\n"
        "    \"explanation\": \"<2-3 sentences explaining in simple terms what the message is trying to do and why it is manipulative>\",\n"
        "    \"shield_advice\": \"<1-2 sentences of actionable protective advice on what to do or not do>\"\n"
        "  },\n"
        "  \"tamil\": {\n"
        "    \"explanation\": \"<Tamil translation: simple explanation of manipulation>\",\n"
        "    \"shield_advice\": \"<Tamil translation: protective advice>\"\n"
        "  }\n"
        "}\n\n"
        "Do not wrap your output in markdown. Just return raw JSON."
    )
)


# =====================================================================
# RUNNER UTILITIES
# =====================================================================

async def run_single_agent(agent: Agent, prompt: str, user_id: str = None) -> str:
    """Helper to run a single agent with a prompt using InMemoryRunner with automatic rate-limit fallback."""
    global CURRENT_MODEL
    if not user_id:
        user_id = f"user_{uuid.uuid4().hex[:12]}"
        
    max_retries = 6
    
    # Create local agent copy to prevent module-level singleton state mutation across requests
    local_agent = copy.copy(agent)
    
    for attempt in range(max_retries):
        local_agent.model = CURRENT_MODEL
        try:
            runner = InMemoryRunner(agent=local_agent)
            session = await runner.session_service.create_session(app_name=runner.app_name, user_id=user_id)
            
            new_message = types.Content(
                role="user",
                parts=[types.Part.from_text(text=prompt)]
            )
            
            chunks = []
            async for event in runner.run_async(user_id=user_id, session_id=session.id, new_message=new_message):
                if event.content and event.content.parts:
                    for part in event.content.parts:
                        if part.text:
                            chunks.append(part.text)
                            
            return "".join(chunks).strip()
        except Exception as e:
            err_str = str(e)
            err_str_lower = err_str.lower()
            is_transient = any(
                term in err_str_lower or term in err_str
                for term in ["429", "503", "500", "quota", "resource_exhausted", "unavailable", "temporary", "high demand", "internal"]
            )
            if is_transient:
                # Rotate model
                try:
                    curr_idx = MODELS_POOL.index(CURRENT_MODEL)
                    next_idx = (curr_idx + 1) % len(MODELS_POOL)
                    CURRENT_MODEL = MODELS_POOL[next_idx]
                except ValueError:
                    CURRENT_MODEL = MODELS_POOL[0]
                
                logger.warning(
                    f"Transient API error / Quota hit on agent {agent.name}. "
                    f"Rotating global model to fallback: {CURRENT_MODEL}. Error: {e}"
                )
                await asyncio.sleep(1.5)
            else:
                logger.error(f"Error executing agent {agent.name}: {e}")
                raise e
    raise Exception(f"Failed to execute agent {agent.name} after {max_retries} attempts.")


def clean_json_string(text: str) -> str:
    """Strip markdown code blocks if the model wrapped the output in them."""
    if not text:
        return ""
    text = text.strip()
    if text.startswith("```"):
        # Strip start
        text = text.split("```", 1)[1]
        # Strip language label (e.g. json) if present
        if text.lower().startswith("json"):
            text = text[4:].strip()
        # Strip end
        if "```" in text:
            text = text.rsplit("```", 1)[0].strip()
    return text


def parse_agent_json(text: str, fallback_dict: dict) -> dict:
    """Attempt to parse the agent's response into JSON with a fallback."""
    cleaned = clean_json_string(text)
    try:
        return json.loads(cleaned)
    except Exception as e:
        logger.error(f"Failed to parse agent JSON. Text: {repr(cleaned)}. Error: {e}")
        # Try finding json bracket matching
        import re
        match = re.search(r"\{.*\}", cleaned, re.DOTALL)
        if match:
            try:
                return json.loads(match.group(0))
            except Exception:
                pass
        return fallback_dict


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


# =====================================================================
# PIPELINE ORCHESTRATOR (Asynchronous Generator)
# =====================================================================

async def run_multi_agent_pipeline(text: str, input_type: str = "text", metadata: dict = None, user_id: str = None):
    """
    Runs the raw text through the 4 specialized agents sequentially,
    yielding progress update dicts as each agent executes.
    """
    if not user_id:
        user_id = f"session_{uuid.uuid4().hex[:12]}"
    logger.info(f"Starting Multi-Agent MindShield Pipeline for user_id={user_id}.")
    
    # Bound prompt text length to prevent excessive token usage
    text_bounded = text[:6000] if text else ""
    
    # -------------------------------------------------------------
    # STEP 1: Ingestion Agent
    # -------------------------------------------------------------
    yield {
        "status": "ingesting",
        "message": "Agent 1: Ingestion Agent is cleaning text and extracting metadata..."
    }
    
    ingestion_prompt = f"Analyze and structure this input text:\n\n{text_bounded}"
    raw_ingestion_res = await run_single_agent(ingestion_agent, ingestion_prompt, user_id)
    ingestion_data = parse_agent_json(raw_ingestion_res, {
        "cleaned_text": text,
        "tone": "unknown",
        "length": len(text.split()),
        "language": "unknown",
        "sender_context": "unknown"
    })
    
    cleaned_text = ingestion_data.get("cleaned_text", text)
    yield {
        "status": "ingested",
        "message": f"Ingestion Complete. Language: {ingestion_data.get('language')}, Tone: {ingestion_data.get('tone')}.",
        "data": ingestion_data
    }
    await asyncio.sleep(0.3)  # brief beat for UI animation pacing
    
    # -------------------------------------------------------------
    # STEP 2: Pattern Detection Agent
    # -------------------------------------------------------------
    yield {
        "status": "detecting",
        "message": "Agent 2: Pattern Detection Agent is scanning for gaslighting, fear, urgency, and false authority..."
    }
    
    detection_prompt = f"Analyze this text for psychological manipulation patterns:\n\n{cleaned_text}"
    raw_detection_res = await run_single_agent(pattern_detection_agent, detection_prompt, user_id)
    detection_data = parse_agent_json(raw_detection_res, {
        "manipulation_detected": False,
        "detected_patterns": []
    })
    
    yield {
        "status": "detected",
        "message": f"Detection Complete. Found {len(detection_data.get('detected_patterns', []))} pattern(s).",
        "data": detection_data
    }
    await asyncio.sleep(0.3)
    
    # -------------------------------------------------------------
    # STEP 3: Risk Scoring Agent
    # -------------------------------------------------------------
    yield {
        "status": "scoring",
        "message": "Agent 3: Risk Scoring Agent is calculating severity dimensions and overall threat levels..."
    }
    
    scoring_prompt = (
        f"Input Text:\n\"{cleaned_text}\"\n\n"
        f"Detected Patterns:\n{json.dumps(detection_data.get('detected_patterns', []))}\n\n"
        f"Calculate severity scores and overall risk level."
    )
    raw_scoring_res = await run_single_agent(risk_scoring_agent, scoring_prompt, user_id)
    scoring_data = parse_agent_json(raw_scoring_res, {
        "scores": {"emotional_manipulation": 0, "deception": 0, "coercion": 0},
        "overall_risk_score": 0,
        "risk_level": "Safe",
        "rationale": "Fallback calculation due to engine failure."
    })
    
    yield {
        "status": "scored",
        "message": f"Scoring Complete. Risk Level: {scoring_data.get('risk_level')} ({scoring_data.get('overall_risk_score')}/100).",
        "data": scoring_data
    }
    await asyncio.sleep(0.3)
    
    # -------------------------------------------------------------
    # STEP 4: Explanation & Shield Agent
    # -------------------------------------------------------------
    yield {
        "status": "shielding",
        "message": "Agent 4: Explanation & Shield Agent is translating findings and formulating safety recommendations in English & Tamil..."
    }
    
    shield_prompt = (
        f"Analysis Summary:\n"
        f"- Risk Level: {scoring_data.get('risk_level')}\n"
        f"- Overall Score: {scoring_data.get('overall_risk_score')}\n"
        f"- Detected Patterns: {json.dumps(detection_data.get('detected_patterns', []))}\n\n"
        f"Generate a plain-language explanation and protective guide in both English and Tamil."
    )
    raw_shield_res = await run_single_agent(explanation_shield_agent, shield_prompt, user_id)
    shield_data = parse_agent_json(raw_shield_res, {
        "english": {"explanation": "Analysis complete.", "shield_advice": "Exercise caution."},
        "tamil": {"explanation": "ஆய்வு நிறைவடைந்தது.", "shield_advice": "எச்சரிக்கையுடன் செயல்படவும்."}
    })
    
    yield {
        "status": "shielded",
        "message": "Shielding Complete. Translating content output successfully.",
        "data": shield_data
    }
    await asyncio.sleep(0.1)
    
    # -------------------------------------------------------------
    # STEP 5: Final Result Merge
    # -------------------------------------------------------------
    # Format according to the expected response keys for backward compatibility
    # Ensure all final scores go through compute_score() — single authority.
    from .scoring_engine import detect_scam_patterns, compute_score, score_to_level, get_certainty
    
    # Calculate pattern score using single authority rules
    pattern_score, scam_matches, pattern_cats = detect_scam_patterns(cleaned_text)
    
    confidence = 100
    is_url = (input_type == "url")
    use_penalty = True
    
    if metadata:
        if "ocr_confidence" in metadata:
            confidence = metadata["ocr_confidence"]
        elif "audio_confidence" in metadata:
            confidence = metadata["audio_confidence"]
            
        if input_type == "text":
            use_penalty = False
            
    llm_score = scoring_data.get("overall_risk_score", 0)
    flags_score = min(len(detection_data.get("detected_patterns", [])) * 10, 30)
    
    url_rule_score = 0
    if is_url and metadata:
        url_rule_score = metadata.get("url_rule_score", 0)
        
    final_score, breakdown = compute_score(
        llm_score=llm_score,
        pattern_score=pattern_score,
        flags_score=flags_score,
        url_rule_score=url_rule_score,
        confidence=confidence,
        is_url=is_url,
        use_conf_penalty=use_penalty
    )
    
    # Inject 3D risk dimensions into the score breakdown so the frontend can render them
    llm_scores = scoring_data.get("scores", {}) or {}
    breakdown["emotional_manipulation"] = llm_scores.get("emotional_manipulation", 0)
    breakdown["deception"] = llm_scores.get("deception", 0)
    breakdown["coercion"] = llm_scores.get("coercion", 0)
    
    if is_url and metadata:
        domain_info = metadata.get("domain_analysis", {})
        if domain_info.get("trusted_domain"):
            final_score = int(final_score * 0.6)
            
    final_level = score_to_level(final_score)
    certainty = get_certainty(confidence, final_score)
    
    # Merge tactics using local helper (prevents Django import errors)
    merged_tactics = merge_tactics(
        [
            {
                "tactic": p.get("tactic", "Unknown"),
                "description": p.get("description", ""),
                "severity": p.get("severity", "medium").lower(),
                "evidence": p.get("evidence", "")
            }
            for p in detection_data.get("detected_patterns", [])
        ],
        pattern_cats
    )
    
    final_output = {
        "input_type": input_type,
        "manipulation_detected": detection_data.get("manipulation_detected", False) or len(merged_tactics) > 0,
        "overall_credibility": "Authentic" if final_score < 15 else "Suspicious" if final_score < 60 else "Manipulative" if final_score < 80 else "Highly Dangerous",
        "fake_probability": final_score,
        "risk_level": final_level,
        "certainty": certainty,
        "manipulation_tactics": merged_tactics,
        "red_flags": [t.get("tactic") for t in merged_tactics],
        "plain_english_explanation": shield_data.get("english", {}).get("explanation", ""),
        "recommendation": shield_data.get("english", {}).get("shield_advice", ""),
        "explanation": scoring_data.get("rationale", ""),
        
        # Multilingual specific outputs
        "tamil_explanation": shield_data.get("tamil", {}).get("explanation", ""),
        "tamil_recommendation": shield_data.get("tamil", {}).get("shield_advice", ""),
        
        # Details & Metadata
        "ingestion_metadata": {
            "tone": ingestion_data.get("tone"),
            "length": ingestion_data.get("length"),
            "language": ingestion_data.get("language"),
            "sender_context": ingestion_data.get("sender_context")
        },
        "score_breakdown": breakdown,
        "source": f"Multi-Agent Team ({MODEL_NAME})"
    }
    
    # Merge additional metadata (e.g. ocr_confidence, transcription, domain_analysis, etc.)
    if metadata:
        final_output.update(metadata)
        
    yield {
        "status": "complete",
        "result": final_output
    }
