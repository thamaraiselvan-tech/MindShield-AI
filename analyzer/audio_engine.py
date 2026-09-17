import os
import logging
import tempfile

try:
    import whisper
    WHISPER_AVAILABLE = True
except ImportError:
    whisper = None
    WHISPER_AVAILABLE = False

logger = logging.getLogger(__name__)

# =========================
# FFMPEG PATH FIX (Windows)
# =========================
if os.name == "nt":
    ffmpeg_common_paths = [
        # Exact WinGet install path
        r"C:\Users\THAMARAI SELVAN\AppData\Local\Microsoft\WinGet\Packages\Gyan.FFmpeg_Microsoft.Winget.Source_8wekyb3d8bbwe\ffmpeg-8.1-full_build\bin",
        # Common fallback paths
        r"C:\ffmpeg\bin",
        r"C:\Program Files\ffmpeg\bin",
        os.path.join(os.environ.get("USERPROFILE", ""), "ffmpeg", "bin"),
    ]
    current_path = os.environ.get("PATH", "")
    for p in ffmpeg_common_paths:
        if os.path.exists(p) and p not in current_path:
            os.environ["PATH"] = p + os.pathsep + current_path
            print(f"AUDIO: Added ffmpeg to PATH: {p}")

    # Force temp directory to user folder (avoids Windows permission errors)
    _tmp = os.path.join(os.environ.get("USERPROFILE", tempfile.gettempdir()), "AppData", "Local", "Temp")
    os.makedirs(_tmp, exist_ok=True)
    tempfile.tempdir = _tmp

# =========================
# LOAD WHISPER
# =========================
_whisper_model = None
if WHISPER_AVAILABLE:
    try:
        _whisper_model = whisper.load_model("base")
        logger.info("Whisper model loaded.")
    except Exception as e:
        logger.error(f"Whisper model failed to load: {e}")
else:
    logger.warning("Whisper not installed — audio analysis unavailable.")


def _compute_audio_confidence(result):
    """
    Compute audio transcription confidence from Whisper segment data.
    Uses no_speech_prob from each segment — higher no_speech_prob means
    lower quality transcription.

    Also factors in total transcription length as a secondary signal.

    Returns: confidence 0-100
    """
    segments = result.get("segments", [])
    text = result.get("text", "").strip()
    char_count = len(text)

    if not segments or char_count == 0:
        return 10  # Very low confidence — no usable data

    # Primary signal: average no_speech_prob across segments
    no_speech_probs = [s.get("no_speech_prob", 0.5) for s in segments]
    avg_no_speech = sum(no_speech_probs) / len(no_speech_probs)

    # no_speech_prob=0 → high quality speech, no_speech_prob=1 → just noise
    speech_quality = max(0, min(100, round((1.0 - avg_no_speech) * 100)))

    # Secondary signal: transcription length
    if char_count >= 200:
        length_bonus = 10
    elif char_count >= 100:
        length_bonus = 5
    elif char_count >= 50:
        length_bonus = 0
    elif char_count >= 20:
        length_bonus = -10
    else:
        length_bonus = -20

    # Combine: 80% speech quality + 20% length adjustment
    confidence = max(10, min(95, speech_quality + length_bonus))

    logger.info(
        f"Audio confidence: {confidence}% "
        f"(avg_no_speech={avg_no_speech:.2f}, chars={char_count}, "
        f"segments={len(segments)})"
    )
    return confidence


def transcribe_audio(audio_input):
    """
    Transcribe audio to text using Whisper.
    Accepts a Django UploadedFile object or a file path string.

    Returns: (transcription_text, confidence 0-100)
    """
    if _whisper_model is None:
        logger.error("Whisper model not available.")
        return "", 0

    tmp_path = None

    try:
        if hasattr(audio_input, 'read'):
            audio_bytes = audio_input.read()
            suffix = os.path.splitext(getattr(audio_input, 'name', '.mp3'))[-1] or ".mp3"
        elif isinstance(audio_input, str):
            # Already a file path — transcribe directly
            result = _whisper_model.transcribe(audio_input)
            transcription = result["text"].strip()
            confidence = _compute_audio_confidence(result)
            return transcription, confidence
        else:
            logger.error(f"Unsupported audio input type: {type(audio_input)}")
            return "", 0

        # Write to temp file — must close before Whisper opens it (Windows lock fix)
        tmp_dir = tempfile.gettempdir()
        tmp_path = os.path.join(tmp_dir, f"mindshield_audio{suffix}")

        with open(tmp_path, 'wb') as f:
            f.write(audio_bytes)

        logger.info(f"Transcribing audio: {tmp_path} ({os.path.getsize(tmp_path)} bytes)")

        result = _whisper_model.transcribe(tmp_path)
        transcription = result["text"].strip()
        confidence = _compute_audio_confidence(result)

        logger.info(f"Whisper transcribed {len(transcription)} characters (confidence: {confidence}%).")
        return transcription, confidence

    except Exception as e:
        logger.error(f"Audio transcription error: {type(e).__name__}: {e}", exc_info=True)
        return "", 0

    finally:
        # Always clean up temp file
        if tmp_path and os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except Exception:
                pass
