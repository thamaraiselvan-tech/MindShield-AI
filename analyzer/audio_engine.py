import os
import logging
import tempfile
import whisper

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
try:
    _whisper_model = whisper.load_model("base")
    logger.info("Whisper model loaded.")
except Exception as e:
    _whisper_model = None
    logger.error(f"Whisper model failed to load: {e}")


def transcribe_audio(audio_input):
    """
    Transcribe audio to text using Whisper.
    Accepts a Django UploadedFile object or a file path string.
    """
    if _whisper_model is None:
        logger.error("Whisper model not available.")
        return ""

    tmp_path = None

    try:
        if hasattr(audio_input, 'read'):
            audio_bytes = audio_input.read()
            suffix = os.path.splitext(getattr(audio_input, 'name', '.mp3'))[-1] or ".mp3"
        elif isinstance(audio_input, str):
            # Already a file path — transcribe directly
            result = _whisper_model.transcribe(audio_input)
            return result["text"].strip()
        else:
            logger.error(f"Unsupported audio input type: {type(audio_input)}")
            return ""

        # Write to temp file — must close before Whisper opens it (Windows lock fix)
        tmp_dir = tempfile.gettempdir()
        tmp_path = os.path.join(tmp_dir, f"mindshield_audio{suffix}")

        with open(tmp_path, 'wb') as f:
            f.write(audio_bytes)

        logger.info(f"Transcribing audio: {tmp_path} ({os.path.getsize(tmp_path)} bytes)")

        result = _whisper_model.transcribe(tmp_path)
        transcription = result["text"].strip()

        logger.info(f"Whisper transcribed {len(transcription)} characters.")
        return transcription

    except Exception as e:
        logger.error(f"Audio transcription error: {type(e).__name__}: {e}", exc_info=True)
        return ""

    finally:
        # Always clean up temp file
        if tmp_path and os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except Exception:
                pass
