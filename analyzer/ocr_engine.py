import os
import io
import re
import logging
import tempfile
import pytesseract
from PIL import Image, ImageEnhance, ImageFilter
import cv2
import numpy as np

logger = logging.getLogger(__name__)

# =========================
# TESSERACT PATH
# Use env var for flexibility — works locally and on Render
# =========================
if os.name == "nt":
    tesseract_path = os.getenv(
        "TESSERACT_PATH",
        r"C:\Users\THAMARAI SELVAN\AppData\Local\Programs\Tesseract-OCR\tesseract.exe"
    )
    pytesseract.pytesseract.tesseract_cmd = tesseract_path

    # Force temp dir to user folder (avoids Windows permission errors)
    _tmp = os.path.join(
        os.environ.get("USERPROFILE", tempfile.gettempdir()),
        "AppData", "Local", "Temp"
    )
    os.makedirs(_tmp, exist_ok=True)
    os.environ["TMPDIR"] = _tmp
    os.environ["TEMP"]   = _tmp
    os.environ["TMP"]    = _tmp
    tempfile.tempdir     = _tmp
# On Linux (Render): tesseract is on PATH automatically


# =========================
# IMAGE QUALITY DETECTION
# =========================

def is_clean_image(img_array):
    """
    Detect if image is a clean poster/ad/screenshot (vs noisy scanned doc).
    Combines std deviation AND edge density for better accuracy.
    High std alone is not enough — noisy scans also have high std.
    """
    gray = cv2.cvtColor(img_array, cv2.COLOR_RGB2GRAY)
    std_dev = np.std(gray)

    # Edge density: clean images have clear, defined edges
    edges = cv2.Canny(gray, 100, 200)
    edge_density = np.mean(edges) / 255.0

    # Clean image = high contrast AND well-defined edges
    return std_dev > 40 and edge_density > 0.05


# =========================
# IMAGE RESIZING
# =========================

def resize_for_ocr(img):
    """
    Resize image to optimal size for OCR.
    - Too small → poor OCR accuracy
    - Too large → slow processing
    Target: longest dimension = 1400px
    """
    max_dim = 1400
    w, h = img.size
    longest = max(w, h)

    if longest < 800:
        # Upscale small images
        scale = 800 / longest
        img = img.resize((int(w * scale), int(h * scale)), Image.LANCZOS)
    elif longest > max_dim:
        # Downscale huge images
        scale = max_dim / longest
        img = img.resize((int(w * scale), int(h * scale)), Image.LANCZOS)

    return img


# =========================
# PREPROCESSING STRATEGIES
# =========================

def preprocess_clean(pil_img):
    """Light preprocessing for posters, ads, screenshots."""
    pil_img = pil_img.convert("L")
    pil_img = ImageEnhance.Contrast(pil_img).enhance(2.0)
    pil_img = ImageEnhance.Sharpness(pil_img).enhance(2.0)
    pil_img = pil_img.filter(ImageFilter.SHARPEN)
    return pil_img


def preprocess_noisy(img_array):
    """Aggressive preprocessing for scanned/photographed documents."""
    gray = cv2.cvtColor(img_array, cv2.COLOR_RGB2GRAY)
    gray = cv2.medianBlur(gray, 3)
    gray = cv2.adaptiveThreshold(
        gray, 255,
        cv2.ADAPTIVE_THRESH_GAUSSIAN_C,
        cv2.THRESH_BINARY, 31, 2
    )
    return Image.fromarray(gray)


# =========================
# CONFIDENCE-BASED TEXT EXTRACTION
# =========================

def extract_with_confidence(processed_img, config):
    """
    Use pytesseract image_to_data to filter low-confidence words.
    Words with confidence < 40 are likely OCR garbage.
    Falls back to image_to_string if data extraction fails.
    """
    try:
        data = pytesseract.image_to_data(
            processed_img,
            config=config,
            lang="eng",
            output_type=pytesseract.Output.DICT
        )

        words = []
        for i, word in enumerate(data["text"]):
            word = word.strip()
            if not word:
                continue
            conf = int(data["conf"][i])
            if conf >= 40:   # only keep confident words
                words.append(word)
            else:
                logger.debug(f"Dropped low-confidence word: '{word}' (conf={conf})")

        return " ".join(words)

    except Exception as e:
        logger.warning(f"Confidence extraction failed, using fallback: {e}")
        return pytesseract.image_to_string(processed_img, config=config, lang="eng")


# =========================
# TEXT CLEANING
# =========================

def clean_ocr_text(text):
    """
    Remove OCR noise that confuses the LLM.
    Conservative cleaning — preserve short but meaningful tokens.
    """
    lines = text.splitlines()
    cleaned = []

    for line in lines:
        stripped = line.strip()

        if not stripped:
            continue

        # Skip lines with NO alphanumeric characters at all
        if not re.search(r'[a-zA-Z0-9₹$€£¥]', stripped):
            continue

        # Skip very short lines that are just punctuation artifacts
        # BUT keep short meaningful tokens like "UPI", "OK", "₹", "ID"
        if len(stripped) <= 2 and not re.search(r'[a-zA-Z0-9]', stripped):
            continue

        # Skip lines of repeated single characters (eee, sss, ---)
        if re.fullmatch(r'(.)\1{2,}', stripped):
            continue

        # Remove trailing garbage symbols
        stripped = re.sub(r'[\s°¢©•]+$', '', stripped).strip()

        if stripped:
            cleaned.append(stripped)

    result = "\n".join(cleaned)
    result = re.sub(r'\n{3,}', '\n\n', result)
    return result.strip()


# =========================
# MAIN OCR FUNCTION
# =========================

def extract_text_from_image(image_file):
    """
    Extract and clean text from uploaded image using Tesseract OCR.
    Features:
    - Smart preprocessing (clean vs noisy image detection)
    - Confidence-based word filtering
    - Auto resize for optimal OCR
    - Second pass fallback if first pass gets little text
    """
    try:
        image_bytes = image_file.read()
        img = Image.open(io.BytesIO(image_bytes))

        # Normalize color mode
        if img.mode == "P":
            img = img.convert("RGBA")
        if img.mode == "RGBA":
            background = Image.new("RGB", img.size, (255, 255, 255))
            background.paste(img, mask=img.split()[3])
            img = background
        elif img.mode != "RGB":
            img = img.convert("RGB")

        # Resize to optimal OCR dimensions
        img = resize_for_ocr(img)

        img_array = np.array(img)
        clean = is_clean_image(img_array)

        if clean:
            processed = preprocess_clean(img)
            config = r"--oem 3 --psm 3"
        else:
            processed = preprocess_noisy(img_array)
            config = r"--oem 3 --psm 6"

        # First pass — confidence filtered
        raw_text = extract_with_confidence(processed, config)
        cleaned_text = clean_ocr_text(raw_text)

        # Second pass — try opposite strategy if first got little text
        if len(cleaned_text) < 50:
            logger.warning(f"First OCR pass got only {len(cleaned_text)} chars, retrying with alternate strategy...")

            if clean:
                processed2 = preprocess_noisy(img_array)
                config2 = r"--oem 3 --psm 6"
            else:
                processed2 = preprocess_clean(img)
                config2 = r"--oem 3 --psm 3"

            raw_text2 = extract_with_confidence(processed2, config2)
            cleaned_text2 = clean_ocr_text(raw_text2)

            if len(cleaned_text2) > len(cleaned_text):
                cleaned_text = cleaned_text2
                logger.info(f"Second OCR pass improved result: {len(cleaned_text)} chars")

        logger.info(f"OCR extracted {len(cleaned_text)} characters after cleaning.")
        return cleaned_text

    except Exception as e:
        logger.error(f"OCR error: {e}", exc_info=True)
        return ""
