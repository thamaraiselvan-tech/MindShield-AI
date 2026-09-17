import requests
import logging
from bs4 import BeautifulSoup
from urllib.parse import urlparse
import whois
from datetime import datetime
from newspaper import Article
import re
import unicodedata

logger = logging.getLogger(__name__)

# =========================
# TRUSTED DOMAINS
# Specific domains only — no bare TLDs to prevent over-trusting
# =========================
trusted_domains = [
    # International news
    "bbc.com", "reuters.com", "nytimes.com", "theguardian.com",
    "apnews.com", "npr.org",
    # Indian news
    "thehindu.com", "ndtv.com",
    "timesofindia.com", "hindustantimes.com", "indianexpress.com",
    # Health/Science
    "who.int", "nature.com", "pubmed.ncbi.nlm.nih.gov",
    "cdc.gov", "nih.gov", "mayoclinic.org",
    # Reference
    "wikipedia.org", "britannica.com",
    # Indian government (specific domains only)
    "india.gov.in", "mygov.in", "pib.gov.in",
    "incometax.gov.in", "rbi.org.in",
    # E-commerce
    "amazon.com", "amazon.in", "flipkart.com",
    # Tech platforms
    "youtube.com", "google.com", "microsoft.com",
    "apple.com", "github.com", "linkedin.com",
    # Indian education (specific institutions)
    "swayam.gov.in", "ugc.ac.in",
    "iitm.ac.in", "iitb.ac.in", "iitd.ac.in",
    "iisc.ac.in", "nitt.edu",
]

suspicious_tlds = [
    ".xyz", ".click", ".top", ".buzz",
    ".info", ".online", ".site", ".tk",
    ".ml", ".ga", ".cf", ".gq"
]

# =========================
# HOMOGLYPH MAP — Extended with Cyrillic/Unicode lookalikes
# Detects visually similar fake domains (g00gle, paypa1, gооgle with Cyrillic о)
# =========================
HOMOGLYPHS = {
    # ASCII number substitutions
    "0": "o", "1": "l", "3": "e", "4": "a",
    "5": "s", "6": "g", "7": "t", "8": "b",
    "@": "a", "!": "i", "$": "s",
    # Multi-char
    "vv": "w", "rn": "m",
}

# Cyrillic → Latin mappings (used after NFKD normalization fails)
CYRILLIC_MAP = {
    '\u0430': 'a',  # Cyrillic а
    '\u0435': 'e',  # Cyrillic е
    '\u043e': 'o',  # Cyrillic о
    '\u0440': 'p',  # Cyrillic р
    '\u0441': 'c',  # Cyrillic с
    '\u0443': 'y',  # Cyrillic у
    '\u0445': 'x',  # Cyrillic х
    '\u0456': 'i',  # Ukrainian і
    '\u0455': 's',  # Cyrillic ѕ
    '\u0458': 'j',  # Cyrillic ј
    '\u04bb': 'h',  # Cyrillic һ
    '\u0131': 'i',  # Turkish dotless ı
    '\u2113': 'l',  # Script small l (ℓ)
}

# Known brands that attackers impersonate
KNOWN_BRANDS = [
    "google", "facebook", "paypal", "amazon", "apple",
    "microsoft", "netflix", "instagram", "whatsapp",
    "hdfc", "sbi", "icici", "axis", "paytm",
    "flipkart", "swiggy", "zomato", "ola", "uber",
    "phonepe", "gpay", "razorpay", "cred",
    "twitter", "telegram", "discord", "linkedin",
]


def normalize_domain(domain):
    """
    Normalize unicode and homoglyphs for spoof detection.
    Extended: handles Cyrillic, Unicode NFKD, and punycode.
    """
    # Decode punycode (xn--) domains
    try:
        parts = domain.split(".")
        decoded_parts = []
        for part in parts:
            if part.startswith("xn--"):
                decoded_parts.append(part.encode("ascii").decode("idna"))
            else:
                decoded_parts.append(part)
        domain = ".".join(decoded_parts)
    except Exception:
        pass

    # Apply Cyrillic → Latin mapping first (before NFKD strips them)
    mapped = []
    for char in domain.lower():
        mapped.append(CYRILLIC_MAP.get(char, char))
    domain = "".join(mapped)

    # Unicode NFKD normalization
    try:
        domain = unicodedata.normalize("NFKD", domain)
        domain = domain.encode("ascii", "ignore").decode("ascii")
    except Exception:
        pass

    normalized = domain.lower()

    # Apply ASCII homoglyph substitutions
    for fake, real in HOMOGLYPHS.items():
        normalized = normalized.replace(fake, real)

    return normalized


def detect_subdomain_spoof(domain):
    """
    Detect subdomain tricks like paypal.secure-login.xyz
    where the trusted brand is in subdomain but real domain is malicious.
    """
    parts = domain.split(".")
    if len(parts) < 3:
        return False, None

    # Check if a known brand appears in subdomain but base domain is different
    subdomains = ".".join(parts[:-2])
    base = ".".join(parts[-2:])

    for brand in KNOWN_BRANDS:
        if brand in subdomains and brand not in base:
            return True, f"Brand '{brand}' used in subdomain to spoof trusted site"

    return False, None


def detect_homoglyph_attack(domain):
    """
    Detect g00gle.com, paypa1.com, gооgle.com (Cyrillic) style attacks.
    Fixed logic: properly detects when normalized domain matches a brand
    but the original domain doesn't exactly match the brand.
    """
    original_lower = domain.lower()
    normalized = normalize_domain(domain)

    # Extract the main domain part (without TLD)
    original_base = original_lower.split(".")[0]
    normalized_base = normalized.split(".")[0]

    for brand in KNOWN_BRANDS:
        # Case 1: Normalized version matches the brand, but original doesn't
        # This catches g00gle → google, paypa1 → paypal, Cyrillic spoofs
        if brand == normalized_base and brand != original_base:
            return True, f"Domain impersonates '{brand}' using lookalike characters"

        # Case 2: Normalized version contains the brand as substring
        # but original doesn't contain it exactly (partial match)
        if brand in normalized_base and brand not in original_base:
            return True, f"Domain may be impersonating '{brand}'"

        # Case 3: Brand in domain but domain has extra suspicious chars
        # e.g., google-secure.com, paypal-verify.com
        if brand in original_base and original_base != brand:
            # Check if it's brand + suspicious suffix
            remainder = original_base.replace(brand, "")
            suspicious_suffixes = [
                "secure", "verify", "login", "update", "alert",
                "support", "help", "service", "account", "confirm",
            ]
            for suffix in suspicious_suffixes:
                if suffix in remainder:
                    return True, f"Domain mimics '{brand}' with deceptive suffix"

    return False, None


def extract_with_newspaper(url):
    try:
        article = Article(url)
        article.download()
        article.parse()
        return article.text.strip(), article.title
    except Exception:
        return "", ""


def extract_with_requests(url):
    try:
        response = requests.get(url, timeout=10, headers={"User-Agent": "Mozilla/5.0"})
        soup = BeautifulSoup(response.text, "html.parser")
        for tag in soup(["script", "style", "nav", "footer", "header"]):
            tag.extract()
        text = soup.get_text(separator=" ").strip()
        title = soup.title.string if soup.title else ""
        return text, title
    except Exception:
        return "", ""


def extract_text_from_url(url):
    try:
        text, title = extract_with_newspaper(url)
        if len(text) > 500:
            return text, title, "newspaper"
        text, title = extract_with_requests(url)
        if len(text) > 200:
            return text, title, "requests"
        return "", title, "title_only"
    except Exception:
        return "", "", "extraction_failed"


def extract_domain_info(url):
    parsed = urlparse(url)
    domain = parsed.netloc.replace("www.", "")
    is_https = parsed.scheme == "https"

    trusted = any(domain == td or domain.endswith("." + td) for td in trusted_domains)
    suspicious = any(domain.endswith(tld) for tld in suspicious_tlds)

    # Subdomain spoof detection
    is_subdomain_spoof, spoof_reason = detect_subdomain_spoof(domain)
    if is_subdomain_spoof:
        trusted = False  # override trust if spoof detected
        suspicious = True

    # Homoglyph attack detection
    is_homoglyph, homoglyph_reason = detect_homoglyph_attack(domain)
    if is_homoglyph:
        trusted = False  # override trust if homoglyph detected
        suspicious = True

    domain_age_days = None
    try:
        base_domain = ".".join(domain.split(".")[-2:])
        w = whois.whois(base_domain)
        creation_date = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
        if creation_date:
            domain_age_days = (datetime.now() - creation_date).days
    except Exception:
        domain_age_days = None

    return {
        "domain": domain,
        "is_https": is_https,
        "suspicious_tld": suspicious,
        "trusted_domain": trusted,
        "domain_age_days": domain_age_days,
        "subdomain_spoof": is_subdomain_spoof,
        "spoof_reason": spoof_reason or "",
        "homoglyph_attack": is_homoglyph,
        "homoglyph_reason": homoglyph_reason or "",
    }


def url_structure_risk(url):
    risk_flags = []
    parsed = urlparse(url)
    domain = parsed.netloc.replace("www.", "")

    is_trusted = any(domain == td or domain.endswith("." + td) for td in trusted_domains)

    # Raw IP address
    if re.search(r"https?://\d+\.\d+\.\d+\.\d+", url):
        risk_flags.append("ip_address_used")

    # Long URL — skip for trusted domains
    if len(url) > 120 and not is_trusted:
        risk_flags.append("very_long_url")

    # Suspicious keywords — skip for trusted domains
    if not is_trusted:
        for keyword in ["login", "verify", "account", "update", "bank",
                        "secure", "confirm", "password", "urgent", "free", "winner"]:
            if keyword in url.lower():
                risk_flags.append(f"suspicious_keyword_{keyword}")

    # Excessive subdomains
    if len(parsed.netloc.split(".")) > 4:
        risk_flags.append("excessive_subdomains")

    # Subdomain spoof
    is_spoof, _ = detect_subdomain_spoof(domain)
    if is_spoof:
        risk_flags.append("subdomain_spoof")

    # Homoglyph
    is_homoglyph, _ = detect_homoglyph_attack(domain)
    if is_homoglyph:
        risk_flags.append("homoglyph_attack")

    return risk_flags


def analyze_url_input(url):
    text, title, method = extract_text_from_url(url)
    domain_info = extract_domain_info(url)
    structure_flags = url_structure_risk(url)

    extraction_status = "full_content" if method != "title_only" else "limited_content"
    if not text and not title:
        extraction_status = "failed"

    return {
        "content": text,
        "title": title,
        "domain_info": domain_info,
        "structure_flags": structure_flags,
        "extraction_method": method,
        "extraction_status": extraction_status
    }
