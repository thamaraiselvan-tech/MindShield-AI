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
# =========================
trusted_domains = [
    "bbc.com", "reuters.com", "nytimes.com", "theguardian.com",
    "apnews.com", "npr.org", "thehindu.com", "ndtv.com",
    "timesofindia.com", "hindustantimes.com", "indianexpress.com",
    "who.int", "nature.com", "pubmed.ncbi.nlm.nih.gov",
    "cdc.gov", "nih.gov", "mayoclinic.org",
    "wikipedia.org", "britannica.com", "gov.in", "nic.in",
    "edu", "ac.in", "ac.uk",
    "amazon.com", "amazon.in", "flipkart.com",
    "youtube.com", "google.com", "microsoft.com",
    "apple.com", "github.com", "linkedin.com",
    "swayam.gov.in", "swayam2.ac.in", "iitm.ac.in",
    "ugc.ac.in", "mygov.in",
]

suspicious_tlds = [
    ".xyz", ".click", ".top", ".buzz",
    ".info", ".online", ".site", ".tk",
    ".ml", ".ga", ".cf", ".gq"
]

# Homoglyph map — detects visually similar fake domains (g00gle, paypa1)
HOMOGLYPHS = {
    "0": "o", "1": "l", "3": "e", "4": "a",
    "5": "s", "6": "g", "7": "t", "8": "b",
    "@": "a", "vv": "w"
}

# Known brands that attackers impersonate
KNOWN_BRANDS = [
    "google", "facebook", "paypal", "amazon", "apple",
    "microsoft", "netflix", "instagram", "whatsapp",
    "hdfc", "sbi", "icici", "axis", "paytm",
    "flipkart", "swiggy", "zomato", "ola", "uber"
]


def normalize_domain(domain):
    """Normalize unicode and homoglyphs for spoof detection."""
    # Normalize unicode (catches punycode attacks)
    try:
        domain = domain.encode("ascii").decode("ascii")
    except Exception:
        domain = unicodedata.normalize("NFKD", domain).encode("ascii", "ignore").decode()

    normalized = domain.lower()
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
    """Detect g00gle.com, paypa1.com style attacks."""
    normalized = normalize_domain(domain)
    base = normalized.split(".")[0]  # just the domain name part

    for brand in KNOWN_BRANDS:
        # Normalized domain looks like a brand but isn't exactly it
        if brand in normalized and not any(
            domain.endswith(f"{brand}.{tld}") for tld in ["com", "in", "org", "net"]
        ):
            # Check if it's close but not exact
            if brand != base and brand in base:
                return True, f"Domain may be impersonating '{brand}'"

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
