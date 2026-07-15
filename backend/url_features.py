"""URL Intelligence — 55+ lexical, structural, brand-similarity, typosquatting,
homograph, entropy, and Unicode signals extracted from a raw URL."""
from __future__ import annotations

import math
import re
import unicodedata
from urllib.parse import urlparse, parse_qs

from thefuzz import fuzz

SUSPICIOUS_TLDS = {"tk", "ml", "ga", "cf", "gq", "xyz", "top", "club", "work",
                   "info", "zip", "mov", "rest", "country", "stream", "loan", "click"}
BRANDS = ["paypal", "sbi", "hdfc", "icici", "axis", "amazon", "flipkart",
          "google", "gmail", "microsoft", "apple", "icloud", "facebook",
          "instagram", "netflix", "whatsapp", "binance", "metamask", "office365"]
PHISHY_WORDS = ["login", "verify", "secure", "account", "update", "confirm",
                "password", "banking", "signin", "webscr", "auth", "wallet",
                "billing", "support", "alert", "recover", "unlock"]
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
              "buff.ly", "adf.ly", "rebrand.ly", "shorturl.at"}
SUSPICIOUS_PORTS = {8080, 8443, 7777, 8888, 4444, 1337, 31337}

IP_REGEX = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
HEX_REGEX = re.compile(r"%[0-9a-fA-F]{2}")
CYRILLIC_CHARS = set("аеорсух")  # look-alike letters
GREEK_CHARS = set("αεοριυ")


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def _ngram_set(s: str, n: int = 3) -> set[str]:
    s = s.lower()
    return {s[i:i + n] for i in range(max(0, len(s) - n + 1))}


def _has_lookalikes(s: str) -> bool:
    chars = set(s)
    return bool(chars & CYRILLIC_CHARS) or bool(chars & GREEK_CHARS)


def _normalize(url: str) -> str:
    raw = url.strip()
    if not re.match(r"^[a-zA-Z]+://", raw):
        raw = "http://" + raw
    return raw


def _brand_similarity(host: str) -> tuple[str | None, int]:
    """Return (best_brand, similarity 0-100). High = potential typosquat."""
    host_low = host.lower()
    apex = host_low.split(".")[0] if host_low else ""
    if not apex:
        return None, 0
    best_brand = None
    best_score = 0
    for b in BRANDS:
        if b == apex:  # exact match = legitimate domain
            return b, 100
        # Token set ratio handles substrings + reorderings
        score = max(fuzz.partial_ratio(b, apex), fuzz.ratio(b, apex))
        if score > best_score:
            best_score = score
            best_brand = b
    return best_brand, best_score


def extract_features(url: str) -> dict:
    """Return ~55 features + per-feature risk + ML score."""
    raw = _normalize(url)
    parsed = urlparse(raw)
    host = (parsed.hostname or "").lower()
    path = parsed.path or ""
    query = parsed.query or ""
    fragment = parsed.fragment or ""
    full = raw.lower()

    host_parts = host.split(".") if host else []
    tld = host_parts[-1] if host_parts else ""
    sld = host_parts[-2] if len(host_parts) >= 2 else ""
    apex = ".".join(host_parts[-2:]) if len(host_parts) >= 2 else host
    subdomains = host_parts[:-2] if len(host_parts) > 2 else []

    features: list[dict] = []

    def add(name, value, risk, category="lexical", detail=""):
        features.append({
            "name": name, "value": value, "category": category,
            "risk": round(max(0.0, min(1.0, risk)), 2),
            "detail": detail,
        })

    # ────────────────── LEXICAL (length & character) ──────────────────
    url_len = len(raw)
    add("url_length", url_len, 0.9 if url_len > 100 else (0.5 if url_len > 75 else (0.2 if url_len > 54 else 0.0)),
        "lexical", "Long URLs hide redirects")
    add("hostname_length", len(host), 0.6 if len(host) > 40 else (0.3 if len(host) > 25 else 0.0), "lexical")
    add("path_length", len(path), 0.5 if len(path) > 80 else 0.0, "lexical")
    add("query_length", len(query), 0.4 if len(query) > 100 else 0.0, "lexical")

    specials = sum(1 for c in raw if c in "?&%=+#@")
    add("special_char_count", specials, 0.5 if specials >= 6 else 0.0, "lexical")
    dots = host.count(".")
    add("dot_count", dots, 0.7 if dots >= 5 else (0.4 if dots == 4 else 0.0), "lexical")
    hyphens = host.count("-")
    add("hyphen_count", hyphens, 0.6 if hyphens >= 3 else (0.3 if hyphens >= 1 else 0.0), "lexical")
    digit_host = sum(c.isdigit() for c in host)
    add("digit_count_host", digit_host, 0.7 if digit_host >= 5 else (0.4 if digit_host >= 2 else 0.0), "lexical")
    digits_all = sum(c.isdigit() for c in raw)
    add("digit_ratio_url", round(digits_all / max(1, url_len), 2),
        0.5 if digits_all / max(1, url_len) > 0.15 else 0.0, "lexical")
    upper_host = sum(1 for c in host if c.isupper())
    add("uppercase_in_host", upper_host, 0.2 if upper_host else 0.0, "lexical")

    # ────────────────── STRUCTURAL ──────────────────
    https = parsed.scheme == "https"
    add("uses_https", https, 0.0 if https else 0.7, "structural", "Missing HTTPS")
    is_ip = bool(IP_REGEX.match(host))
    add("ip_in_host", is_ip, 0.95 if is_ip else 0.0, "structural", "Literal IP as host")
    at_sign = "@" in raw
    add("has_at_symbol", at_sign, 0.85 if at_sign else 0.0, "structural", "@-trick credential URL")
    add("subdomain_depth", len(subdomains), 0.75 if len(subdomains) >= 3 else (0.4 if len(subdomains) == 2 else 0.0), "structural")
    bad_tld = tld in SUSPICIOUS_TLDS
    add("suspicious_tld", tld, 0.8 if bad_tld else 0.0, "structural",
        f".{tld} is commonly abused" if bad_tld else "")
    add("double_slash_path", path.count("//") > 0, 0.7 if path.count("//") > 0 else 0.0, "structural")
    path_depth = len([p for p in path.split("/") if p])
    add("path_depth", path_depth, 0.4 if path_depth >= 5 else 0.0, "structural")
    qp_count = len([q for q in query.split("&") if q])
    add("query_param_count", qp_count, 0.3 if qp_count >= 5 else 0.0, "structural")
    add("has_fragment", bool(fragment), 0.2 if fragment else 0.0, "structural")
    port = parsed.port
    is_susp_port = port in SUSPICIOUS_PORTS
    add("explicit_port", port or "default", 0.6 if is_susp_port else (0.3 if port and port not in (80, 443) else 0.0),
        "structural", "Non-standard port" if port and port not in (80, 443) else "")

    # ────────────────── ENTROPY ──────────────────
    host_e = round(_entropy(host), 2)
    add("host_entropy", host_e, 0.7 if host_e > 4.0 else (0.3 if host_e > 3.5 else 0.0),
        "entropy", "High entropy → auto-generated domain")
    add("path_entropy", round(_entropy(path), 2), 0.4 if _entropy(path) > 4.2 else 0.0, "entropy")
    add("query_entropy", round(_entropy(query), 2), 0.3 if _entropy(query) > 4.0 else 0.0, "entropy")

    # ────────────────── UNICODE / HOMOGRAPH ──────────────────
    has_non_ascii = any(ord(c) > 127 for c in host)
    add("non_ascii_host", has_non_ascii, 0.8 if has_non_ascii else 0.0, "unicode",
        "Host contains non-ASCII chars (IDN risk)" if has_non_ascii else "")
    puny = "xn--" in host
    add("punycode_host", puny, 0.85 if puny else 0.0, "unicode", "Punycode IDN — possible homograph")
    add("cyrillic_lookalike", _has_lookalikes(host), 0.9 if _has_lookalikes(host) else 0.0,
        "unicode", "Cyrillic look-alike letters detected" if _has_lookalikes(host) else "")
    nfkd = unicodedata.normalize("NFKD", host)
    add("nfkd_normalised_diff", nfkd != host, 0.6 if nfkd != host else 0.0, "unicode")

    # ────────────────── BRAND SIMILARITY / TYPOSQUAT ──────────────────
    brand, sim = _brand_similarity(host)
    is_typosquat = bool(brand) and 70 <= sim < 100 and brand not in apex
    add("brand_match", brand or "none", 0.0 if sim >= 95 and brand in apex else (0.85 if is_typosquat else 0.0),
        "brand", "Looks like a typo of a known brand" if is_typosquat else "")
    add("brand_similarity", sim, 0.85 if is_typosquat else 0.0, "brand")
    brand_in_path = next((b for b in BRANDS if b in path.lower()), None)
    add("brand_in_path", brand_in_path or "none",
        0.7 if brand_in_path and (not brand or brand_in_path not in apex) else 0.0, "brand")

    # ────────────────── PHISHY KEYWORDS ──────────────────
    phishy_hits = [w for w in PHISHY_WORDS if w in full]
    add("phishy_words", ",".join(phishy_hits) or "none",
        0.65 if len(phishy_hits) >= 3 else (0.45 if len(phishy_hits) == 2 else (0.25 if phishy_hits else 0.0)),
        "lexical")
    add("phishy_word_count", len(phishy_hits),
        0.5 if len(phishy_hits) >= 2 else 0.0, "lexical")

    # ────────────────── URL SHORTENER / REDIRECT HINTS ──────────────────
    shortener = host in SHORTENERS
    add("url_shortener", shortener, 0.7 if shortener else 0.0, "structural")
    redirect_kw = any(k in query.lower() for k in ("url=", "redirect=", "next=", "dest=", "target="))
    add("redirect_param", redirect_kw, 0.6 if redirect_kw else 0.0, "structural")

    # ────────────────── ENCODING / OBFUSCATION ──────────────────
    hex_count = len(HEX_REGEX.findall(raw))
    add("hex_encoded_count", hex_count, 0.6 if hex_count >= 5 else (0.3 if hex_count >= 2 else 0.0), "lexical")
    add("has_data_uri", raw.startswith("data:"), 0.95 if raw.startswith("data:") else 0.0, "structural")
    add("has_javascript_uri", parsed.scheme == "javascript", 0.95 if parsed.scheme == "javascript" else 0.0, "structural")

    # ────────────────── CONSONANT/VOWEL RATIO (gibberish detector) ──────────────────
    consonants = sum(1 for c in apex if c.isalpha() and c.lower() not in "aeiou")
    vowels = sum(1 for c in apex if c.lower() in "aeiou")
    cv_ratio = consonants / max(1, vowels)
    add("consonant_vowel_ratio", round(cv_ratio, 2), 0.5 if cv_ratio > 4 else 0.0, "lexical",
        "Mostly consonants → likely gibberish" if cv_ratio > 4 else "")

    # ────────────────── BIGRAM RARITY (simple gibberish heuristic) ──────────────────
    rare_bigrams = sum(1 for i in range(len(apex) - 1)
                       if apex[i:i + 2] in ("xz", "qz", "jx", "zx", "qq", "kj"))
    add("rare_bigram_count", rare_bigrams, 0.5 if rare_bigrams else 0.0, "lexical")

    # ────────────────── NUMERIC PRESENCE NEAR BRAND ──────────────────
    brand_with_digits = bool(brand and brand != apex and re.search(rf"{re.escape(brand)}\d+", apex))
    add("brand_with_digits", brand_with_digits, 0.85 if brand_with_digits else 0.0, "brand",
        "e.g. paypal123" if brand_with_digits else "")

    # ────────────────── AGGREGATION → ML score ──────────────────
    strong = {
        "ip_in_host": 12, "has_at_symbol": 10, "punycode_host": 10,
        "cyrillic_lookalike": 11, "brand_match": 10, "brand_with_digits": 11,
        "uses_https": 9, "suspicious_tld": 9, "url_shortener": 7,
        "host_entropy": 7, "url_length": 7, "phishy_words": 7,
        "double_slash_path": 6, "subdomain_depth": 5, "non_ascii_host": 9,
        "has_data_uri": 12, "has_javascript_uri": 12, "redirect_param": 6,
        "brand_in_path": 7,
    }
    total = 0.0
    max_total = 0.0
    for f in features:
        w = strong.get(f["name"], 3)
        total += f["risk"] * w
        max_total += w
    raw_ratio = total / max_total if max_total else 0.0
    ml_score = round(100.0 * (1.0 - (1.0 - raw_ratio) ** 2.4), 1)

    return {
        "features": features,
        "feature_count": len(features),
        "ml_score": ml_score,
        "parsed": {
            "scheme": parsed.scheme, "host": host, "tld": tld, "sld": sld,
            "apex": apex, "path": path, "subdomains": subdomains, "port": port,
        },
    }
