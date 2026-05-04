"""URL feature analysis - 22 features extracted from raw URL.
Returns per-feature risk contributions and an aggregated ML score (0-100)
that simulates an XGBoost-trained classifier output.
"""
from __future__ import annotations

import math
import re
from urllib.parse import urlparse

SUSPICIOUS_TLDS = {"tk", "ml", "ga", "cf", "gq", "xyz", "top", "club", "work", "info", "zip", "mov"}
BRAND_KEYWORDS = [
    "paypal", "sbi", "hdfc", "icici", "axis", "amazon", "flipkart", "google",
    "gmail", "microsoft", "apple", "icloud", "facebook", "instagram", "netflix",
    "whatsapp", "bank", "secure", "login", "signin", "verify", "update", "account",
    "wallet", "bitcoin", "crypto"
]
PHISHY_WORDS = ["login", "verify", "secure", "account", "update", "confirm", "password", "banking", "signin", "webscr"]
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "adf.ly", "rebrand.ly"}

IP_REGEX = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def extract_features(url: str) -> dict:
    """Return 22 features + per-feature risk weight (0-1 contribution)."""
    raw = url.strip()
    if not re.match(r"^[a-zA-Z]+://", raw):
        raw = "http://" + raw
    parsed = urlparse(raw)
    host = (parsed.hostname or "").lower()
    path = parsed.path or ""
    query = parsed.query or ""
    full = raw.lower()

    host_parts = host.split(".") if host else []
    tld = host_parts[-1] if host_parts else ""
    subdomains = host_parts[:-2] if len(host_parts) > 2 else []

    features: list[dict] = []

    def add(name: str, value, risk: float, detail: str = ""):
        features.append({
            "name": name,
            "value": value,
            "risk": round(max(0.0, min(1.0, risk)), 2),
            "detail": detail,
        })

    # 1. URL length
    url_len = len(raw)
    add("url_length", url_len, 0.9 if url_len > 100 else (0.5 if url_len > 75 else (0.2 if url_len > 54 else 0.0)),
        "Long URLs often hide redirects")

    # 2. Hostname length
    add("hostname_length", len(host), 0.6 if len(host) > 40 else (0.3 if len(host) > 25 else 0.0))

    # 3. Uses HTTPS
    https = parsed.scheme == "https"
    add("uses_https", https, 0.0 if https else 0.7, "Missing HTTPS certificate")

    # 4. Hostname is raw IP
    is_ip = bool(IP_REGEX.match(host))
    add("ip_in_host", is_ip, 0.95 if is_ip else 0.0, "Hostname is literal IP")

    # 5. Contains '@' (credential-style URL)
    at_sign = "@" in raw
    add("has_at_symbol", at_sign, 0.85 if at_sign else 0.0)

    # 6. Subdomain depth
    sub_depth = len(subdomains)
    add("subdomain_depth", sub_depth, 0.75 if sub_depth >= 3 else (0.4 if sub_depth == 2 else 0.0))

    # 7. Suspicious TLD
    bad_tld = tld in SUSPICIOUS_TLDS
    add("suspicious_tld", tld, 0.8 if bad_tld else 0.0, f".{tld} is commonly abused" if bad_tld else "")

    # 8. Hyphens in host
    hyphen_count = host.count("-")
    add("hyphen_count", hyphen_count, 0.6 if hyphen_count >= 3 else (0.3 if hyphen_count >= 1 else 0.0))

    # 9. Digits in host
    digit_count = sum(c.isdigit() for c in host)
    add("digit_count_host", digit_count, 0.7 if digit_count >= 5 else (0.4 if digit_count >= 2 else 0.0))

    # 10. Special chars in URL
    specials = sum(1 for c in raw if c in "?&%=+#")
    add("special_char_count", specials, 0.5 if specials >= 6 else 0.0)

    # 11. Double slashes in path
    double_slash = path.count("//") > 0
    add("double_slash_path", double_slash, 0.7 if double_slash else 0.0)

    # 12. Shannon entropy of host
    entropy = round(_shannon_entropy(host), 2)
    add("host_entropy", entropy, 0.7 if entropy > 4.0 else (0.3 if entropy > 3.5 else 0.0),
        "High entropy suggests auto-generated domain")

    # 13. Brand keyword in subdomain/path (common for impersonation)
    brand_hit = next((b for b in BRAND_KEYWORDS if b in host or b in path.lower()), None)
    # Brand kw is only a red flag if the apex domain itself is NOT the brand
    apex = ".".join(host_parts[-2:]) if len(host_parts) >= 2 else host
    brand_in_apex = brand_hit and brand_hit in apex
    add("brand_keyword", brand_hit or "none",
        0.85 if brand_hit and not brand_in_apex else 0.0,
        f"Mentions '{brand_hit}' outside apex domain" if brand_hit and not brand_in_apex else "")

    # 14. Phishy action words
    phishy = [w for w in PHISHY_WORDS if w in full]
    add("phishy_words", ",".join(phishy) or "none", 0.6 if len(phishy) >= 2 else (0.3 if phishy else 0.0))

    # 15. URL shortener service
    shortener = host in SHORTENERS
    add("url_shortener", shortener, 0.7 if shortener else 0.0)

    # 16. Port explicitly specified
    port = parsed.port
    add("explicit_port", port or "default", 0.5 if port and port not in (80, 443) else 0.0)

    # 17. Path depth
    path_depth = len([p for p in path.split("/") if p])
    add("path_depth", path_depth, 0.4 if path_depth >= 5 else 0.0)

    # 18. Query param count
    qp_count = len([q for q in query.split("&") if q])
    add("query_param_count", qp_count, 0.3 if qp_count >= 5 else 0.0)

    # 19. Punycode / xn-- (IDN homograph)
    puny = "xn--" in host
    add("punycode_host", puny, 0.8 if puny else 0.0, "Possible homograph attack" if puny else "")

    # 20. Hex / URL-encoded chars
    hex_count = len(re.findall(r"%[0-9a-fA-F]{2}", raw))
    add("hex_encoded_count", hex_count, 0.5 if hex_count >= 3 else 0.0)

    # 21. Uppercase letters ratio in host
    upper = sum(1 for c in host if c.isupper())
    add("uppercase_in_host", upper, 0.2 if upper else 0.0)

    # 22. Total digits ratio
    digits_all = sum(c.isdigit() for c in raw)
    ratio = round(digits_all / max(1, len(raw)), 2)
    add("digit_ratio", ratio, 0.5 if ratio > 0.15 else 0.0)

    # Weighted aggregation → 0..100 ML score
    # Each feature contributes up to (risk * weight); weights emphasize strongest signals.
    strong_weights = {
        "ip_in_host": 12, "has_at_symbol": 10, "punycode_host": 10,
        "brand_keyword": 10, "uses_https": 9, "suspicious_tld": 9,
        "url_shortener": 7, "host_entropy": 7, "url_length": 7,
        "phishy_words": 6, "double_slash_path": 6, "subdomain_depth": 5,
    }
    total = 0.0
    max_total = 0.0
    for f in features:
        w = strong_weights.get(f["name"], 3)
        total += f["risk"] * w
        max_total += w
    raw = total / max_total if max_total else 0.0
    # Non-linear boost so a few strong signals drive a high score (XGBoost-like)
    ml_score = round(100.0 * (1.0 - (1.0 - raw) ** 2.5), 1)

    return {
        "features": features,
        "ml_score": ml_score,
        "parsed": {
            "scheme": parsed.scheme,
            "host": host,
            "tld": tld,
            "path": path,
        },
    }
