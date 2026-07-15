"""Adaptive Decision Engine — combines 9 risk factors into final verdict,
confidence, threat category and explainable JSON report."""
from __future__ import annotations

from typing import Literal


THREAT_CATEGORIES = {
    "credential_phishing": ["paypal", "login", "signin", "account", "verify", "office365", "google", "microsoft"],
    "banking_fraud": ["bank", "sbi", "hdfc", "icici", "axis", "chase", "wells"],
    "brand_impersonation": ["amazon", "apple", "netflix", "instagram", "facebook"],
    "crypto_theft": ["binance", "metamask", "wallet", "crypto", "bitcoin"],
    "malware_distribution": [".exe", ".zip", ".scr", "/bin.sh", "/i", "/mips"],
}


def _category(scan: dict) -> str:
    url = (scan.get("url") or "").lower()
    brand = (scan.get("visual", {}) or {}).get("cloned_brand", "") or ""
    text = url + " " + str(brand).lower()
    for cat, keywords in THREAT_CATEGORIES.items():
        if any(k in text for k in keywords):
            return cat
    return "unknown"


def decide(
    *,
    url: str,
    ml_score: float,
    model_score: float | None,
    visual_score: float,
    visual_available: bool,
    db_score: float,
    crawler_hits: int,
    network: dict | None,
    cloned_brand: str | None,
) -> dict:
    """Return final risk, confidence, category, explainable report.

    Risk factors (weight × normalised 0-1 score):
      ML feature score         × 0.20
      ML model probability     × 0.25 (if model available)
      Visual cloning           × 0.18
      Community DB             × 0.12
      Crawler corroboration    × 0.07
      WHOIS / domain age       × 0.06
      DNS health               × 0.04
      SSL trust                × 0.06
      HTTP redirect chain      × 0.02
    Total = 1.00
    """
    factors: list[dict] = []

    def add(name, weight, score_0_100, detail=""):
        factors.append({
            "name": name, "weight": weight,
            "score": round(score_0_100, 1),
            "weighted": round(weight * score_0_100, 2),
            "detail": detail,
        })

    add("url_features_ml", 0.20, ml_score, "Heuristic 55-feature score")
    if model_score is not None:
        add("model_probability", 0.25, model_score, "Trained ensemble model")
    if visual_available:
        add("visual_cloning", 0.18, visual_score, "Gemini vision detection")
    add("community_db", 0.12, db_score, "Crowdsourced threat reports")
    add("crawler_intel", 0.07, min(100.0, crawler_hits * 25.0),
        f"{crawler_hits} crawler finding(s)")

    net = network or {}
    whois_r = (net.get("whois") or {})
    age = whois_r.get("age_days")
    if age is not None:
        whois_score = (100.0 if age < 30 else (70.0 if age < 180 else (35.0 if age < 365 else 5.0)))
    else:
        whois_score = 40.0
    add("whois_risk", 0.06, whois_score, f"Domain age {age if age is not None else 'unknown'} days")

    dns_r = (net.get("dns") or {})
    dns_score = 0.0 if dns_r.get("has_a") else 50.0
    if dns_r and not dns_r.get("has_mx"):
        dns_score += 25.0
    add("dns_risk", 0.04, min(100.0, dns_score), "DNS posture")

    ssl_r = (net.get("ssl") or {})
    if not ssl_r.get("valid"):
        ssl_score = 70.0
    elif ssl_r.get("self_signed"):
        ssl_score = 90.0
    else:
        ssl_score = 0.0
    add("ssl_trust", 0.06, ssl_score, ssl_r.get("error") or "Certificate inspection")

    http_r = (net.get("http") or {})
    redirects = len(http_r.get("redirect_chain") or [])
    add("redirect_chain", 0.02, min(100.0, redirects * 25.0),
        f"{redirects} redirect hop(s)")

    # Normalise weights (handles optional ones)
    total_w = sum(f["weight"] for f in factors)
    if total_w == 0:
        risk_score = 0.0
    else:
        risk_score = sum(f["weighted"] for f in factors) / total_w
    risk_score = round(risk_score, 1)

    # Confidence: how much corroboration across independent signals
    contributing = sum(1 for f in factors if f["score"] > 10)
    confidence = round(min(100.0, contributing / max(1, len(factors)) * 100.0 + 5 * contributing), 1)

    if risk_score >= 65:
        verdict = "PHISHING"
    elif risk_score >= 35:
        verdict = "SUSPICIOUS"
    else:
        verdict = "SAFE"

    category = _category({
        "url": url, "visual": {"cloned_brand": cloned_brand},
    }) if verdict != "SAFE" else "benign"

    # Explainable report — natural-language rationale
    top_factors = sorted(factors, key=lambda f: f["weighted"], reverse=True)[:3]
    reasons = []
    for tf in top_factors:
        if tf["score"] >= 10:
            reasons.append(f"{tf['name']} contributed {tf['weighted']:.1f} pts ({tf['detail']})")
    if not reasons:
        reasons = ["No significant risk signals observed across any layer"]

    return {
        "risk_score": risk_score,
        "confidence": confidence,
        "verdict": verdict,
        "category": category,
        "factors": factors,
        "top_factors": top_factors,
        "explanation": reasons,
    }
