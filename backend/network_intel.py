"""Network intelligence — WHOIS, DNS, SSL, and HTTP-header probes.

Each function is async and bounded by a short timeout; failures degrade
gracefully so the scanner never blocks on a single dead lookup.
"""
from __future__ import annotations

import asyncio
import logging
import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse

import httpx

logger = logging.getLogger("network_intel")

DNS_TIMEOUT = 4.0
WHOIS_TIMEOUT = 6.0
SSL_TIMEOUT = 6.0
HEAD_TIMEOUT = 8.0


# ─────────────────── DNS ───────────────────
async def dns_probe(host: str) -> dict:
    """Async DNS resolution + simple record sniffing."""
    out: dict = {"a": [], "mx": [], "ns": [], "txt_count": 0, "error": None}
    try:
        import dns.resolver
        import dns.asyncresolver
        r = dns.asyncresolver.Resolver()
        r.lifetime = DNS_TIMEOUT
        r.timeout = DNS_TIMEOUT
        try:
            ans = await r.resolve(host, "A")
            out["a"] = [str(x) for x in ans][:6]
        except Exception:
            pass
        try:
            ans = await r.resolve(host, "MX")
            out["mx"] = [str(x.exchange).rstrip(".") for x in ans][:4]
        except Exception:
            pass
        try:
            ans = await r.resolve(host, "NS")
            out["ns"] = [str(x).rstrip(".") for x in ans][:4]
        except Exception:
            pass
        try:
            ans = await r.resolve(host, "TXT")
            out["txt_count"] = len(list(ans))
        except Exception:
            pass
    except Exception as e:
        out["error"] = f"{type(e).__name__}: {e}"
    out["has_a"] = bool(out["a"])
    out["has_mx"] = bool(out["mx"])
    return out


# ─────────────────── WHOIS ───────────────────
def _sync_whois(host: str) -> dict:
    out: dict = {"registrar": None, "creation_date": None, "expiration_date": None,
                 "country": None, "age_days": None, "error": None}
    try:
        import whois
        w = whois.whois(host)
        out["registrar"] = getattr(w, "registrar", None) or w.get("registrar") if hasattr(w, "get") else None
        cd = getattr(w, "creation_date", None)
        if isinstance(cd, list):
            cd = cd[0] if cd else None
        ed = getattr(w, "expiration_date", None)
        if isinstance(ed, list):
            ed = ed[0] if ed else None
        if cd:
            try:
                if isinstance(cd, str):
                    cd = datetime.fromisoformat(cd.replace("Z", "+00:00"))
                if cd.tzinfo is None:
                    cd = cd.replace(tzinfo=timezone.utc)
                out["creation_date"] = cd.isoformat()
                out["age_days"] = (datetime.now(timezone.utc) - cd).days
            except Exception:
                pass
        if ed:
            try:
                if isinstance(ed, str):
                    ed = datetime.fromisoformat(ed.replace("Z", "+00:00"))
                if ed.tzinfo is None:
                    ed = ed.replace(tzinfo=timezone.utc)
                out["expiration_date"] = ed.isoformat()
            except Exception:
                pass
        out["country"] = getattr(w, "country", None)
    except Exception as e:
        out["error"] = f"{type(e).__name__}: {e}"
    return out


async def whois_probe(host: str) -> dict:
    try:
        return await asyncio.wait_for(asyncio.to_thread(_sync_whois, host), timeout=WHOIS_TIMEOUT)
    except asyncio.TimeoutError:
        return {"error": "timeout", "age_days": None}
    except Exception as e:
        return {"error": f"{type(e).__name__}: {e}", "age_days": None}


# ─────────────────── SSL ───────────────────
def _sync_ssl(host: str, port: int = 443) -> dict:
    out: dict = {"valid": False, "issuer": None, "subject": None,
                 "not_before": None, "not_after": None,
                 "days_until_expiry": None, "self_signed": False, "error": None}
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=SSL_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
        if cert:
            out["valid"] = True
            out["issuer"] = dict(x[0] for x in cert.get("issuer", []))
            out["subject"] = dict(x[0] for x in cert.get("subject", []))
            nb = cert.get("notBefore")
            na = cert.get("notAfter")
            if nb:
                out["not_before"] = nb
            if na:
                out["not_after"] = na
                try:
                    exp = datetime.strptime(na, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                    out["days_until_expiry"] = (exp - datetime.now(timezone.utc)).days
                except Exception:
                    pass
            out["self_signed"] = out["issuer"] == out["subject"]
    except ssl.SSLCertVerificationError as e:
        out["error"] = f"cert verification failed: {e.reason if hasattr(e,'reason') else e}"
    except Exception as e:
        out["error"] = f"{type(e).__name__}: {e}"
    return out


async def ssl_probe(host: str) -> dict:
    try:
        return await asyncio.wait_for(asyncio.to_thread(_sync_ssl, host), timeout=SSL_TIMEOUT + 2)
    except asyncio.TimeoutError:
        return {"valid": False, "error": "timeout"}
    except Exception as e:
        return {"valid": False, "error": f"{type(e).__name__}: {e}"}


# ─────────────────── HTTP HEADERS + REDIRECT CHAIN ───────────────────
async def http_probe(url: str) -> dict:
    out: dict = {
        "status": None, "redirect_chain": [], "final_url": None,
        "server": None, "x_frame_options": None, "content_security_policy": False,
        "strict_transport_security": False, "set_cookie_count": 0,
        "content_type": None, "error": None,
    }
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    try:
        async with httpx.AsyncClient(timeout=HEAD_TIMEOUT, follow_redirects=True,
                                     headers={"User-Agent": "PhishSentinel/2.0"}) as c:
            r = await c.get(url)
            out["status"] = r.status_code
            out["final_url"] = str(r.url)
            out["redirect_chain"] = [str(h.url) for h in r.history]
            hdrs = {k.lower(): v for k, v in r.headers.items()}
            out["server"] = hdrs.get("server")
            out["x_frame_options"] = hdrs.get("x-frame-options")
            out["content_security_policy"] = bool(hdrs.get("content-security-policy"))
            out["strict_transport_security"] = bool(hdrs.get("strict-transport-security"))
            out["set_cookie_count"] = sum(1 for k in r.headers.keys() if k.lower() == "set-cookie")
            out["content_type"] = hdrs.get("content-type", "")
    except Exception as e:
        out["error"] = f"{type(e).__name__}: {e}"
    return out


# ─────────────────── ORCHESTRATOR ───────────────────
async def gather_network_intel(url: str) -> dict:
    host = urlparse(url if "://" in url else "http://" + url).hostname or ""
    if not host:
        return {"error": "no host"}
    dns_r, whois_r, ssl_r, http_r = await asyncio.gather(
        dns_probe(host), whois_probe(host),
        ssl_probe(host) if not host.replace(".", "").isdigit() else asyncio.sleep(0, result={"valid": False}),
        http_probe(url),
        return_exceptions=False,
    )
    return {"dns": dns_r, "whois": whois_r, "ssl": ssl_r, "http": http_r}


# ─────────────────── RISK SCORING ───────────────────
def network_risk(intel: dict) -> dict:
    """Turn raw probe data into 0-100 risk + per-signal contributions."""
    sigs: list[dict] = []

    def add(name, value, risk, detail=""):
        sigs.append({"name": name, "value": value,
                     "risk": round(max(0.0, min(1.0, risk)), 2),
                     "detail": detail})

    dns_r = intel.get("dns", {}) or {}
    add("dns_resolves", dns_r.get("has_a"), 0.0 if dns_r.get("has_a") else 0.5)
    add("has_mx_record", dns_r.get("has_mx"), 0.0 if dns_r.get("has_mx") else 0.3,
        "No MX → likely not a real business")
    add("a_record_count", len(dns_r.get("a", [])), 0.0)

    whois_r = intel.get("whois", {}) or {}
    age = whois_r.get("age_days")
    if age is None:
        add("domain_age_days", "unknown", 0.4, "WHOIS unavailable / hidden")
    else:
        add("domain_age_days", age,
            0.9 if age < 30 else (0.65 if age < 180 else (0.3 if age < 365 else 0.0)),
            f"Domain is {age} days old")

    ssl_r = intel.get("ssl", {}) or {}
    if not ssl_r.get("valid"):
        add("ssl_valid", False, 0.7, ssl_r.get("error", "no valid TLS cert"))
    else:
        add("ssl_valid", True, 0.0)
        if ssl_r.get("self_signed"):
            add("ssl_self_signed", True, 0.9, "Self-signed certificate")
        days_left = ssl_r.get("days_until_expiry")
        if isinstance(days_left, int):
            add("ssl_days_left", days_left,
                0.6 if days_left < 7 else (0.3 if days_left < 30 else 0.0))

    http_r = intel.get("http", {}) or {}
    if http_r.get("error"):
        add("http_reachable", False, 0.5, http_r["error"])
    else:
        add("http_reachable", True, 0.0)
        chain = http_r.get("redirect_chain") or []
        add("redirect_chain_length", len(chain),
            0.6 if len(chain) >= 3 else (0.3 if len(chain) == 2 else 0.0),
            "Many redirects can obfuscate destination")
        add("missing_csp", not http_r.get("content_security_policy"),
            0.2 if not http_r.get("content_security_policy") else 0.0)
        add("missing_hsts", not http_r.get("strict_transport_security"),
            0.2 if not http_r.get("strict_transport_security") else 0.0)

    weights = {
        "ssl_self_signed": 10, "domain_age_days": 12, "ssl_valid": 8,
        "redirect_chain_length": 6, "has_mx_record": 4, "dns_resolves": 6,
        "http_reachable": 4, "ssl_days_left": 5, "missing_csp": 2,
        "missing_hsts": 2,
    }
    total = sum(s["risk"] * weights.get(s["name"], 2) for s in sigs)
    max_t = sum(weights.get(s["name"], 2) for s in sigs)
    ratio = total / max_t if max_t else 0.0
    score = round(100.0 * (1.0 - (1.0 - ratio) ** 2.2), 1)
    return {"network_score": score, "signals": sigs}
