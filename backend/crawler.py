"""Autonomous Web-Crawling Bot for PhishSentinel.
Pulls candidates from two public sources:
  • URLhaus  — recently abused URLs (HTTP feed)
  • CertStream — live SSL certificate transparency log (websocket)
Filters phishy candidates, runs the full hybrid scan, stores findings.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import random
import uuid
from datetime import datetime, timezone

import httpx
import websockets
from apscheduler.schedulers.asyncio import AsyncIOScheduler

from url_features import extract_features

logger = logging.getLogger("crawler")

URLHAUS_FEED = "https://urlhaus.abuse.ch/downloads/text_recent/"
CERTSTREAM_WS = "wss://certstream.calidog.io"

PHISHY_KEYWORDS = [
    "login", "verify", "secure", "account", "bank", "wallet", "signin", "auth",
    "paypal", "apple", "icloud", "amazon", "google", "microsoft", "office",
    "sbi", "hdfc", "icici", "axis", "netflix", "facebook", "instagram",
    "whatsapp", "binance", "metamask", "crypto",
]

# Module-level state (single-process)
_state = {
    "running": False,
    "last_run": None,
    "next_run": None,
    "interval_minutes": 15,
    "active_run": None,
}


def _is_phishy(s: str) -> bool:
    s = s.lower()
    return any(k in s for k in PHISHY_KEYWORDS)


async def _fetch_urlhaus(limit: int = 40) -> list[str]:
    try:
        async with httpx.AsyncClient(timeout=15.0) as c:
            r = await c.get(URLHAUS_FEED)
            if r.status_code != 200:
                return []
            urls = [ln.strip() for ln in r.text.splitlines()
                    if ln.strip() and not ln.startswith("#")]
            random.shuffle(urls)
            return urls[:limit]
    except Exception as e:
        logger.warning(f"URLhaus fetch error: {e}")
        return []


async def _sample_certstream(seconds: float = 12.0, max_hits: int = 20) -> list[str]:
    """Open a CertStream websocket briefly and grab phishy domains as they appear."""
    hits: list[str] = []
    try:
        async with websockets.connect(CERTSTREAM_WS, ping_interval=None,
                                      open_timeout=8, close_timeout=2) as ws:
            end = asyncio.get_event_loop().time() + seconds
            while asyncio.get_event_loop().time() < end and len(hits) < max_hits:
                try:
                    msg = await asyncio.wait_for(ws.recv(), timeout=1.5)
                except asyncio.TimeoutError:
                    continue
                try:
                    data = json.loads(msg)
                except Exception:
                    continue
                if data.get("message_type") != "certificate_update":
                    continue
                domains = data.get("data", {}).get("leaf_cert", {}).get("all_domains", []) or []
                for d in domains:
                    d = (d or "").lstrip("*.").strip().lower()
                    if d and "." in d and _is_phishy(d):
                        hits.append("https://" + d)
                        if len(hits) >= max_hits:
                            break
    except Exception as e:
        logger.warning(f"CertStream sample error: {type(e).__name__}: {e}")
    return hits


async def crawl_cycle(db, hybrid_scan_fn, manual: bool = False) -> dict:
    """One full crawler cycle. hybrid_scan_fn(url) → scan dict."""
    run_id = str(uuid.uuid4())
    started = datetime.now(timezone.utc).isoformat()
    _state["active_run"] = run_id

    urlhaus_candidates, cert_candidates = await asyncio.gather(
        _fetch_urlhaus(40),
        _sample_certstream(12.0, 20),
    )
    candidates: list[tuple[str, str]] = (
        # URLhaus is already a curated abuse feed — skip phishy-keyword filter
        [(u, "urlhaus") for u in urlhaus_candidates]
        + [(u, "certstream") for u in cert_candidates]
    )
    # De-dupe by host
    seen_hosts = set()
    deduped: list[tuple[str, str]] = []
    for url, src in candidates:
        host = url.split("/")[2] if "://" in url else url
        if host in seen_hosts:
            continue
        seen_hosts.add(host)
        deduped.append((url, src))
    deduped = deduped[:6]  # Cap full hybrid scans per cycle (each takes 5-30s)

    findings = []
    for url, source in deduped:
        try:
            scan = await asyncio.wait_for(hybrid_scan_fn(url), timeout=60.0)
        except Exception as e:
            logger.warning(f"Crawler scan failed {url}: {e}")
            continue
        # URLhaus listings are pre-confirmed abuse — always store.
        # CertStream candidates only stored if score >= 25.
        if source == "certstream" and scan["final_score"] < 25:
            continue
        host = scan["host"]
        if await db.crawler_findings.find_one({"host": host}, {"_id": 0}):
            continue
        finding = {
            "id": str(uuid.uuid4()),
            "url": url,
            "host": host,
            "ml_score": scan["ml_score"],
            "cnn_score": scan["cnn_score"],
            "db_score": scan["db_score"],
            "final_score": scan["final_score"],
            "verdict": scan["verdict"],
            "source": source,
            "scan_id": scan["id"],
            "discovered_at": datetime.now(timezone.utc).isoformat(),
        }
        await db.crawler_findings.insert_one(finding)
        findings.append({k: v for k, v in finding.items() if k != "_id"})

    finished = datetime.now(timezone.utc).isoformat()
    summary = {
        "id": run_id,
        "started_at": started,
        "finished_at": finished,
        "candidates_pulled": len(candidates),
        "candidates_scanned": len(deduped),
        "new_findings": len(findings),
        "trigger": "manual" if manual else "scheduled",
        "sources": {"urlhaus": len(urlhaus_candidates), "certstream": len(cert_candidates)},
    }
    await db.crawler_runs.insert_one(summary)
    _state["last_run"] = finished
    _state["active_run"] = None
    logger.info(f"Crawler cycle done: {len(deduped)} scanned, {len(findings)} new findings")
    return summary


def start_scheduler(db, hybrid_scan_fn, interval_minutes: int = 15):
    """Start background APScheduler. Returns the scheduler instance."""
    sched = AsyncIOScheduler()

    async def _job():
        try:
            await crawl_cycle(db, hybrid_scan_fn)
            _state["next_run"] = (
                sched.get_jobs()[0].next_run_time.isoformat()
                if sched.get_jobs() else None
            )
        except Exception:
            logger.exception("Scheduled crawler cycle failed")

    sched.add_job(_job, "interval", minutes=interval_minutes,
                  next_run_time=datetime.now(timezone.utc))
    sched.start()
    _state["running"] = True
    _state["interval_minutes"] = interval_minutes
    logger.info(f"Crawler scheduler started — every {interval_minutes}min")
    return sched


def get_state() -> dict:
    return dict(_state)
