"""Autonomous Threat-Hunting Bot — polls multiple public phishing feeds
(URLhaus, OpenPhish, PhishTank), CertStream SSL log, and any newly
observed domain gets pushed through the full hybrid scan pipeline."""
from __future__ import annotations

import asyncio
import json
import logging
import random
import uuid
from datetime import datetime, timezone

import httpx
import websockets
from apscheduler.schedulers.asyncio import AsyncIOScheduler

from url_features import extract_features

logger = logging.getLogger("crawler")

FEEDS = {
    "urlhaus":  "https://urlhaus.abuse.ch/downloads/text_recent/",
    "openphish": "https://openphish.com/feed.txt",
    "phishtank": "http://data.phishtank.com/data/online-valid.json",
}
CERTSTREAM_WS = "wss://certstream.calidog.io"

PHISHY_KEYWORDS = [
    "login", "verify", "secure", "account", "bank", "wallet", "signin", "auth",
    "paypal", "apple", "icloud", "amazon", "google", "microsoft", "office",
    "sbi", "hdfc", "icici", "axis", "netflix", "facebook", "instagram",
    "whatsapp", "binance", "metamask", "crypto",
]

_state = {
    "running": False,
    "last_run": None,
    "next_run": None,
    "interval_minutes": 15,
    "active_run": None,
    "feed_status": {},
}


def _is_phishy(s: str) -> bool:
    s = s.lower()
    return any(k in s for k in PHISHY_KEYWORDS)


async def _fetch_feed(name: str, url: str, limit: int) -> list[str]:
    try:
        async with httpx.AsyncClient(timeout=20.0, follow_redirects=True) as c:
            r = await c.get(url, headers={"User-Agent": "PhishSentinel/2.0"})
            if r.status_code != 200:
                _state["feed_status"][name] = f"HTTP {r.status_code}"
                return []
            if name == "phishtank":
                try:
                    data = r.json()
                    urls = [item["url"] for item in data if isinstance(item, dict) and item.get("url")]
                except Exception:
                    urls = []
            else:
                urls = [ln.strip() for ln in r.text.splitlines()
                        if ln.strip() and not ln.startswith("#")]
            _state["feed_status"][name] = f"ok · {len(urls)} entries"
            random.shuffle(urls)
            return urls[:limit]
    except Exception as e:
        _state["feed_status"][name] = f"error: {type(e).__name__}"
        return []


async def _sample_certstream(seconds: float = 10.0, max_hits: int = 15) -> list[str]:
    hits: list[str] = []
    try:
        async with websockets.connect(CERTSTREAM_WS, ping_interval=None,
                                      open_timeout=6, close_timeout=2) as ws:
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
        _state["feed_status"]["certstream"] = f"ok · {len(hits)} phishy domains"
    except Exception as e:
        _state["feed_status"]["certstream"] = f"error: {type(e).__name__}"
    return hits


async def crawl_cycle(db, hybrid_scan_fn, manual: bool = False) -> dict:
    run_id = str(uuid.uuid4())
    started = datetime.now(timezone.utc).isoformat()
    _state["active_run"] = run_id

    urlhaus, openphish, phishtank, cert_hits = await asyncio.gather(
        _fetch_feed("urlhaus", FEEDS["urlhaus"], 40),
        _fetch_feed("openphish", FEEDS["openphish"], 40),
        _fetch_feed("phishtank", FEEDS["phishtank"], 40),
        _sample_certstream(10.0, 15),
    )

    candidates: list[tuple[str, str]] = (
        [(u, "urlhaus") for u in urlhaus]
        + [(u, "openphish") for u in openphish]
        + [(u, "phishtank") for u in phishtank]
        + [(u, "certstream") for u in cert_hits]
    )

    # De-dupe by host
    seen = set()
    deduped: list[tuple[str, str]] = []
    for url, src in candidates:
        try:
            host = url.split("/")[2] if "://" in url else url.split("/")[0]
        except IndexError:
            continue
        if host in seen:
            continue
        seen.add(host)
        deduped.append((url, src))
    deduped = deduped[:8]  # bound per-cycle work

    findings = []
    for url, source in deduped:
        try:
            scan = await asyncio.wait_for(hybrid_scan_fn(url), timeout=70.0)
        except Exception as e:
            logger.warning(f"Crawler scan failed {url}: {e}")
            continue
        # URLhaus/OpenPhish/PhishTank are pre-confirmed abuse → always store
        # CertStream needs a score threshold
        if source == "certstream" and scan.get("final_score", 0) < 25:
            continue
        host = scan["host"]
        if await db.crawler_findings.find_one({"host": host}, {"_id": 0}):
            continue
        finding = {
            "id": str(uuid.uuid4()),
            "url": url,
            "host": host,
            "ml_score": scan.get("ml_score", 0),
            "model_score": scan.get("model_score"),
            "cnn_score": scan.get("cnn_score", 0),
            "db_score": scan.get("db_score", 0),
            "network_score": scan.get("network_score", 0),
            "final_score": scan.get("final_score", 0),
            "verdict": scan.get("verdict", "SUSPICIOUS"),
            "category": scan.get("category", "unknown"),
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
        "sources": {
            "urlhaus": len(urlhaus), "openphish": len(openphish),
            "phishtank": len(phishtank), "certstream": len(cert_hits),
        },
    }
    await db.crawler_runs.insert_one(summary)
    _state["last_run"] = finished
    _state["active_run"] = None
    logger.info(f"Crawler cycle done: {len(deduped)} scanned, {len(findings)} findings")
    return summary


def start_scheduler(db, hybrid_scan_fn, interval_minutes: int = 15):
    sched = AsyncIOScheduler()

    async def _job():
        try:
            await crawl_cycle(db, hybrid_scan_fn)
            jobs = sched.get_jobs()
            if jobs:
                _state["next_run"] = jobs[0].next_run_time.isoformat()
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
