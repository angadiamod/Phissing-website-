"""PhishSentinel backend — hybrid phishing detection + autonomous crawler bot."""
from __future__ import annotations

import asyncio
import logging
import os
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlparse

from dotenv import load_dotenv
from fastapi import APIRouter, BackgroundTasks, FastAPI, HTTPException
from motor.motor_asyncio import AsyncIOMotorClient
from pydantic import BaseModel, Field
from starlette.middleware.cors import CORSMiddleware

from url_features import extract_features
from visual_detector import analyze_visual
import crawler as crawler_mod

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / ".env")

mongo_url = os.environ["MONGO_URL"]
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ["DB_NAME"]]

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s — %(message)s")
logger = logging.getLogger("phishsentinel")

_scheduler = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _scheduler
    try:
        _scheduler = crawler_mod.start_scheduler(db, run_hybrid_scan, interval_minutes=15)
    except Exception:
        logger.exception("Failed to start crawler scheduler")
    yield
    if _scheduler:
        try:
            _scheduler.shutdown(wait=False)
        except Exception:
            pass
    client.close()


app = FastAPI(title="PhishSentinel API", lifespan=lifespan)
api_router = APIRouter(prefix="/api")


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def verdict_label(score: float) -> Literal["SAFE", "SUSPICIOUS", "PHISHING"]:
    if score >= 60:
        return "PHISHING"
    if score >= 30:
        return "SUSPICIOUS"
    return "SAFE"


def host_of(url: str) -> str:
    raw = url.strip()
    if not raw.startswith(("http://", "https://")):
        raw = "http://" + raw
    return (urlparse(raw).hostname or "").lower()


class ScanRequest(BaseModel):
    url: str = Field(min_length=3, max_length=2048)


class ThreatReport(BaseModel):
    url: str = Field(min_length=3, max_length=2048)
    reason: str = Field(min_length=3, max_length=500)
    reporter: str = Field(default="anonymous", max_length=60)


class VoteRequest(BaseModel):
    direction: Literal["up", "down"]


async def run_hybrid_scan(url: str) -> dict[str, Any]:
    """Core scan logic — reused by /api/scan and the crawler."""
    url = url.strip()
    host = host_of(url)
    if not host:
        raise ValueError("Invalid URL")

    url_analysis = extract_features(url)
    ml_score = url_analysis["ml_score"]

    reports = await db.threat_reports.find({"host": host}, {"_id": 0}).to_list(50)
    confirmed = [r for r in reports if r.get("vote_score", 0) > 0]
    if confirmed:
        db_score = min(100.0, 60.0 + 10.0 * len(confirmed))
        db_note = f"Host reported {len(confirmed)}× by community"
    else:
        db_score = 0.0
        db_note = "No community reports for this host"

    try:
        visual = await asyncio.wait_for(analyze_visual(url), timeout=45.0)
    except asyncio.TimeoutError:
        visual = {"cnn_score": 0.0, "cloned_brand": None, "similarity": 0,
                  "suspicious_elements": [], "screenshot_b64": None,
                  "note": "Visual analysis timed out"}
    except Exception as exc:
        logger.exception("Visual analysis failed")
        visual = {"cnn_score": 0.0, "cloned_brand": None, "similarity": 0,
                  "suspicious_elements": [], "screenshot_b64": None,
                  "note": f"error: {type(exc).__name__}"}

    cnn_score = float(visual.get("cnn_score", 0.0))
    visual_available = bool(visual.get("screenshot_b64"))
    if visual_available:
        w_ml, w_cnn, w_db = 0.5, 0.3, 0.2
    else:
        w_ml, w_cnn, w_db = 0.75, 0.0, 0.25
    final = round(ml_score * w_ml + cnn_score * w_cnn + db_score * w_db, 1)

    scan = {
        "id": str(uuid.uuid4()),
        "url": url,
        "host": host,
        "created_at": now_iso(),
        "ml_score": ml_score,
        "cnn_score": cnn_score,
        "db_score": db_score,
        "final_score": final,
        "verdict": verdict_label(final),
        "url_analysis": url_analysis,
        "visual": {
            "cloned_brand": visual.get("cloned_brand"),
            "similarity": visual.get("similarity", 0),
            "suspicious_elements": visual.get("suspicious_elements", []),
            "reasoning": visual.get("reasoning", ""),
            "screenshot_b64": visual.get("screenshot_b64"),
            "note": visual.get("note", ""),
        },
        "threat_intel": {"db_score": db_score, "note": db_note,
                         "matching_reports": len(confirmed)},
    }
    doc = {**scan}
    doc["visual"] = {**scan["visual"], "screenshot_b64": None}
    await db.scans.insert_one(doc)
    return scan


@api_router.get("/")
async def root():
    return {"service": "PhishSentinel", "status": "online", "modules": ["url", "visual", "db", "crawler"]}


@api_router.post("/scan")
async def scan_url(req: ScanRequest) -> dict[str, Any]:
    try:
        return await run_hybrid_scan(req.url)
    except ValueError as e:
        raise HTTPException(400, str(e))


@api_router.get("/scans")
async def list_scans(limit: int = 20):
    return await db.scans.find({}, {
        "_id": 0, "id": 1, "url": 1, "host": 1, "created_at": 1,
        "ml_score": 1, "cnn_score": 1, "db_score": 1,
        "final_score": 1, "verdict": 1,
    }).sort("created_at", -1).to_list(max(1, min(100, limit)))


@api_router.get("/scans/{scan_id}")
async def get_scan(scan_id: str):
    doc = await db.scans.find_one({"id": scan_id}, {"_id": 0})
    if not doc:
        raise HTTPException(404, "Scan not found")
    return doc


@api_router.post("/threats/report")
async def report_threat(req: ThreatReport):
    host = host_of(req.url)
    if not host:
        raise HTTPException(400, "Invalid URL")
    doc = {
        "id": str(uuid.uuid4()), "url": req.url.strip(), "host": host,
        "reason": req.reason.strip(),
        "reporter": req.reporter.strip() or "anonymous",
        "created_at": now_iso(),
        "vote_score": 1, "upvotes": 1, "downvotes": 0,
    }
    await db.threat_reports.insert_one(doc)
    return {k: v for k, v in doc.items() if k != "_id"}


@api_router.get("/threats")
async def list_threats(limit: int = 30):
    return await db.threat_reports.find({}, {"_id": 0}).sort("created_at", -1).to_list(max(1, min(100, limit)))


@api_router.post("/threats/{threat_id}/vote")
async def vote_threat(threat_id: str, req: VoteRequest):
    field = "upvotes" if req.direction == "up" else "downvotes"
    delta = 1 if req.direction == "up" else -1
    result = await db.threat_reports.find_one_and_update(
        {"id": threat_id}, {"$inc": {field: 1, "vote_score": delta}},
        projection={"_id": 0}, return_document=True,
    )
    if not result:
        raise HTTPException(404, "Threat not found")
    return result


@api_router.get("/stats")
async def stats():
    total_scans = await db.scans.count_documents({})
    return {
        "total_scans": total_scans,
        "phishing": await db.scans.count_documents({"verdict": "PHISHING"}),
        "suspicious": await db.scans.count_documents({"verdict": "SUSPICIOUS"}),
        "safe": await db.scans.count_documents({"verdict": "SAFE"}),
        "community_reports": await db.threat_reports.count_documents({}),
        "crawler_findings": await db.crawler_findings.count_documents({}),
    }


# ───────── crawler endpoints ─────────
@api_router.get("/crawler/status")
async def crawler_status():
    state = crawler_mod.get_state()
    return {
        **state,
        "total_findings": await db.crawler_findings.count_documents({}),
        "total_runs": await db.crawler_runs.count_documents({}),
    }


@api_router.get("/crawler/findings")
async def crawler_findings(limit: int = 30):
    return await db.crawler_findings.find({}, {"_id": 0}).sort("discovered_at", -1).to_list(max(1, min(100, limit)))


@api_router.get("/crawler/runs")
async def crawler_runs(limit: int = 15):
    return await db.crawler_runs.find({}, {"_id": 0}).sort("started_at", -1).to_list(max(1, min(50, limit)))


@api_router.post("/crawler/run")
async def crawler_run(background: BackgroundTasks):
    """Trigger a manual crawl cycle in the background."""
    state = crawler_mod.get_state()
    if state.get("active_run"):
        raise HTTPException(409, "Crawler cycle already running")
    background.add_task(crawler_mod.crawl_cycle, db, run_hybrid_scan, True)
    return {"status": "started", "trigger": "manual"}


app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get("CORS_ORIGINS", "*").split(","),
    allow_methods=["*"], allow_headers=["*"],
)
