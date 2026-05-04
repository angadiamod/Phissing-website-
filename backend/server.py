"""PhishSentinel backend — hybrid phishing detection API."""
from __future__ import annotations

import logging
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlparse

from dotenv import load_dotenv
from fastapi import APIRouter, FastAPI, HTTPException
from motor.motor_asyncio import AsyncIOMotorClient
from pydantic import BaseModel, Field
from starlette.middleware.cors import CORSMiddleware

from url_features import extract_features
from visual_detector import analyze_visual

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / ".env")

mongo_url = os.environ["MONGO_URL"]
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ["DB_NAME"]]

app = FastAPI(title="PhishSentinel API")
api_router = APIRouter(prefix="/api")

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s — %(message)s")
logger = logging.getLogger("phishsentinel")


# ───────── helpers ─────────
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


# ───────── models ─────────
class ScanRequest(BaseModel):
    url: str = Field(min_length=3, max_length=2048)


class ThreatReport(BaseModel):
    url: str = Field(min_length=3, max_length=2048)
    reason: str = Field(min_length=3, max_length=500)
    reporter: str = Field(default="anonymous", max_length=60)


class VoteRequest(BaseModel):
    direction: Literal["up", "down"]


# ───────── routes ─────────
@api_router.get("/")
async def root():
    return {"service": "PhishSentinel", "status": "online"}


@api_router.post("/scan")
async def scan_url(req: ScanRequest) -> dict[str, Any]:
    url = req.url.strip()
    host = host_of(url)
    if not host:
        raise HTTPException(400, "Invalid URL")

    # 1. URL feature analysis
    url_analysis = extract_features(url)
    ml_score = url_analysis["ml_score"]

    # 2. Collaborative threat-intel DB lookup
    reports = await db.threat_reports.find(
        {"host": host}, {"_id": 0}
    ).to_list(50)
    confirmed = [r for r in reports if r.get("vote_score", 0) >= 0]
    if confirmed:
        db_score = min(100.0, 60.0 + 10.0 * len(confirmed))
        db_note = f"Host reported {len(confirmed)}× by community"
    else:
        db_score = 0.0
        db_note = "No community reports for this host"

    # 3. Visual cloning
    try:
        visual = await analyze_visual(url)
    except Exception as exc:
        logger.exception("Visual analysis failed")
        visual = {
            "cnn_score": 0.0, "cloned_brand": None, "similarity": 0,
            "suspicious_elements": [], "screenshot_b64": None,
            "note": f"error: {type(exc).__name__}",
        }
    cnn_score = float(visual.get("cnn_score", 0.0))
    visual_available = bool(visual.get("screenshot_b64"))

    # Weighted final score — redistribute CNN weight to ML when no screenshot was analysed
    if visual_available:
        w_ml, w_cnn, w_db = 0.5, 0.3, 0.2
    else:
        w_ml, w_cnn, w_db = 0.75, 0.0, 0.25
    final = round(ml_score * w_ml + cnn_score * w_cnn + db_score * w_db, 1)
    verdict = verdict_label(final)

    scan = {
        "id": str(uuid.uuid4()),
        "url": url,
        "host": host,
        "created_at": now_iso(),
        "ml_score": ml_score,
        "cnn_score": cnn_score,
        "db_score": db_score,
        "final_score": final,
        "verdict": verdict,
        "url_analysis": url_analysis,
        "visual": {
            "cloned_brand": visual.get("cloned_brand"),
            "similarity": visual.get("similarity", 0),
            "suspicious_elements": visual.get("suspicious_elements", []),
            "reasoning": visual.get("reasoning", ""),
            "screenshot_b64": visual.get("screenshot_b64"),
            "note": visual.get("note", ""),
        },
        "threat_intel": {
            "db_score": db_score,
            "note": db_note,
            "matching_reports": len(confirmed),
        },
    }

    # Persist (omit the big base64 screenshot in the doc to keep history small)
    doc = {**scan}
    doc["visual"] = {**scan["visual"], "screenshot_b64": None}
    await db.scans.insert_one(doc)

    return scan


@api_router.get("/scans")
async def list_scans(limit: int = 20) -> list[dict[str, Any]]:
    docs = await db.scans.find(
        {},
        {
            "_id": 0, "id": 1, "url": 1, "host": 1, "created_at": 1,
            "ml_score": 1, "cnn_score": 1, "db_score": 1,
            "final_score": 1, "verdict": 1,
        },
    ).sort("created_at", -1).to_list(max(1, min(100, limit)))
    return docs


@api_router.get("/scans/{scan_id}")
async def get_scan(scan_id: str) -> dict[str, Any]:
    doc = await db.scans.find_one({"id": scan_id}, {"_id": 0})
    if not doc:
        raise HTTPException(404, "Scan not found")
    return doc


@api_router.post("/threats/report")
async def report_threat(req: ThreatReport) -> dict[str, Any]:
    host = host_of(req.url)
    if not host:
        raise HTTPException(400, "Invalid URL")
    doc = {
        "id": str(uuid.uuid4()),
        "url": req.url.strip(),
        "host": host,
        "reason": req.reason.strip(),
        "reporter": req.reporter.strip() or "anonymous",
        "created_at": now_iso(),
        "vote_score": 1,
        "upvotes": 1,
        "downvotes": 0,
    }
    await db.threat_reports.insert_one(doc)
    return {k: v for k, v in doc.items() if k != "_id"}


@api_router.get("/threats")
async def list_threats(limit: int = 30) -> list[dict[str, Any]]:
    docs = await db.threat_reports.find(
        {}, {"_id": 0}
    ).sort("created_at", -1).to_list(max(1, min(100, limit)))
    return docs


@api_router.post("/threats/{threat_id}/vote")
async def vote_threat(threat_id: str, req: VoteRequest) -> dict[str, Any]:
    field = "upvotes" if req.direction == "up" else "downvotes"
    delta = 1 if req.direction == "up" else -1
    result = await db.threat_reports.find_one_and_update(
        {"id": threat_id},
        {"$inc": {field: 1, "vote_score": delta}},
        projection={"_id": 0},
        return_document=True,
    )
    if not result:
        raise HTTPException(404, "Threat not found")
    return result


@api_router.get("/stats")
async def stats() -> dict[str, Any]:
    total_scans = await db.scans.count_documents({})
    phishing = await db.scans.count_documents({"verdict": "PHISHING"})
    suspicious = await db.scans.count_documents({"verdict": "SUSPICIOUS"})
    safe = await db.scans.count_documents({"verdict": "SAFE"})
    reports = await db.threat_reports.count_documents({})

    pipeline = [
        {"$group": {"_id": "$verdict", "avg": {"$avg": "$final_score"}}}
    ]
    verdict_avgs = {d["_id"]: round(d["avg"], 1) async for d in db.scans.aggregate(pipeline)}

    return {
        "total_scans": total_scans,
        "phishing": phishing,
        "suspicious": suspicious,
        "safe": safe,
        "community_reports": reports,
        "verdict_avg_scores": verdict_avgs,
    }


app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get("CORS_ORIGINS", "*").split(","),
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("shutdown")
async def shutdown_db_client() -> None:
    client.close()
