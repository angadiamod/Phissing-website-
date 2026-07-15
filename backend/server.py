"""PhishSentinel V2 backend — enterprise hybrid detection platform."""
from __future__ import annotations

import asyncio
import logging
import os
import secrets
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal, Optional
from urllib.parse import urlparse

from dotenv import load_dotenv

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / ".env")  # must be first

from fastapi import (
    APIRouter, BackgroundTasks, Depends, FastAPI, HTTPException, Request, Response,
)
from motor.motor_asyncio import AsyncIOMotorClient
from pydantic import BaseModel, EmailStr, Field
from starlette.middleware.cors import CORSMiddleware

from url_features import extract_features
from visual_detector import analyze_visual
from network_intel import gather_network_intel, network_risk
from decision_engine import decide
import ml_engine
import crawler as crawler_mod
from auth import (
    clear_failures, create_access_token, create_refresh_token,
    get_current_user, hash_password, is_locked_out, record_failure,
    require_admin, seed_admin, verify_password,
)

mongo_url = os.environ["MONGO_URL"]
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ["DB_NAME"]]

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(name)s — %(message)s")
logger = logging.getLogger("phishsentinel")

_scheduler = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _scheduler
    try:
        await db.users.create_index("email", unique=True)
        await db.scans.create_index("created_at")
        await db.threat_reports.create_index("host")
        await db.crawler_findings.create_index("host", unique=False)
        await seed_admin(db)
        # Train models in the background if none exist yet
        if not ml_engine.BEST_MODEL_PATH.exists():
            asyncio.create_task(ml_engine.train_all())
        _scheduler = crawler_mod.start_scheduler(db, run_hybrid_scan, interval_minutes=15)
    except Exception:
        logger.exception("Startup init failed")
    yield
    if _scheduler:
        try: _scheduler.shutdown(wait=False)
        except Exception: pass
    client.close()


app = FastAPI(title="PhishSentinel V2 API", version="2.0", lifespan=lifespan)
api_router = APIRouter(prefix="/api")


# ─────────────── helpers ───────────────
def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def host_of(url: str) -> str:
    raw = url.strip()
    if not raw.startswith(("http://", "https://")):
        raw = "http://" + raw
    return (urlparse(raw).hostname or "").lower()


async def audit(actor: str, action: str, target: str = "", detail: dict | None = None):
    await db.audit.insert_one({
        "id": str(uuid.uuid4()), "actor": actor, "action": action,
        "target": target, "detail": detail or {}, "at": now_iso(),
    })


# ─────────────── request models ───────────────
class ScanRequest(BaseModel):
    url: str = Field(min_length=3, max_length=2048)
    deep: bool = True


class ThreatReport(BaseModel):
    url: str = Field(min_length=3, max_length=2048)
    reason: str = Field(min_length=3, max_length=500)


class VoteRequest(BaseModel):
    direction: Literal["up", "down"]


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=6, max_length=200)


class RegisterRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=6, max_length=200)
    name: str = Field(min_length=1, max_length=80)


# ─────────────── CORE SCAN ───────────────
async def run_hybrid_scan(url: str, *, deep: bool = True) -> dict[str, Any]:
    url = url.strip()
    host = host_of(url)
    if not host:
        raise ValueError("Invalid URL")

    url_analysis = extract_features(url)
    ml_score = url_analysis["ml_score"]

    # ML model probability + SHAP explanation
    model_pred = ml_engine.predict_with_best(url_analysis["features"])
    model_score = model_pred["model_score"] if model_pred else None
    shap_explanation = ml_engine.explain_prediction(url_analysis["features"])

    # Community DB score
    reports = await db.threat_reports.find({"host": host}, {"_id": 0}).to_list(50)
    confirmed = [r for r in reports if r.get("vote_score", 0) > 0]
    if confirmed:
        db_score = min(100.0, 60.0 + 10.0 * len(confirmed))
        db_note = f"Host reported {len(confirmed)}× by community"
    else:
        db_score = 0.0
        db_note = "No community reports for this host"

    # Crawler intel corroboration
    crawler_hits = await db.crawler_findings.count_documents({"host": host})

    # Visual + Network intel in parallel (heavy)
    visual_task = analyze_visual(url) if deep else asyncio.sleep(0, result={
        "cnn_score": 0.0, "cloned_brand": None, "similarity": 0,
        "suspicious_elements": [], "screenshot_b64": None,
        "note": "Deep scan disabled",
    })
    network_task = gather_network_intel(url) if deep else asyncio.sleep(0, result={})

    try:
        visual = await asyncio.wait_for(visual_task, timeout=45.0)
    except Exception as e:
        visual = {"cnn_score": 0.0, "cloned_brand": None, "similarity": 0,
                  "suspicious_elements": [], "screenshot_b64": None,
                  "note": f"visual error: {type(e).__name__}"}
    try:
        network = await asyncio.wait_for(network_task, timeout=20.0) if deep else {}
    except Exception as e:
        network = {"error": f"{type(e).__name__}"}

    cnn_score = float(visual.get("cnn_score", 0.0))
    visual_available = bool(visual.get("screenshot_b64"))
    net_risk = network_risk(network) if network and not network.get("error") else {"network_score": 0.0, "signals": []}

    decision = decide(
        url=url, ml_score=ml_score, model_score=model_score,
        visual_score=cnn_score, visual_available=visual_available,
        db_score=db_score, crawler_hits=crawler_hits,
        network=network, cloned_brand=visual.get("cloned_brand"),
    )

    scan = {
        "id": str(uuid.uuid4()),
        "url": url, "host": host, "created_at": now_iso(),
        "ml_score": ml_score,
        "model_score": model_score,
        "model_used": model_pred["model_used"] if model_pred else None,
        "cnn_score": cnn_score,
        "db_score": db_score,
        "network_score": net_risk["network_score"],
        "final_score": decision["risk_score"],
        "confidence": decision["confidence"],
        "verdict": decision["verdict"],
        "category": decision["category"],
        "url_analysis": url_analysis,
        "visual": {
            "cloned_brand": visual.get("cloned_brand"),
            "similarity": visual.get("similarity", 0),
            "suspicious_elements": visual.get("suspicious_elements", []),
            "reasoning": visual.get("reasoning", ""),
            "screenshot_b64": visual.get("screenshot_b64"),
            "note": visual.get("note", ""),
        },
        "network": {**network, "signals": net_risk.get("signals", [])},
        "threat_intel": {"db_score": db_score, "note": db_note,
                         "matching_reports": len(confirmed),
                         "crawler_hits": crawler_hits},
        "decision": decision,
        "shap": shap_explanation,
    }
    doc = {**scan}
    # Save the base64 screenshot to a separate collection so the scans list
    # stays lightweight but the evidence is preserved.
    if scan["visual"].get("screenshot_b64"):
        try:
            await db.visual_evidence.insert_one({
                "id": str(uuid.uuid4()),
                "scan_id": scan["id"],
                "url": url,
                "host": host,
                "cloned_brand": scan["visual"].get("cloned_brand"),
                "similarity": scan["visual"].get("similarity", 0),
                "cnn_score": cnn_score,
                "screenshot_b64": scan["visual"]["screenshot_b64"],
                "captured_at": now_iso(),
            })
        except Exception:
            logger.exception("Failed to save visual evidence")
    doc["visual"] = {**scan["visual"], "screenshot_b64": None}
    await db.scans.insert_one(doc)
    return scan


# ─────────────── PUBLIC ROUTES ───────────────
@api_router.get("/")
async def root():
    return {"service": "PhishSentinel", "version": "2.0", "status": "online",
            "modules": ["url_intel", "network_intel", "visual_ai", "threat_db",
                        "crawler", "ml_ensemble", "decision_engine"]}


@api_router.post("/scan")
async def scan_url(req: ScanRequest):
    try:
        return await run_hybrid_scan(req.url, deep=req.deep)
    except ValueError as e:
        raise HTTPException(400, str(e))


@api_router.get("/scans")
async def list_scans(limit: int = 30):
    return await db.scans.find({}, {
        "_id": 0, "id": 1, "url": 1, "host": 1, "created_at": 1,
        "ml_score": 1, "model_score": 1, "cnn_score": 1, "db_score": 1,
        "network_score": 1, "final_score": 1, "verdict": 1,
        "category": 1, "confidence": 1,
    }).sort("created_at", -1).to_list(max(1, min(200, limit)))


@api_router.get("/scans/{scan_id}")
async def get_scan(scan_id: str):
    doc = await db.scans.find_one({"id": scan_id}, {"_id": 0})
    if not doc:
        raise HTTPException(404, "Scan not found")
    return doc


@api_router.get("/threats")
async def list_threats(limit: int = 30):
    return await db.threat_reports.find({}, {"_id": 0}).sort("created_at", -1).to_list(max(1, min(200, limit)))


@api_router.get("/threats/verified")
async def verified_threats(limit: int = 50):
    return await db.threat_reports.find(
        {"verified": True}, {"_id": 0}
    ).sort("verified_at", -1).to_list(max(1, min(200, limit)))


@api_router.post("/threats/report")
async def report_threat(req: ThreatReport, user: dict = Depends(get_current_user)):
    host = host_of(req.url)
    if not host:
        raise HTTPException(400, "Invalid URL")
    doc = {
        "id": str(uuid.uuid4()), "url": req.url.strip(), "host": host,
        "reason": req.reason.strip(),
        "reporter": user["email"], "reporter_id": user["id"],
        "reporter_reputation": user.get("reputation", 10),
        "created_at": now_iso(),
        "vote_score": 1, "upvotes": 1, "downvotes": 0,
        "verified": False, "verified_by": None, "verified_at": None,
    }
    await db.threat_reports.insert_one(doc)
    await audit(user["email"], "threat.report", host)
    return {k: v for k, v in doc.items() if k != "_id"}


@api_router.post("/threats/{threat_id}/vote")
async def vote_threat(threat_id: str, req: VoteRequest,
                      user: dict = Depends(get_current_user)):
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
    return {
        "total_scans": await db.scans.count_documents({}),
        "phishing": await db.scans.count_documents({"verdict": "PHISHING"}),
        "suspicious": await db.scans.count_documents({"verdict": "SUSPICIOUS"}),
        "safe": await db.scans.count_documents({"verdict": "SAFE"}),
        "community_reports": await db.threat_reports.count_documents({}),
        "verified_threats": await db.threat_reports.count_documents({"verified": True}),
        "crawler_findings": await db.crawler_findings.count_documents({}),
        "users": await db.users.count_documents({}),
    }


# ─────────────── ANALYTICS ───────────────
@api_router.get("/analytics/timeseries")
async def analytics_timeseries(days: int = 7):
    """Verdict breakdown over the last N days."""
    from collections import defaultdict
    cutoff = (datetime.now(timezone.utc) - __import__("datetime").timedelta(days=days)).isoformat()
    docs = await db.scans.find(
        {"created_at": {"$gte": cutoff}},
        {"_id": 0, "created_at": 1, "verdict": 1, "final_score": 1, "category": 1},
    ).to_list(5000)
    buckets: dict = defaultdict(lambda: {"SAFE": 0, "SUSPICIOUS": 0, "PHISHING": 0, "avg_score_sum": 0.0, "count": 0})
    for d in docs:
        day = d["created_at"][:10]
        buckets[day][d.get("verdict", "SAFE")] += 1
        buckets[day]["avg_score_sum"] += d.get("final_score", 0)
        buckets[day]["count"] += 1
    series = []
    for day in sorted(buckets.keys()):
        b = buckets[day]
        avg = round(b["avg_score_sum"] / b["count"], 1) if b["count"] else 0
        series.append({
            "date": day, "SAFE": b["SAFE"], "SUSPICIOUS": b["SUSPICIOUS"],
            "PHISHING": b["PHISHING"], "avg_score": avg,
        })
    return {"days": days, "series": series}


@api_router.get("/analytics/categories")
async def analytics_categories():
    pipeline = [{"$group": {"_id": "$category", "count": {"$sum": 1}}}]
    return [{"category": d["_id"] or "unknown", "count": d["count"]}
            async for d in db.scans.aggregate(pipeline)]


@api_router.get("/analytics/top-hosts")
async def analytics_top_hosts(limit: int = 10):
    pipeline = [
        {"$match": {"verdict": {"$in": ["PHISHING", "SUSPICIOUS"]}}},
        {"$group": {"_id": "$host", "count": {"$sum": 1},
                    "avg_score": {"$avg": "$final_score"}}},
        {"$sort": {"count": -1}},
        {"$limit": limit},
    ]
    return [{"host": d["_id"], "count": d["count"],
             "avg_score": round(d["avg_score"], 1)}
            async for d in db.scans.aggregate(pipeline)]


@api_router.get("/intel/feed")
async def intel_feed(limit: int = 50):
    crawler = await db.crawler_findings.find(
        {}, {"_id": 0, "scan_id": 0}
    ).sort("discovered_at", -1).to_list(max(1, min(200, limit)))
    community = await db.threat_reports.find(
        {"vote_score": {"$gte": 1}, "verified": True},
        {"_id": 0},
    ).sort("verified_at", -1).to_list(max(1, min(200, limit)))
    return {"generated_at": now_iso(),
            "crawler_findings": crawler,
            "verified_reports": community}


# ─────────────── CRAWLER ───────────────
@api_router.get("/crawler/status")
async def crawler_status():
    state = crawler_mod.get_state()
    return {**state,
            "total_findings": await db.crawler_findings.count_documents({}),
            "total_runs": await db.crawler_runs.count_documents({})}


@api_router.get("/crawler/findings")
async def crawler_findings(limit: int = 30):
    return await db.crawler_findings.find({}, {"_id": 0}).sort("discovered_at", -1).to_list(max(1, min(200, limit)))


@api_router.get("/crawler/runs")
async def crawler_runs(limit: int = 15):
    return await db.crawler_runs.find({}, {"_id": 0}).sort("started_at", -1).to_list(max(1, min(50, limit)))


@api_router.post("/crawler/run")
async def crawler_run(background: BackgroundTasks,
                      user: dict = Depends(get_current_user)):
    if crawler_mod.get_state().get("active_run"):
        raise HTTPException(409, "Crawler cycle already running")
    background.add_task(crawler_mod.crawl_cycle, db, run_hybrid_scan, True)
    await audit(user["email"], "crawler.run")
    return {"status": "started", "trigger": "manual"}


# ─────────────── MODEL METRICS ───────────────
@api_router.get("/models/metrics")
async def models_metrics():
    return ml_engine.load_metrics()


@api_router.post("/models/retrain")
async def models_retrain(background: BackgroundTasks,
                         admin: dict = Depends(require_admin)):
    background.add_task(ml_engine.train_all)
    await audit(admin["email"], "models.retrain")
    return {"status": "training started"}


# ─────────────── AUTH ───────────────
def _set_auth_cookies(resp: Response, access: str, refresh: str):
    resp.set_cookie("access_token", access, httponly=True, secure=True,
                    samesite="none", max_age=60 * 60 * 12, path="/")
    resp.set_cookie("refresh_token", refresh, httponly=True, secure=True,
                    samesite="none", max_age=60 * 60 * 24 * 7, path="/")


@api_router.post("/auth/register")
async def register(req: RegisterRequest, response: Response):
    email = req.email.lower()
    if await db.users.find_one({"email": email}):
        raise HTTPException(409, "Email already registered")
    user = {
        "id": secrets.token_urlsafe(12),
        "email": email, "name": req.name, "role": "user",
        "password_hash": hash_password(req.password),
        "reputation": 10, "created_at": now_iso(),
    }
    await db.users.insert_one(user)
    access = create_access_token(user["id"], email, "user")
    refresh = create_refresh_token(user["id"])
    _set_auth_cookies(response, access, refresh)
    return {"id": user["id"], "email": email, "name": req.name, "role": "user",
            "token": access}


@api_router.post("/auth/login")
async def login(req: LoginRequest, request: Request, response: Response):
    ident = f"{request.client.host if request.client else 'unknown'}:{req.email.lower()}"
    if await is_locked_out(db, ident):
        raise HTTPException(429, "Too many failed attempts — try again in 15 min")
    user = await db.users.find_one({"email": req.email.lower()})
    if not user or not verify_password(req.password, user["password_hash"]):
        await record_failure(db, ident)
        raise HTTPException(401, "Invalid credentials")
    await clear_failures(db, ident)
    access = create_access_token(user["id"], user["email"], user.get("role", "user"))
    refresh = create_refresh_token(user["id"])
    _set_auth_cookies(response, access, refresh)
    await audit(user["email"], "auth.login")
    return {"id": user["id"], "email": user["email"], "name": user.get("name"),
            "role": user.get("role", "user"), "token": access}


@api_router.post("/auth/logout")
async def logout(response: Response):
    response.delete_cookie("access_token", path="/")
    response.delete_cookie("refresh_token", path="/")
    return {"ok": True}


@api_router.get("/auth/me")
async def me(user: dict = Depends(get_current_user)):
    return user


# ─────────────── ADMIN ───────────────
@api_router.get("/admin/users")
async def admin_list_users(admin: dict = Depends(require_admin)):
    return await db.users.find({}, {"_id": 0, "password_hash": 0}).sort("created_at", -1).to_list(500)


@api_router.post("/admin/users/{user_id}/role")
async def admin_set_role(user_id: str, role: Literal["user", "admin"],
                         admin: dict = Depends(require_admin)):
    res = await db.users.find_one_and_update(
        {"id": user_id}, {"$set": {"role": role}},
        projection={"_id": 0, "password_hash": 0}, return_document=True,
    )
    if not res:
        raise HTTPException(404, "User not found")
    await audit(admin["email"], "admin.role_change", user_id, {"role": role})
    return res


@api_router.delete("/admin/users/{user_id}")
async def admin_delete_user(user_id: str, admin: dict = Depends(require_admin)):
    if user_id == admin["id"]:
        raise HTTPException(400, "Cannot delete yourself")
    await db.users.delete_one({"id": user_id})
    await audit(admin["email"], "admin.user_delete", user_id)
    return {"ok": True}


@api_router.post("/admin/threats/{threat_id}/verify")
async def admin_verify_threat(threat_id: str, admin: dict = Depends(require_admin)):
    result = await db.threat_reports.find_one_and_update(
        {"id": threat_id},
        {"$set": {"verified": True, "verified_by": admin["email"],
                  "verified_at": now_iso()}},
        projection={"_id": 0}, return_document=True,
    )
    if not result:
        raise HTTPException(404, "Threat not found")
    await audit(admin["email"], "admin.threat_verify", threat_id)
    return result


@api_router.get("/admin/audit")
async def admin_audit(limit: int = 100, admin: dict = Depends(require_admin)):
    return await db.audit.find({}, {"_id": 0}).sort("at", -1).to_list(max(1, min(500, limit)))


# ─────────────── PUBLIC SHAREABLE VERDICT ───────────────
@api_router.get("/public/verdict/{scan_id}")
async def public_verdict(scan_id: str):
    """Sanitized, no-auth verdict for shareable /v/{scan_id} links."""
    doc = await db.scans.find_one({"id": scan_id}, {
        "_id": 0, "id": 1, "url": 1, "host": 1, "created_at": 1,
        "ml_score": 1, "model_score": 1, "model_used": 1, "cnn_score": 1,
        "db_score": 1, "network_score": 1, "final_score": 1,
        "verdict": 1, "confidence": 1, "category": 1,
        "visual.cloned_brand": 1, "visual.similarity": 1,
        "shap.model": 1, "shap.contributions": 1, "shap.phish_probability": 1,
    })
    if not doc:
        raise HTTPException(404, "Verdict not found")
    return doc


@api_router.get("/scans/{scan_id}/explain")
async def explain_scan(scan_id: str):
    """On-demand SHAP explanation for older scans that lack a stored one."""
    doc = await db.scans.find_one({"id": scan_id}, {"_id": 0})
    if not doc:
        raise HTTPException(404, "Scan not found")
    if doc.get("shap"):
        return doc["shap"]
    features = (doc.get("url_analysis") or {}).get("features") or []
    if not features:
        raise HTTPException(404, "No features stored for this scan")
    explanation = ml_engine.explain_prediction(features)
    if not explanation:
        raise HTTPException(503, "Explainer unavailable")
    await db.scans.update_one({"id": scan_id}, {"$set": {"shap": explanation}})
    return explanation


# ─────────────── VISUAL EVIDENCE (Layer 2 collection) ───────────────
@api_router.get("/visual/evidence")
async def visual_evidence(limit: int = 30):
    """Public read-only feed of screenshots captured by Layer 2."""
    docs = await db.visual_evidence.find(
        {}, {"_id": 0, "screenshot_b64": 0}
    ).sort("captured_at", -1).to_list(max(1, min(100, limit)))
    return {
        "total": await db.visual_evidence.count_documents({}),
        "items": docs,
    }


@api_router.get("/visual/evidence/{evidence_id}")
async def visual_evidence_detail(evidence_id: str):
    doc = await db.visual_evidence.find_one({"id": evidence_id}, {"_id": 0})
    if not doc:
        raise HTTPException(404, "Evidence not found")
    return doc


@api_router.get("/visual/by-scan/{scan_id}")
async def visual_by_scan(scan_id: str):
    doc = await db.visual_evidence.find_one({"scan_id": scan_id}, {"_id": 0})
    if not doc:
        raise HTTPException(404, "No visual evidence for this scan")
    return doc


app.include_router(api_router)
app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get("CORS_ORIGINS", "*").split(","),
    allow_methods=["*"], allow_headers=["*"],
)
