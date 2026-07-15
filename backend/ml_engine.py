"""ML ensemble engine — trains Random Forest, ExtraTrees, GradientBoost, XGBoost,
LightGBM on a bootstrap dataset, compares accuracy/ROC, saves the best model
plus per-model metrics + feature importance.

The bootstrap dataset is generated from URL features extracted by the
url_features module — phishing URLs from URLhaus (or a seed list) labelled 1,
benign URLs from a curated brand+rank list labelled 0.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import pickle
import random
from pathlib import Path
from typing import Any

import httpx
import numpy as np
from sklearn.ensemble import (
    ExtraTreesClassifier, GradientBoostingClassifier, RandomForestClassifier,
)
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score, f1_score, precision_score, recall_score, roc_auc_score, roc_curve,
)
from sklearn.model_selection import train_test_split
from sklearn.tree import DecisionTreeClassifier

try:
    import xgboost as xgb
    _HAS_XGB = True
except Exception:
    _HAS_XGB = False
try:
    import lightgbm as lgb
    _HAS_LGB = True
except Exception:
    _HAS_LGB = False

from url_features import extract_features

logger = logging.getLogger("ml_engine")

MODEL_DIR = Path(__file__).parent / "models"
MODEL_DIR.mkdir(exist_ok=True)
BEST_MODEL_PATH = MODEL_DIR / "best_model.pkl"
METRICS_PATH = MODEL_DIR / "metrics.json"

URLHAUS = "https://urlhaus.abuse.ch/downloads/text_recent/"

# Benign seed URLs — top brands & news/government/edu
BENIGN_SEED = [
    "https://www.google.com", "https://www.youtube.com", "https://www.facebook.com",
    "https://www.amazon.com", "https://www.wikipedia.org", "https://www.twitter.com",
    "https://www.instagram.com", "https://www.linkedin.com", "https://www.microsoft.com",
    "https://www.apple.com", "https://www.netflix.com", "https://www.github.com",
    "https://www.reddit.com", "https://www.stackoverflow.com", "https://www.bbc.com",
    "https://www.cnn.com", "https://www.nytimes.com", "https://www.theguardian.com",
    "https://www.bloomberg.com", "https://www.wsj.com", "https://www.reuters.com",
    "https://www.harvard.edu", "https://www.mit.edu", "https://www.stanford.edu",
    "https://www.gov.uk", "https://www.usa.gov", "https://www.who.int",
    "https://www.un.org", "https://www.icicibank.com", "https://www.sbi.co.in",
    "https://www.hdfcbank.com", "https://www.flipkart.com", "https://www.amazon.in",
    "https://www.spotify.com", "https://www.dropbox.com", "https://www.adobe.com",
    "https://www.salesforce.com", "https://www.zoom.us", "https://www.slack.com",
    "https://www.notion.so", "https://www.figma.com",
]

# Synthetic phishy seed templates (always present so training works offline)
SYNTHETIC_PHISH = [
    "http://paypal-login-secure.verify-account.tk/signin",
    "http://app1e-icloud-verify.com/login",
    "http://amaz0n-billing.support-update.xyz/cancel?id=12",
    "http://sbi-online-banking.verify-otp.club/login",
    "http://faceb00k-recover-account.tk/auth",
    "http://hdfc-secure-login.xyz/?next=acct",
    "http://192.168.0.55/paypal/signin",
    "http://microsoft-office365-auth.work/login",
    "http://google-account-recovery.gq/verify",
    "http://netflix-billing-update.zip/pay",
    "http://gmail-security-alert.ml/signin",
    "http://wells-fargo-verify.ga/account",
    "http://chase-secure-banking.club/login",
    "http://binance-wallet-restore.top/recover",
    "http://metamask-import-seed.work/auth",
    "http://signin-account-verify.amazon.co.tk/login",
    "http://login.paypa1.com.xn--80akhbyknj4f/v2",
    "http://m1crosoft-helpdesk.support/upgrade",
    "http://verify-instagram-secure.club/auth",
    "http://supportcenter-apple.icloud.zip/v",
]


def _vector(features: list[dict]) -> tuple[list[float], list[str]]:
    """Convert feature list → numeric vector + name index."""
    vec, names = [], []
    for f in features:
        risk = f.get("risk", 0.0)
        names.append(f["name"])
        vec.append(float(risk))
    return vec, names


def _build_xy(samples: list[tuple[str, int]]) -> tuple[np.ndarray, np.ndarray, list[str]]:
    X, y, feature_names = [], [], None
    for url, label in samples:
        try:
            analysis = extract_features(url)
            vec, names = _vector(analysis["features"])
            if feature_names is None:
                feature_names = names
            if names != feature_names:  # rare case: schema drift
                continue
            X.append(vec)
            y.append(label)
        except Exception:
            continue
    return np.array(X), np.array(y), feature_names or []


async def _fetch_urlhaus(limit: int = 200) -> list[str]:
    try:
        async with httpx.AsyncClient(timeout=20.0) as c:
            r = await c.get(URLHAUS)
            if r.status_code != 200:
                return []
            urls = [ln.strip() for ln in r.text.splitlines()
                    if ln.strip() and not ln.startswith("#")]
            random.shuffle(urls)
            return urls[:limit]
    except Exception as e:
        logger.warning(f"URLhaus fetch failed: {e}")
        return []


def _candidates() -> dict[str, Any]:
    classifiers = {
        "DecisionTree": DecisionTreeClassifier(max_depth=10, random_state=42),
        "RandomForest": RandomForestClassifier(n_estimators=200, random_state=42, n_jobs=-1),
        "ExtraTrees": ExtraTreesClassifier(n_estimators=200, random_state=42, n_jobs=-1),
        "GradientBoost": GradientBoostingClassifier(n_estimators=120, random_state=42),
        "LogisticRegression": LogisticRegression(max_iter=500),
    }
    if _HAS_XGB:
        classifiers["XGBoost"] = xgb.XGBClassifier(
            n_estimators=200, max_depth=6, learning_rate=0.1,
            eval_metric="logloss", random_state=42, n_jobs=-1,
        )
    if _HAS_LGB:
        classifiers["LightGBM"] = lgb.LGBMClassifier(
            n_estimators=200, learning_rate=0.1, random_state=42, n_jobs=-1, verbose=-1,
        )
    return classifiers


async def train_all() -> dict:
    """Train every candidate, pick the best by ROC-AUC, persist the winner."""
    phish_urls = await _fetch_urlhaus(150)
    phish_urls.extend(SYNTHETIC_PHISH)
    samples = [(u, 1) for u in phish_urls] + [(u, 0) for u in BENIGN_SEED]
    random.shuffle(samples)

    X, y, feature_names = _build_xy(samples)
    if len(X) < 20 or len(set(y)) < 2:
        logger.warning("Not enough training data")
        return {"error": "insufficient training data", "samples": len(X)}

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=42, stratify=y if len(set(y)) > 1 else None,
    )

    results: list[dict] = []
    fitted: dict[str, Any] = {}
    for name, clf in _candidates().items():
        try:
            clf.fit(X_train, y_train)
            preds = clf.predict(X_test)
            try:
                probs = clf.predict_proba(X_test)[:, 1]
            except Exception:
                probs = preds.astype(float)
            acc = float(accuracy_score(y_test, preds))
            f1 = float(f1_score(y_test, preds, zero_division=0))
            prec = float(precision_score(y_test, preds, zero_division=0))
            rec = float(recall_score(y_test, preds, zero_division=0))
            try:
                auc = float(roc_auc_score(y_test, probs))
            except Exception:
                auc = 0.0
            try:
                fpr, tpr, _ = roc_curve(y_test, probs)
                roc_pts = [{"fpr": round(float(a), 3), "tpr": round(float(b), 3)}
                           for a, b in zip(fpr, tpr)][:60]
            except Exception:
                roc_pts = []
            # Feature importance
            try:
                imp = clf.feature_importances_
            except AttributeError:
                imp = getattr(clf, "coef_", [None])
                if imp is not None and len(imp):
                    imp = np.abs(imp[0])
                else:
                    imp = np.zeros(len(feature_names))
            top_feats = sorted(
                [{"name": feature_names[i], "importance": round(float(imp[i]), 4)}
                 for i in range(len(feature_names))],
                key=lambda x: -x["importance"],
            )[:12]
            results.append({
                "model": name, "accuracy": round(acc, 4), "f1": round(f1, 4),
                "precision": round(prec, 4), "recall": round(rec, 4),
                "roc_auc": round(auc, 4),
                "roc_curve": roc_pts,
                "feature_importance": top_feats,
            })
            fitted[name] = clf
        except Exception as e:
            results.append({"model": name, "error": f"{type(e).__name__}: {e}"})
    results.sort(key=lambda r: r.get("roc_auc", 0.0), reverse=True)
    best = next((r for r in results if "error" not in r), None)
    if best:
        best_name = best["model"]
        with open(BEST_MODEL_PATH, "wb") as f:
            pickle.dump({
                "model": fitted[best_name],
                "feature_names": feature_names,
                "model_name": best_name,
            }, f)
    metrics = {
        "trained_at": __import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat(),
        "n_samples": len(X), "n_features": len(feature_names),
        "best_model": best["model"] if best else None,
        "best_roc_auc": best["roc_auc"] if best else None,
        "results": results,
    }
    with open(METRICS_PATH, "w") as f:
        json.dump(metrics, f, indent=2)
    logger.info(f"ML training done — best: {metrics['best_model']} AUC={metrics['best_roc_auc']}")
    return metrics


def load_best_model():
    if not BEST_MODEL_PATH.exists():
        return None
    try:
        with open(BEST_MODEL_PATH, "rb") as f:
            return pickle.load(f)
    except Exception:
        return None


def load_metrics() -> dict:
    if not METRICS_PATH.exists():
        return {"results": [], "best_model": None}
    try:
        with open(METRICS_PATH) as f:
            return json.load(f)
    except Exception:
        return {"results": [], "best_model": None}


def predict_with_best(features: list[dict]) -> dict | None:
    bundle = load_best_model()
    if not bundle:
        return None
    model = bundle["model"]
    feat_names = bundle["feature_names"]
    by_name = {f["name"]: f.get("risk", 0.0) for f in features}
    vec = [[by_name.get(n, 0.0) for n in feat_names]]
    try:
        probs = model.predict_proba(vec)[0]
        phish_prob = float(probs[1]) if len(probs) > 1 else float(probs[0])
    except Exception:
        try:
            phish_prob = float(model.predict(vec)[0])
        except Exception:
            return None
    return {
        "model_used": bundle["model_name"],
        "phish_probability": round(phish_prob, 4),
        "model_score": round(phish_prob * 100, 1),
    }
