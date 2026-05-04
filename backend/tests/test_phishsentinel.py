"""PhishSentinel backend API tests."""
import os
import time
import pytest
import requests

BASE_URL = os.environ.get("REACT_APP_BACKEND_URL", "https://smart-share-hub-2.preview.emergentagent.com").rstrip("/")
API = f"{BASE_URL}/api"
TIMEOUT = 90  # /api/scan can take up to ~60s due to mshots screenshot


@pytest.fixture(scope="module")
def session():
    s = requests.Session()
    s.headers.update({"Content-Type": "application/json"})
    return s


# ───────── Health ─────────
def test_root(session):
    r = session.get(f"{API}/", timeout=15)
    assert r.status_code == 200
    data = r.json()
    assert data["service"] == "PhishSentinel"
    assert data["status"] == "online"


# ───────── Scan ─────────
@pytest.fixture(scope="module")
def phishy_scan(session):
    payload = {"url": "http://paypal-login-secure.verify-account.tk/signin?id=1"}
    r = session.post(f"{API}/scan", json=payload, timeout=TIMEOUT)
    assert r.status_code == 200, r.text
    return r.json()


def test_scan_phishy_structure(phishy_scan):
    d = phishy_scan
    for key in ["id", "url", "host", "ml_score", "cnn_score", "db_score",
                "final_score", "verdict", "url_analysis", "visual", "threat_intel"]:
        assert key in d, f"Missing: {key}"
    assert "features" in d["url_analysis"]
    assert len(d["url_analysis"]["features"]) == 22
    assert d["verdict"] in ("SAFE", "SUSPICIOUS", "PHISHING")
    # Phishy URL should at least be SUSPICIOUS or PHISHING and have ml_score elevated
    assert d["ml_score"] >= 30, f"ml_score too low for obvious phishy URL: {d['ml_score']}"
    assert d["verdict"] in ("SUSPICIOUS", "PHISHING")


def test_scan_weight_redistribution(phishy_scan):
    """If no screenshot, final = ml*0.75 + db*0.25."""
    d = phishy_scan
    if not d["visual"].get("screenshot_b64"):
        expected = round(d["ml_score"] * 0.75 + d["db_score"] * 0.25, 1)
        assert abs(d["final_score"] - expected) < 0.2, \
            f"weight redistribution mismatch: got {d['final_score']} expected {expected}"
    else:
        expected = round(d["ml_score"] * 0.5 + d["cnn_score"] * 0.3 + d["db_score"] * 0.2, 1)
        assert abs(d["final_score"] - expected) < 0.2, \
            f"weighted formula mismatch: got {d['final_score']} expected {expected}"


def test_scan_legitimate(session):
    r = session.post(f"{API}/scan", json={"url": "https://www.google.com"}, timeout=TIMEOUT)
    assert r.status_code == 200, r.text
    d = r.json()
    assert d["ml_score"] < 40, f"google.com ml_score too high: {d['ml_score']}"
    # Without DB reports and possibly no screenshot, verdict should be SAFE
    assert d["verdict"] in ("SAFE", "SUSPICIOUS"), d["verdict"]


def test_scan_malformed(session):
    r = session.post(f"{API}/scan", json={"url": "://"}, timeout=15)
    # Should reject - either 400 (host empty) or 422 (validation)
    assert r.status_code in (400, 422), f"got {r.status_code}: {r.text}"


# ───────── Scans listing ─────────
def test_list_scans_no_id(session, phishy_scan):
    r = session.get(f"{API}/scans?limit=10", timeout=15)
    assert r.status_code == 200
    docs = r.json()
    assert isinstance(docs, list)
    assert len(docs) >= 1
    for doc in docs:
        assert "_id" not in doc
        assert "id" in doc
        assert "url" in doc
        assert "verdict" in doc


def test_get_scan_by_id(session, phishy_scan):
    sid = phishy_scan["id"]
    r = session.get(f"{API}/scans/{sid}", timeout=15)
    assert r.status_code == 200
    d = r.json()
    assert d["id"] == sid
    assert "_id" not in d


def test_get_scan_404(session):
    r = session.get(f"{API}/scans/nonexistent-id-xyz", timeout=15)
    assert r.status_code == 404


# ───────── Threats ─────────
@pytest.fixture(scope="module")
def threat_report(session):
    payload = {
        "url": "http://TEST-evilsite-phishtest.example/login",
        "reason": "TEST_reported phishing site for community intel",
        "reporter": "TEST_pytest",
    }
    r = session.post(f"{API}/threats/report", json=payload, timeout=15)
    assert r.status_code == 200, r.text
    return r.json()


def test_threat_report_structure(threat_report):
    d = threat_report
    assert "id" in d
    assert d["vote_score"] == 1
    assert d["upvotes"] == 1
    assert d["downvotes"] == 0
    assert "_id" not in d


def test_list_threats(session, threat_report):
    r = session.get(f"{API}/threats?limit=30", timeout=15)
    assert r.status_code == 200
    docs = r.json()
    assert any(t["id"] == threat_report["id"] for t in docs)
    for doc in docs:
        assert "_id" not in doc


def test_threat_vote_up(session, threat_report):
    tid = threat_report["id"]
    r = session.post(f"{API}/threats/{tid}/vote", json={"direction": "up"}, timeout=15)
    assert r.status_code == 200
    d = r.json()
    assert d["upvotes"] == 2
    assert d["vote_score"] == 2


def test_threat_vote_down(session, threat_report):
    tid = threat_report["id"]
    r = session.post(f"{API}/threats/{tid}/vote", json={"direction": "down"}, timeout=15)
    assert r.status_code == 200
    d = r.json()
    assert d["downvotes"] == 1
    # vote_score was 2 after upvote, now 2-1=1
    assert d["vote_score"] == 1


def test_threat_vote_invalid_direction(session, threat_report):
    tid = threat_report["id"]
    r = session.post(f"{API}/threats/{tid}/vote", json={"direction": "sideways"}, timeout=15)
    assert r.status_code == 422


def test_threat_vote_404(session):
    r = session.post(f"{API}/threats/nonexistent-tid/vote", json={"direction": "up"}, timeout=15)
    assert r.status_code == 404


# ───────── DB score after threat report ─────────
def test_scan_db_score_after_report(session):
    """Reporting a host should bump db_score on subsequent scan of same host."""
    test_host_url = "http://TEST-dbscore-target-uniq.example/x"
    # Report the host
    rep = session.post(f"{API}/threats/report", json={
        "url": test_host_url,
        "reason": "TEST_db_score signal check",
        "reporter": "TEST_pytest",
    }, timeout=15)
    assert rep.status_code == 200
    time.sleep(0.5)
    # Scan same host
    r = session.post(f"{API}/scan", json={"url": test_host_url}, timeout=TIMEOUT)
    assert r.status_code == 200, r.text
    d = r.json()
    # Formula: 60 + 10*count, with at least 1 confirmed report
    assert d["db_score"] >= 60.0, f"expected db_score>=60, got {d['db_score']}"
    assert d["threat_intel"]["matching_reports"] >= 1


# ───────── Stats ─────────
def test_stats(session, phishy_scan, threat_report):
    r = session.get(f"{API}/stats", timeout=15)
    assert r.status_code == 200
    d = r.json()
    for key in ["total_scans", "phishing", "suspicious", "safe", "community_reports"]:
        assert key in d
        assert isinstance(d[key], int)
    assert d["total_scans"] >= 1
    assert d["community_reports"] >= 1
