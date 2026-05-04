# PhishSentinel — Zero-Hour Phishing Detection Console

## Problem Statement (from user + PPT)
Build URL analysis, visual cloning, and collaborative threat intelligence modules for a hybrid
phishing detector as described in the user's PPT ("PhishSentinel: Zero-Hour Phishing Detection
Using Autonomous Web Crawling, XGBoost and CNN Visual Analysis"). PPT specs: 22 URL features,
CNN visual clone detection, shared DB, weighted verdict ML·0.5 + CNN·0.3 + DB·0.2, labels
SAFE 0-29 / SUSPICIOUS 30-59 / PHISHING 60-100.

## Architecture
- Backend: FastAPI (was Flask in PPT) + MongoDB (was SQLite in PPT) + Gemini 3 Flash vision
  via Emergent Universal LLM Key + mshots WordPress public screenshot service
- Frontend: React + Shadcn + Tailwind, JetBrains Mono / IBM Plex Sans, dark terminal aesthetic

## Implemented (Feb 2026)
- POST /api/scan — runs 22-feature URL analysis + vision clone detection + DB lookup, weighted verdict
- URL features: length, entropy, TLD rep, HTTPS, IP host, punycode, brand keywords, special chars, hyphens, subdomain depth, digit ratio, etc. (22 total)
- Non-linear ML score curve (XGBoost-like) — few strong signals drive a high score
- Weight redistribution when screenshot unavailable: ML 0.75 / DB 0.25
- Visual clone analysis via Gemini 3 Flash on live mshots screenshot (cloned_brand, similarity 0-100, suspicious_elements, reasoning)
- Community threat reports + up/down voting; host-level reputation feeds DB score (60+10×confirmed)
- GET /api/scans, /api/scans/{id}, /api/threats, POST /api/threats/report, POST /api/threats/{id}/vote, GET /api/stats
- 45s timeout guard on visual analysis to bound /api/scan latency
- Dashboard: scanner hero with ">_" caret input, scanning progress bar, traffic-light verdict gauge, 3-column score breakdown, 22-feature analysis table, visual clone card with screenshot, tabbed Threat Feed + Scan History, stats bar, methodology sidebar, Report Threat dialog
- All interactive elements have data-testid attributes
- Verified: 16/16 backend tests pass (iteration_1.json)

## User Personas
- Security analyst / SOC operator scanning suspicious URLs
- End-user checking a received link before clicking
- Community reporters feeding the collaborative threat DB

## Backlog / Next
- P1: Add Chrome extension packaging (mentioned in PPT) — calls /api/scan
- P1: Rate limiting on /api/scan and /api/threats/report
- P2: Per-user vote dedupe to stop vote stacking
- P2: Real XGBoost model trained on PhishTank+Alexa dataset (currently XGBoost-style heuristic)
- P2: Trigger auto web crawler (CertStream) for new-domain monitoring (PPT future-work)
- P2: Export verdict as JSON report / PDF for SOC workflows
