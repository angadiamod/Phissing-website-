# PhishSentinel PRD

## Problem Statement
PhishSentinel — Zero-Hour Phishing Detection. Hybrid system: URL analysis +
visual cloning + collaborative threat intel + autonomous crawler bot.

## Architecture
- Backend: FastAPI + MongoDB + Gemini 3 Flash vision + APScheduler + websockets
- Frontend: React + Shadcn + Tailwind, JetBrains Mono / IBM Plex Sans, dark terminal aesthetic

## Implemented (Feb–May 2026)
### Phase 1 (Feb 2026)
- 22-feature URL analysis (XGBoost-style non-linear scoring)
- Gemini 3 Flash visual clone detection on live screenshots (mshots)
- Collaborative threat reports + up/down voting → DB score
- Weighted verdict ML·0.5 + CNN·0.3 + DB·0.2; weight redistribution when no screenshot
- Dashboard with traffic-light verdict gauge, 22-feature table, screenshot card,
  Threat Feed + Scan History tabs, Report Threat dialog, stats bar
- 16/16 backend tests pass (iteration_1.json)

### Phase 2 (May 2026) — Autonomous Web Crawler Bot
- /app/backend/crawler.py — APScheduler-based bot, runs every 15 min
- Sources: URLhaus public abuse feed (HTTP) + CertStream live SSL log (WS)
- Filters phishy candidates → runs full hybrid scan → stores findings
- Endpoints: GET /api/crawler/{status,findings,runs}, POST /api/crawler/run
- Frontend: new "🤖 CRAWLER" tab with live status, findings list, cycle history,
  manual "Run Now" button, polling refresh every 8s
- Methodology card updated to 4-layer engine

## Backlog
- P1: Chrome extension wrapper (calls /api/scan)
- P1: Rate limiting on /api/scan + /api/threats/report
- P2: Per-user vote dedupe
- P2: Real XGBoost model trained on PhishTank+Alexa
- P2: Email/Slack alerts when crawler finds PHISHING verdict
- P2: Graph view of related malicious infrastructure (host clusters)
