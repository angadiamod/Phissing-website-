# PhishSentinel Setup Guide

This project has two parts:

- Backend: Python/FastAPI service in `backend/`
- Frontend: React app in `frontend/`

You must run both services for the app to work.

## Requirements

- Python 3.11+
- Node.js 18+ and npm
- MongoDB running locally or reachable via a MongoDB Atlas connection string

## 1) Start MongoDB

If you want to run MongoDB locally with Docker:

```bash
docker run -d --name phishsentinel-mongo -p 27017:27017 mongo:7
```

If you already have MongoDB running, make sure it accepts connections at `mongodb://localhost:27017`.

## 2) Set up the backend

From the repository root:

```bash
cd backend
python -m venv .venv
```

On Windows PowerShell:

```powershell
cd backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

On macOS/Linux:

```bash
source .venv/bin/activate
```

Then install Python dependencies:

```bash
pip install -r requirements.txt
```

Create a `.env` file inside `backend/` with the required environment variables:

```env
MONGO_URL=mongodb://localhost:27017
DB_NAME=phishsentinel
JWT_SECRET=change-this-secret
ADMIN_EMAIL=admin@phishsentinel.app
ADMIN_PASSWORD=ChangeMe!2026
```

Then start the API:

```bash
uvicorn server:app --host 0.0.0.0 --port 8000 --reload
```

The backend should be available at:

- http://localhost:8000
- API docs: http://localhost:8000/docs

## 3) Set up the frontend

Open a second terminal and run:

```bash
cd frontend
npm install
```

Create a `.env` file inside `frontend/` with:

```env
REACT_APP_BACKEND_URL=http://localhost:8000
```

Start the React app:

```bash
npm start
```

The frontend runs at:

- http://localhost:3000

## 4) Log in

The app seeds an admin user automatically on backend startup.

Default admin credentials:

- Email: `admin@phishsentinel.app`
- Password: `ChangeMe!2026`

## 5) Useful notes

- The backend is required for scans and authentication.
- The frontend expects the backend at `http://localhost:8000`.
- If you change `MONGO_URL` or `DB_NAME`, keep the frontend `.env` pointing to the matching backend URL.
- If you change `ADMIN_PASSWORD`, the backend will reseed it on startup.

## 6) Production-style build

To build the frontend bundle:

```bash
cd frontend
npm run build
```

To run the backend without reloader in a normal environment:

```bash
cd backend
uvicorn server:app --host 0.0.0.0 --port 8000
```
