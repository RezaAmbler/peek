# PEEK V2 - Port Enumeration & Evaluation Kit

Network security scanner with historical comparison capabilities.

## Quick Start

1. Clone the repository
2. Copy `.env.example` to `.env`
3. Start services:
   ```bash
   docker-compose up -d
   ```
4. Access the application:
   - Frontend: http://localhost:3000
   - Backend API: http://localhost:8000
   - API Docs: http://localhost:8000/docs

## Default Credentials

- Username: `admin`
- Password: `admin`

**⚠️ Change this in production!**

## Development

Backend:
```bash
cd backend
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Frontend:
```bash
cd frontend
npm install
npm run dev
```

## Architecture

- **Backend**: FastAPI + SQLAlchemy + SQLite
- **Frontend**: React + TypeScript + Vite + Tailwind
- **Task Queue**: Celery + Redis (for scan execution)

## Phase 1A Status

✅ Authentication system
✅ User management foundation
✅ Docker Compose setup
🚧 Scan functionality (Phase 2)
