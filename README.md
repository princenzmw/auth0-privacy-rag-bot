# MLH Global Hack Week: API Week — Flask Starter (with CRUD + CORS)

Minimal Flask API with health/hello/joke endpoints, **toggleable in-memory Tasks CRUD**, and **CORS** enabled.

## Requirements
- Python 3.9+ (recommended)
- pip or uv
- Flask, flask-cors (auto-installed via `requirements.txt`)

## Endpoints
- `GET /health` → 
```json
{ "status": "ok" }
```
- `GET /hello?name=Prince` →
```json
{ "message": "Hello, Prince" }
```
- `GET /joke` → Two-part joke with deterministic fallback
- **(Toggle)** `GET /tasks` → `{ tasks: [...] }`
- **(Toggle)** `POST /tasks` → `{ id, text, done }` (JSON body: `{ text: string }`)
- **(Toggle)** `PATCH /tasks/<id>` → Update `{ text?, done? }`
- **(Toggle)** `DELETE /tasks/<id>`

## Toggle Tasks On/Off
Controlled by env var **`TASKS_ENABLED`** (default `true`).

**Windows PowerShell (current session)**
```powershell
$env:TASKS_ENABLED = "false"; python app.py   # disable
$env:TASKS_ENABLED = "true"; python app.py    # enable
```

**Render**: set `TASKS_ENABLED` in "Environment" to `true` or `false` (default is `true` via `render.yaml`).

## Local Setup (Windows PowerShell)
```powershell
python -m venv .venv
.\.venv\Scripts\Activate
pip install -r requirements.txt
python app.py
# Visit http://localhost:5000/health
```

### If you're using UV,
```powershell
uv venv .venv
.venv\Scripts\Activate.ps1
uv pip install -r requirements.txt
python app.py
# Visit http://localhost:5000/health
```

## Quick Start
```powershell
git clone https://github.com/princenzmw/mlh-flask-api-starter.git
cd mlh-api-week-flask-template
python -m venv .venv
.\.venv\Scripts\Activate
pip install -r requirements.txt
python app.py
```

## Deploy to Render
Click the button or create a Web Service from this repo. Render uses `render.yaml`.

[![Deploy to Render](https://render.com/images/deploy-to-render-button.svg)](https://render.com/deploy?repo=https://github.com/princenzmw/mlh-api-week-flask-template)

## Run on Replit
Import this repo → set run to `python app.py` (or use default detection).

## Project Structure
```bash
mlh-api-week-flask-template
├── .venv/                 # Python virtual environment (gitignored)
├── .gitignore
├── .python-version
├── app.py
├── Procfile
├── pyproject.toml
├── README.md
├── render.yaml
├── requirements.txt
└── uv.lock
```

## Notes
- CORS is enabled via `flask-cors`.
- In-memory tasks reset on each deploy/restart.
