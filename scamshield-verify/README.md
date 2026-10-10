# ScamShield Verify

ScamShield Verify is a cyber-safety investigation workspace: detect message signals, check claims against a small trusted-source catalogue, explain risk, read results aloud, and find nearby listed assistance. Users register or sign in before opening the workspace; passwords are PBKDF2-hashed and browser sessions use HTTP-only cookies. The frontend is React, TypeScript, Vite and Tailwind CSS; the API is FastAPI with deterministic scoring and local SQLite case history.

## Windows PowerShell: Development

Use two terminals from the repository folder.

Terminal 1, backend:

```powershell
Set-Location .\backend
python -m venv venv
.\venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
if (-not (Test-Path .env)) { Copy-Item .env.example .env }
uvicorn main:app --reload --port 8000
```

Terminal 2, frontend:

```powershell
Set-Location .\frontend
npm install
npm run dev
```

Open http://localhost:5173. Vite proxies `/api` to `http://localhost:8000`; restart the Vite dev server after changing its proxy configuration. Keep `.env` on the backend; API credentials are never sent to the browser.
Language preferences and the opaque authentication token are kept in this browser's local storage. User sessions are stored as token hashes in SQLite and expire after seven days. The API also sets an HTTP-only session cookie. Set `AUTH_COOKIE_SECURE=true` in `backend/.env` when serving the app over HTTPS; the local development default leaves Secure off so the cookie works over localhost HTTP.

## Production Build

```powershell
Set-Location .\frontend
npm run build
Set-Location ..\backend
.\venv\Scripts\Activate.ps1
uvicorn main:app --port 8000
```

FastAPI serves the generated `frontend/dist` build at http://localhost:8000. When no production build exists, the backend root redirects to the Vite development server.

## Optional Services

Set `LLM_API_KEY`, `LLM_BASE_URL`, and `LLM_MODEL` in `backend/.env` to enable claim assessment against retrieved evidence, enhanced explanation translation, translated speech, and open-ended assistant answers. Use an OpenAI-compatible service. Without it, deterministic scoring, built-in Kannada and Hindi analysis translations, and multilingual common-question fallbacks remain available. Risk scores, message evidence, source evidence and URLs are not translated.

Screenshot OCR uses Tesseract. Install Tesseract and its English, Kannada, and Hindi language data, then set `TESSERACT_CMD` if it is not on PATH. OCR text is returned to the editor before analysis so it can be corrected.

Nearby place search uses OpenStreetMap Nominatim and Overpass. Configure `MAP_USER_AGENT`, `NOMINATIM_URL`, and `OVERPASS_URL` in `backend/.env` for a deployed installation, and follow each service's attribution and usage policies. Search records are live OSM listings, not independently verified station records; phone numbers may be absent or unverified. Precise browser coordinates are sent only after the user chooses nearby search and are not stored by this app. A deployed service with higher traffic should use a contracted places provider or self-hosted OSM services.

## Tests

Backend tests, from `backend`:

```powershell
python -m pytest tests -q
```

Frontend production build, from `frontend`:

```powershell
npm run build
npm audit
```

## Privacy and Limitations

The original full message is not saved, but case results retain detected entities and extracted claims as well as a digit-masked snippet. Delete cases from Case history to remove them from the local SQLite database. Message contents are not written to application logs.

Risk scores are fixed-rule estimates, not proof that a message is fraudulent or safe. Claim retrieval uses the small catalogue in `backend/data/sources.json`; maintainers must re-check its source text and dates. Nearby police data comes from OpenStreetMap and can be incomplete. The assistant does not file complaints, call a station, or secure an account. Official India-wide guidance includes cyber-fraud reporting at 1930 and immediate emergencies at 112; use https://cybercrime.gov.in/ for the National Cyber Crime Reporting Portal.

Browser speech uses the selected language locale (`en-IN`, `kn-IN`, or `hi-IN`) and prefers a matching installed voice. If no exact voice is available, it uses the closest available voice and reports that fallback; when translation is unavailable, the original text is not described as translated.

## Authentication and case privacy

Register or sign in at the application page. The API exposes `POST /api/auth/register`, `POST /api/auth/login`, `GET /api/auth/me`, and `POST /api/auth/logout`. Passwords are stored only as salted PBKDF2-HMAC-SHA256 hashes; random session tokens are stored as hashes in SQLite and returned to the frontend for Bearer authentication. The API also sets an HTTP-only, SameSite=Lax cookie. Configure `AUTH_COOKIE_SECURE=true` behind HTTPS.

Analysis records are associated with the signed-in account, and history, summaries, deletion, and analytics are scoped to that user. The schema migration adds a nullable owner column to existing cases without deleting them; pre-existing ownerless cases are retained but are not exposed to signed-in accounts.