import io
import json
import logging
import math
import os
import re
import sqlite3
import threading
import time
import copy
import hashlib
import hmac
import secrets
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal
from urllib.parse import urlparse

import httpx
import intel
from dotenv import load_dotenv

from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles

from pydantic import BaseModel, Field, model_validator


# ============================================================
# CONFIGURATION
# ============================================================

load_dotenv()

BASE = Path(__file__).resolve().parent
FRONTEND = BASE.parent / "frontend"
FRONTEND_DIST = FRONTEND / "dist"

DATA_DIR = BASE / "data"
DB = BASE / "history.db"

DATA_DIR.mkdir(exist_ok=True)

LLM_KEY = os.getenv("LLM_API_KEY", "")
LLM_URL = os.getenv("LLM_BASE_URL", "")
LLM_MODEL = os.getenv("LLM_MODEL", "")

LLM_ON = bool(LLM_KEY and LLM_URL and LLM_MODEL)
AUTH_COOKIE_NAME = "scamshield_session"
AUTH_COOKIE_SECURE = os.getenv("AUTH_COOKIE_SECURE", "").lower() == "true"
AUTH_SESSION_TTL = 7 * 24 * 60 * 60
PASSWORD_HASH_ITERATIONS = 600_000

MAP_USER_AGENT = os.getenv(
    "MAP_USER_AGENT",
    "ScamShieldVerify/1.0"
)

NOMINATIM_URL = os.getenv(
    "NOMINATIM_URL",
    "https://nominatim.openstreetmap.org"
).rstrip("/")

OVERPASS_URL = os.getenv(
    "OVERPASS_URL",
    "https://overpass-api.de/api/interpreter"
)

DISCLAIMER = (
    "ScamShield Verify is an assistive cybersecurity tool. "
    "It cannot guarantee that a message is safe or fraudulent. "
    "Always verify sensitive requests through the organization's official channels."
)


# ============================================================
# APP
# ============================================================

app = FastAPI(
    title="ScamShield Verify",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:8000",
        "http://127.0.0.1:8000",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


logging.basicConfig(level=logging.INFO)
log = logging.getLogger("scamshield")


# ============================================================
# LANGUAGES
# ============================================================

LANGUAGES = {
    "en": "English",
    "kn": "Kannada",
    "hi": "Hindi",
}

LANGUAGE_LOCALES = {
    "en": "en-IN",
    "kn": "kn-IN",
    "hi": "hi-IN",
}


# ============================================================
# RATE LIMITING
# ============================================================

RATE_BUCKETS = {}
RATE_LOCK = threading.Lock()


def rate_check(request: Request, bucket: str, limit: int, seconds: int = 60):
    now = time.monotonic()

    client = (
        request.client.host
        if request.client
        else "unknown"
    )

    key = (client, bucket)

    with RATE_LOCK:
        recent = [
            stamp
            for stamp in RATE_BUCKETS.get(key, [])
            if now - stamp < seconds
        ]

        if len(recent) >= limit:
            raise HTTPException(
                status_code=429,
                detail="Too many requests. Please try again shortly."
            )

        recent.append(now)
        RATE_BUCKETS[key] = recent


# ============================================================
# DATA LOADING
# ============================================================

DEFAULT_SOURCES = [
    {
        "id": "cyber-1",
        "title": "National Cyber Crime Reporting Portal",
        "org": "Government of India",
        "url": "https://cybercrime.gov.in/",
        "category": "cybercrime",
        "language": "en",
        "keywords": "cyber crime fraud report online financial fraud 1930",
        "text": (
            "The National Cyber Crime Reporting Portal is used to report "
            "cybercrime complaints in India. Financial cyber fraud should "
            "be reported promptly through the official reporting channels."
        ),
        "retrieved_on": "2026-10-04",
    },
    {
        "id": "rbi-1",
        "title": "RBI Customer Safety Guidance",
        "org": "Reserve Bank of India",
        "url": "https://www.rbi.org.in/",
        "category": "banking",
        "language": "en",
        "keywords": "OTP PIN CVV password banking fraud phishing",
        "text": (
            "Customers should not share OTPs, PINs, passwords or other "
            "confidential banking credentials with unknown persons."
        ),
        "retrieved_on": "2026-10-04",
        "contradicts": (
            r"\b(?:share|send|give|tell|provide)\b.{0,40}"
            r"\b(?:otp|pin|cvv|password)\b"
        ),
    },
    {
        "id": "cert-1",
        "title": "CERT-In Cyber Security Guidance",
        "org": "CERT-In",
        "url": "https://www.cert-in.org.in/",
        "category": "security",
        "language": "en",
        "keywords": "phishing malicious links cyber security suspicious links",
        "text": (
            "Users should be careful with suspicious links, phishing "
            "messages and requests for sensitive information."
        ),
        "retrieved_on": "2026-10-04",
    },
    {
        "id": "uidai-1",
        "title": "UIDAI Official Portal",
        "org": "UIDAI",
        "url": "https://uidai.gov.in/",
        "category": "aadhaar",
        "language": "en",
        "keywords": "Aadhaar authentication identity official",
        "text": (
            "UIDAI provides official Aadhaar-related services and information "
            "through its official portal."
        ),
        "retrieved_on": "2026-10-04",
    },
    {
        "id": "itd-1",
        "title": "Income Tax Department",
        "org": "Income Tax Department",
        "url": "https://www.incometax.gov.in/",
        "category": "tax",
        "language": "en",
        "keywords": "income tax ITR refund tax official",
        "text": (
            "Income tax services and taxpayer information should be checked "
            "through the official Income Tax Department portal."
        ),
        "retrieved_on": "2026-10-04",
    },
    {
        "id": "emergency-1",
        "title": "Emergency Response Support System",
        "org": "Government of India",
        "url": "https://112.gov.in/",
        "category": "emergency",
        "language": "en",
        "keywords": "112 emergency police fire medical",
        "text": (
            "112 is India's unified emergency response number for immediate "
            "police, fire and medical emergencies."
        ),
        "retrieved_on": "2026-10-04",
    },
]


def load_json_file(path: Path, fallback):
    if not path.exists():
        return fallback

    try:
        return json.loads(
            path.read_text(encoding="utf-8")
        )
    except Exception as exc:
        log.warning("Could not load %s: %s", path, exc)
        return fallback


SOURCES = load_json_file(
    DATA_DIR / "sources.json",
    DEFAULT_SOURCES
)

DEFAULT_TESTS = [
    {
        "text": "Your bank account will be blocked immediately. Share your OTP now.",
        "label": "scam",
        "language": "en",
        "category": "otp",
    },
    {
        "text": "Congratulations! You have won a prize. Pay a processing fee to receive it.",
        "label": "scam",
        "language": "en",
        "category": "reward",
    },
    {
        "text": "Complete your KYC immediately or your account will be suspended.",
        "label": "scam",
        "language": "en",
        "category": "kyc",
    },
    {
        "text": "Your delivery requires a customs fee. Pay the delivery fee immediately.",
        "label": "scam",
        "language": "en",
        "category": "delivery",
    },
    {
        "text": "You have been selected for a government cash reward. Send your bank details.",
        "label": "scam",
        "language": "en",
        "category": "government",
    },
    {
        "text": "Please do not share your OTP or password with anyone.",
        "label": "legit",
        "language": "en",
        "category": "safety",
    },
    {
        "text": "Your order has been delivered successfully.",
        "label": "legit",
        "language": "en",
        "category": "delivery",
    },
    {
        "text": "ನಿಮ್ಮ ಖಾತೆ ಬ್ಲಾಕ್ ಆಗುತ್ತದೆ. ತಕ್ಷಣ OTP ಕಳುಹಿಸಿ.",
        "label": "scam",
        "language": "kn",
        "category": "otp",
    },
    {
        "text": "आपने इनाम जीता है। पुरस्कार पाने के लिए शुल्क जमा करें।",
        "label": "scam",
        "language": "hi",
        "category": "reward",
    },
    {
        "text": "Please check your tax information through the official income tax portal.",
        "label": "legit",
        "language": "en",
        "category": "tax",
    },
]


TESTS = load_json_file(
    DATA_DIR / "tests.json",
    DEFAULT_TESTS
)


# ============================================================
# DATABASE
# ============================================================

def init_db():
    with sqlite3.connect(DB) as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS cases (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts REAL,
                input_type TEXT,
                language TEXT,
                score INTEGER,
                level TEXT,
                patterns TEXT,
                snippet TEXT,
                result TEXT
            )
            """
        )
        columns = {
            row[1]
            for row in connection.execute(
                "PRAGMA table_info(cases)"
            )
        }
        if "user_id" not in columns:
            connection.execute(
                "ALTER TABLE cases ADD COLUMN user_id INTEGER"
            )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at REAL NOT NULL
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS sessions (
                token_hash TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id),
                expires_at REAL NOT NULL,
                created_at REAL NOT NULL
            )
            """
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_cases_user_id ON cases(user_id)"
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id)"
        )


init_db()


def db_execute(query, args=()):
    with sqlite3.connect(DB) as connection:
        cursor = connection.execute(query, args)
        rows = cursor.fetchall()
        last_id = cursor.lastrowid
        connection.commit()

    if query.lstrip().upper().startswith("SELECT"):
        return rows

    return last_id


def password_hash(password: str, salt: bytes | None = None) -> str:
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        PASSWORD_HASH_ITERATIONS,
    )
    return f"pbkdf2_sha256${PASSWORD_HASH_ITERATIONS}${salt.hex()}${digest.hex()}"


def verify_password(password: str, stored_hash: str) -> bool:
    try:
        algorithm, iterations, salt_hex, digest_hex = stored_hash.split("$")
        if algorithm != "pbkdf2_sha256":
            return False
        expected = bytes.fromhex(digest_hex)
        actual = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            bytes.fromhex(salt_hex),
            int(iterations),
            dklen=len(expected),
        )
        return hmac.compare_digest(actual, expected)
    except (TypeError, ValueError):
        return False


def session_token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def authenticated_user(request: Request):
    authorization = request.headers.get("authorization", "")
    scheme, _, bearer_token = authorization.partition(" ")
    token = bearer_token.strip() if scheme.casefold() == "bearer" else request.cookies.get(AUTH_COOKIE_NAME)
    if not token:
        return None

    rows = db_execute(
        """
        SELECT users.id, users.name, users.email
        FROM sessions
        JOIN users ON users.id = sessions.user_id
        WHERE sessions.token_hash = ? AND sessions.expires_at > ?
        """,
        (session_token_hash(token), time.time()),
    )
    if not rows:
        return None
    return {"id": rows[0][0], "name": rows[0][1], "email": rows[0][2]}


def issue_session(user_id: int, request: Request, response: Response):
    token = secrets.token_urlsafe(32)
    now = time.time()
    db_execute(
        "DELETE FROM sessions WHERE expires_at <= ?",
        (now,),
    )
    db_execute(
        """
        INSERT INTO sessions (token_hash, user_id, expires_at, created_at)
        VALUES (?, ?, ?, ?)
        """,
        (session_token_hash(token), user_id, now + AUTH_SESSION_TTL, now),
    )
    response.set_cookie(
        AUTH_COOKIE_NAME,
        token,
        max_age=AUTH_SESSION_TTL,
        httponly=True,
        secure=AUTH_COOKIE_SECURE or request.url.scheme == "https",
        samesite="lax",
        path="/",
    )
    return token


PUBLIC_API_PATHS = {
    "/api/health",
    "/api/languages",
    "/api/auth/register",
    "/api/auth/login",
    "/api/auth/me",
    "/api/auth/logout",
}


@app.middleware("http")
async def protect_api(request: Request, call_next):
    path = request.url.path
    if path.startswith("/api/") and path not in PUBLIC_API_PATHS:
        user = authenticated_user(request)
        if user is None:
            return JSONResponse(
                status_code=401,
                content={"detail": "Please log in to continue."},
            )
        request.state.user = user
    return await call_next(request)


# ============================================================
# PYDANTIC MODELS
# ============================================================

class AuthRegisterIn(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    email: str = Field(min_length=3, max_length=254)
    password: str = Field(min_length=8, max_length=128)
    confirm_password: str = Field(min_length=8, max_length=128)

    @model_validator(mode="after")
    def validate_registration(self):
        if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", self.email.strip()):
            raise ValueError("Enter a valid email address.")
        if self.password != self.confirm_password:
            raise ValueError("Passwords do not match.")
        if not self.name.strip():
            raise ValueError("Name cannot be empty.")
        return self


class AuthLoginIn(BaseModel):
    email: str = Field(min_length=3, max_length=254)
    password: str = Field(min_length=1, max_length=128)

    @model_validator(mode="after")
    def validate_email(self):
        if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", self.email.strip()):
            raise ValueError("Enter a valid email address.")
        return self


class TextIn(BaseModel):
    text: str = Field(min_length=1, max_length=5000)
    input_type: str = "text"

    input_language: Literal[
        "auto", "en", "kn", "hi"
    ] = "auto"

    output_language: Literal[
        "en", "kn", "hi"
    ] = "en"


class AskIn(BaseModel):
    question: str = Field(
        min_length=1,
        max_length=500
    )

    analysis_id: int | None = None
    context: dict | None = None

    output_language: Literal[
        "en", "kn", "hi"
    ] = "en"


class LanguagePreferencesIn(BaseModel):
    input_language: Literal[
        "auto", "en", "kn", "hi"
    ] = "auto"

    output_language: Literal[
        "en", "kn", "hi"
    ] = "en"

    speech_language: Literal[
        "en", "kn", "hi"
    ] = "en"


class SpeechIn(BaseModel):
    text: str | None = Field(
        default=None,
        max_length=5000
    )

    analysis: dict | None = None

    speech_language: Literal[
        "en", "kn", "hi"
    ] = "en"


class AssistanceIn(BaseModel):
    location_query: str | None = Field(
        default=None,
        max_length=160
    )

    latitude: float | None = Field(
        default=None,
        ge=-90,
        le=90
    )

    longitude: float | None = Field(
        default=None,
        ge=-180,
        le=180
    )

    radius_m: int = Field(
        default=15000,
        ge=1000,
        le=50000
    )

    categories: list[
        Literal["cybercrime", "police", "emergency"]
    ] = Field(
        default_factory=lambda: [
            "cybercrime",
            "police",
            "emergency"
        ]
    )

    @model_validator(mode="after")
    def require_location(self):
        has_latitude = self.latitude is not None
        has_longitude = self.longitude is not None
        if has_latitude != has_longitude:
            raise ValueError("Provide both latitude and longitude.")
        if not has_latitude and not (self.location_query or "").strip():
            raise ValueError("Provide a location query or coordinates.")
        return self


class ClaimIn(BaseModel):
    claim: str = Field(
        min_length=1,
        max_length=500
    )


# ============================================================
# BASIC HELPERS
# ============================================================

def clean_text(text: str) -> str:
    text = (text or "").strip()

    if not text:
        raise HTTPException(
            status_code=400,
            detail="Please enter a message to analyze."
        )

    if len(text) > 5000:
        raise HTTPException(
            status_code=413,
            detail="Message is too long. Limit is 5000 characters."
        )

    return text


def level_of(score: int) -> str:
    if score >= 80:
        return "CRITICAL"

    if score >= 60:
        return "HIGH"

    if score >= 30:
        return "MEDIUM"

    return "LOW"


def detect_lang(text: str):
    letters = [
        char
        for char in text
        if char.isalpha()
    ]

    total = len(letters) or 1

    kannada = sum(
        "\u0C80" <= char <= "\u0CFF"
        for char in letters
    ) / total

    hindi = sum(
        "\u0900" <= char <= "\u097F"
        for char in letters
    ) / total

    english = sum(
        char.isascii()
        for char in letters
    ) / total

    if kannada > 0.15 and english > 0.15:
        return {
            "language": "Mixed: Kannada + English",
            "code": "kn",
            "confidence": round(
                max(kannada, english) * 100
            ),
        }

    if kannada > 0.5:
        return {
            "language": "Kannada",
            "code": "kn",
            "confidence": round(kannada * 100),
        }

    if hindi > 0.5:
        return {
            "language": "Hindi",
            "code": "hi",
            "confidence": round(hindi * 100),
        }

    return {
        "language": "English",
        "code": "en",
        "confidence": round(english * 100),
    }


# ============================================================
# SCAM RULES
# ============================================================

NEG = re.compile(
    r"\b(?:do not|don't|dont|never)\s+"
    r"(?:share|disclose|give|reveal|send|provide)"
    r".{0,80}?"
    r"\b(?:otp|pin|cvv|password|aadhaar|aadhar)\b",
    re.IGNORECASE
)


SIGNALS = {
    "OTP_REQUEST": (
        20,
        "Asks you to share an OTP, PIN or CVV",
        r"(?:share|send|enter|give|provide|tell|submit|verify)"
        r"\w*.{0,30}\b(?:otp|pin|cvv)\b"
        r"|ಒಟಿಪಿ\s*(?:ನೀಡಿ|ಕಳುಹಿಸಿ)"
        r"|ओटीपी\s*(?:साझा|भेज|बताएं)"
    ),

    "CREDENTIAL_REQUEST": (
        20,
        "Asks for passwords, Aadhaar or bank/card details",
        r"(?:share|send|enter|give|provide|verify|submit)"
        r"\w*.{0,30}"
        r"(?:password|aadhaar|aadhar|card number|bank details)"
        r"|ಪಾಸ್ವರ್ಡ್"
        r"|ಆಧಾರ್\s*(?:ನೀಡಿ|ಕಳುಹಿಸಿ)"
        r"|पासवर्ड"
    ),

    "URGENCY_THREAT": (
        15,
        "Uses urgency or threats to rush you",
        r"immediately|urgent|within\s+\d+\s*"
        r"(?:hours|hrs|minutes)|expire|will be blocked|"
        r"suspended|arrest|legal action|ತಕ್ಷಣ|ತುರ್ತು|"
        r"ಬ್ಲಾಕ್|तुरंत|ब्लॉक"
    ),

    "REWARD_BAIT": (
        15,
        "Promises money or prizes",
        r"you\s+(?:have\s+)?won|lottery|prize|free gift|"
        r"every citizen|cashback|ಬಹುಮಾನ|ಲಾಟರಿ|"
        r"इनाम|लॉटरी"
    ),

    "FEE_REQUEST": (
        15,
        "Asks you to pay a fee or deposit",
        r"registration fee|joining fee|processing fee|"
        r"security deposit|pay\s+(?:a\s+)?(?:fee|rs|₹)"
    ),

    "KYC_REFUND_LURE": (
        10,
        "Uses a KYC, refund or fee lure",
        r"\bkyc\b|refund|customs fee|delivery fee|"
        r"ಕೆವೈಸಿ|केवाईसी"
    ),
}


URL_RE = re.compile(
    r"(?:https?://|www\.)[^\s<>\"']+"
    r"|(?:\b[a-z0-9-]+\.)+"
    r"(?:xyz|top|click|link|icu|buzz|info|cc)\b"
    r"[^\s<>\"']*",
    re.IGNORECASE
)


SUS_TLD = {
    "xyz",
    "top",
    "click",
    "link",
    "icu",
    "buzz",
    "info",
    "cc",
}


SHORT = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "cutt.ly",
    "is.gd",
}


ORGS = {
    "State Bank of India": (
        r"\bsbi\b|state bank",
        [
            "sbi.co.in",
            "onlinesbi.sbi",
        ],
    ),

    "HDFC Bank": (
        r"hdfc",
        [
            "hdfcbank.com",
        ],
    ),

    "ICICI Bank": (
        r"icici",
        [
            "icicibank.com",
        ],
    ),

    "Reserve Bank of India": (
        r"\brbi\b|reserve bank",
        [
            "rbi.org.in",
        ],
    ),

    "UIDAI (Aadhaar)": (
        r"uidai|aadhaar",
        [
            "uidai.gov.in",
        ],
    ),

    "Amazon": (
        r"amazon",
        [
            "amazon.in",
            "amazon.com",
        ],
    ),

    "Income Tax Department": (
        r"income tax",
        [
            "incometax.gov.in",
        ],
    ),

    "India Post": (
        r"india post",
        [
            "indiapost.gov.in",
        ],
    ),
}


OFFICIAL = {
    domain
    for _, domains in ORGS.values()
    for domain in domains
}


CLAIM_RE = re.compile(
    r"₹\s?\d"
    r"|rs\.?\s?\d"
    r"|every citizen"
    r"|government"
    r"|aadhaar"
    r"|\bkyc\b"
    r"|account\s+(?:will be\s+)?"
    r"(?:blocked|suspended|closed)"
    r"|refund"
    r"|lottery"
    r"|prize"
    r"|ಸರ್ಕಾರ"
    r"|ಆಧಾರ್"
    r"|ಬ್ಲಾಕ್"
    r"|ಬಹುಮಾನ",
    re.IGNORECASE
)


# ============================================================
# URL ANALYSIS
# ============================================================

def analyze_url(url: str):
    url = url.rstrip(".,);")

    parsed = urlparse(
        url if "://" in url else "http://" + url
    )

    host = (parsed.hostname or "").lower()

    reasons = []

    if host.rsplit(".", 1)[-1] in SUS_TLD:
        reasons.append(
            "Uncommon top-level domain"
        )

    if host in SHORT:
        reasons.append(
            "URL shortener hides the real destination"
        )

    if parsed.scheme == "http":
        reasons.append(
            "Not using HTTPS"
        )

    if host.count("-") >= 2:
        reasons.append(
            "Domain name looks unusual"
        )

    for domain in OFFICIAL:
        if (
            domain in host
            and not (
                host == domain
                or host.endswith("." + domain)
            )
        ):
            reasons.append(
                f"Contains '{domain}' but is not that organization's domain"
            )

    return {
        "url": url,
        "host": host,
        "reasons": reasons,
    }


# ============================================================
# IMPERSONATION
# ============================================================

def impersonation(text, urls, signal_types):
    results = []

    hosts = [
        item["host"]
        for item in urls
    ]

    for organization, (
        pattern,
        domains
    ) in ORGS.items():

        if not re.search(
            pattern,
            text,
            re.IGNORECASE
        ):
            continue

        def valid_host(host):
            return any(
                host == domain
                or host.endswith("." + domain)
                for domain in domains
            )

        if hosts and not any(
            valid_host(host)
            for host in hosts
        ):
            results.append({
                "claimed_org": organization,
                "result": "Possible impersonation",
                "hosts": hosts,
                "reason": (
                    f"The link domain does not match "
                    f"{organization}'s known official domains "
                    f"({', '.join(domains)})."
                ),
            })

        elif (
            not hosts
            and (
                {"OTP_REQUEST", "CREDENTIAL_REQUEST"}
                & set(signal_types)
            )
        ):
            results.append({
                "claimed_org": organization,
                "result": "Possible impersonation",
                "hosts": [],
                "reason": (
                    f"The message mentions {organization} "
                    "and asks for sensitive details, "
                    "with no verifiable official link."
                ),
            })

    return results


# ============================================================
# RETRIEVAL
# ============================================================

def tokenize(text):
    return [
        word
        for word in re.findall(
            r"\w+",
            text.lower(),
            flags=re.UNICODE
        )
        if len(word) > 2
    ]


DOCS = [
    set(
        tokenize(
            source.get("title", "")
            + " "
            + source.get("text", "")
            + " "
            + source.get("keywords", "")
        )
    )
    for source in SOURCES
]


DF = Counter(
    word
    for document in DOCS
    for word in document
)


def idf(word):
    return math.log(
        1 + len(DOCS) / (1 + DF.get(word, 0))
    )


def retrieve(claim, k=3):
    query_words = set(tokenize(claim))

    hits = []

    for source, document in zip(
        SOURCES,
        DOCS
    ):
        shared = query_words & document

        if len(shared) < 2:
            continue

        score = sum(
            idf(word)
            for word in shared
        ) / (
            sum(
                idf(word)
                for word in query_words
            ) or 1
        )

        if score >= 0.15:
            hits.append(
                (score, source)
            )

    hits.sort(
        key=lambda item: -item[0]
    )

    result = []

    for score, source in hits[:k]:
        result.append({
            "id": source["id"],
            "title": source["title"],
            "org": source["org"],
            "url": source["url"],
            "text": source["text"],
            "retrieved_on": source.get(
                "retrieved_on",
                ""
            ),
            "score": round(score, 2),
            "contradicts": source.get(
                "contradicts",
                ""
            ),
        })

    return result


# ============================================================
# LLM HELPERS
# ============================================================

def llm_json(prompt):
    if not LLM_ON:
        return None

    try:
        response = httpx.post(
            f"{LLM_URL.rstrip('/')}/chat/completions",
            timeout=30,
            headers={
                "Authorization":
                    f"Bearer {LLM_KEY}",
                "Content-Type":
                    "application/json",
            },
            json={
                "model": LLM_MODEL,
                "temperature": 0,
                "messages": [
                    {
                        "role": "user",
                        "content": prompt,
                    }
                ],
            },
        )

        response.raise_for_status()

        content = response.json()[
            "choices"
        ][0]["message"]["content"].strip()

        content = re.sub(
            r"^```(?:json)?\s*",
            "",
            content,
            flags=re.IGNORECASE
        )

        content = re.sub(
            r"\s*```$",
            "",
            content
        )

        return json.loads(content)

    except Exception as exc:
        log.warning(
            "LLM JSON request failed: %s",
            exc
        )
        return None


def llm_text(prompt):
    if not LLM_ON:
        return None

    try:
        response = httpx.post(
            f"{LLM_URL.rstrip('/')}/chat/completions",
            timeout=30,
            headers={
                "Authorization":
                    f"Bearer {LLM_KEY}",
                "Content-Type":
                    "application/json",
            },
            json={
                "model": LLM_MODEL,
                "temperature": 0,
                "messages": [
                    {
                        "role": "user",
                        "content": prompt,
                    }
                ],
            },
        )

        response.raise_for_status()

        return response.json()[
            "choices"
        ][0]["message"]["content"].strip()

    except Exception as exc:
        log.warning(
            "LLM text request failed: %s",
            exc
        )
        return None


# ============================================================
# CLAIM VERIFICATION
# ============================================================

def verify_claim(
    claim: str,
    use_llm: bool = True
):
    hits = retrieve(claim)

    evidence = [
        {
            key: hit[key]
            for key in (
                "id",
                "title",
                "org",
                "url",
                "text",
                "score",
                "retrieved_on",
            )
        }
        for hit in hits
    ]

    if not hits:
        return {
            "claim": claim,
            "status": "UNSUPPORTED",
            "reason": (
                "No matching official source "
                "was found in the trusted database."
            ),
            "evidence": [],
            "by": "rules",
        }

    if use_llm:
        evidence_text = "\n".join(
            f"[{hit['id']}] "
            f"{hit['org']}: "
            f"{hit['text']}"
            for hit in hits
        )

        prompt = (
            "You are verifying a claim using ONLY the supplied evidence. "
            "Never invent a source, URL, quote or fact. "
            "If evidence does not establish the claim, use "
            "INCONCLUSIVE or UNSUPPORTED. "
            "Return JSON only.\n\n"
            'Required format: '
            '{"status":"SUPPORTED|CONTRADICTED|UNSUPPORTED|INCONCLUSIVE",'
            '"reason":"one short sentence"}\n\n'
            f"Claim: {claim}\n\n"
            f"Evidence:\n{evidence_text}"
        )

        result = llm_json(prompt)

        if (
            isinstance(result, dict)
            and result.get("status")
            in {
                "SUPPORTED",
                "CONTRADICTED",
                "UNSUPPORTED",
                "INCONCLUSIVE",
            }
        ):
            return {
                "claim": claim,
                "status": result["status"],
                "reason": str(
                    result.get(
                        "reason",
                        ""
                    )
                )[:300],
                "evidence": evidence,
                "by": "llm",
            }

    for hit in hits:
        contradiction = hit.get(
            "contradicts",
            ""
        )

        if contradiction:
            try:
                matched = re.search(
                    contradiction,
                    claim,
                    re.IGNORECASE
                )
            except re.error:
                matched = False

            if matched:
                return {
                    "claim": claim,
                    "status": "CONTRADICTED",
                    "reason": (
                        f"Official guidance from "
                        f"{hit['org']} advises against this."
                    ),
                    "evidence": evidence,
                    "by": "rules",
                }

    return {
        "claim": claim,
        "status": "INCONCLUSIVE",
        "reason": (
            "Related official guidance exists, "
            "but it cannot confirm or deny this claim."
        ),
        "evidence": evidence,
        "by": "rules",
    }


def extract_claims(text):
    parts = [
        part.strip()
        for part in re.split(
            r"(?<=[.!?।])\s+|\n+",
            text
        )
        if part.strip()
    ]

    claims = []

    for part in parts:
        if CLAIM_RE.search(part):
            claims.append(part[:300])

        if len(claims) >= 5:
            break

    return claims


# ============================================================
# ACTIONS
# ============================================================

def actions_for(level):
    if level in {"HIGH", "CRITICAL"}:
        return [
            "Do not click any link.",
            "Do not share OTP, PIN, password or Aadhaar details.",
            "Do not transfer money.",
            "Verify through the organization's official website or app.",
            "If you already acted, report at cybercrime.gov.in or call 1930.",
        ]

    if level == "MEDIUM":
        return [
            "Do not act immediately.",
            "Check the sender and official source.",
            "Avoid sharing sensitive information.",
            "Verify the request independently.",
        ]

    return [
        "No major scam signals detected.",
        "Still verify unexpected requests before acting.",
    ]


# ============================================================
# TIMELINE / PATTERNS
# ============================================================

def build_timeline(signals, level):
    timeline = []

    if signals:
        for signal in signals:
            timeline.append({
                "tactic": signal["type"],
                "label": signal["label"],
            })
    else:
        timeline.append({
            "tactic": "NO_MAJOR_SIGNAL",
            "label": "No major scam pattern detected.",
        })

    timeline.append({
        "tactic": "RISK",
        "label": f"Overall risk level: {level}",
    })

    return timeline


def build_patterns(signals):
    return [
        {
            "name": signal["type"],
            "detail": signal["label"],
        }
        for signal in signals
    ]


# ============================================================
# FULL ANALYSIS
# ============================================================

def full_analysis(
    text: str,
    use_llm: bool = True
):
    cleaned = NEG.sub(
        " ",
        text
    )

    signals = []

    for (
        signal_type,
        (
            weight,
            label,
            pattern
        )
    ) in SIGNALS.items():

        match = re.search(
            pattern,
            cleaned,
            re.IGNORECASE
        )

        if match:
            signals.append({
                "type": signal_type,
                "label": label,
                "weight": weight,
                "evidence": match.group(0)[:100],
            })

    found_urls = list(
        dict.fromkeys(
            URL_RE.findall(text)
        )
    )

    urls = [
        analyze_url(url)
        for url in found_urls
    ]

    suspicious_urls = [
        url
        for url in urls
        if url["reasons"]
    ]

    if suspicious_urls:
        signals.append({
            "type": "SUSPICIOUS_URL",
            "label": (
                "Link has risk signals "
                "(a signal, not proof of malice)"
            ),
            "weight": 15,
            "evidence":
                suspicious_urls[0]["url"][:100],
        })

    impersonation_result = impersonation(
        text,
        urls,
        [
            signal["type"]
            for signal in signals
        ]
    )

    if impersonation_result:
        signals.append({
            "type": "IMPERSONATION",
            "label":
                "Possible impersonation of an organization",
            "weight": 20,
            "evidence":
                impersonation_result[0][
                    "claimed_org"
                ],
        })

    score = min(
        100,
        sum(
            signal["weight"]
            for signal in signals
        )
    )

    level = level_of(score)

    if score >= 60:
        classification = "Likely scam"
    elif score >= 30:
        classification = "Uncertain"
    else:
        classification = "Likely legitimate"

    claims = [
        verify_claim(
            claim,
            use_llm
        )
        for claim in extract_claims(text)
    ]

    result = {
        "language": detect_lang(text),
        "score": score,
        "level": level,
        "classification": classification,
        "signals": signals,
        "urls": urls,
        "impersonation":
            impersonation_result,
        "claims": claims,
        "actions":
            actions_for(level),
        "timeline":
            build_timeline(
                signals,
                level
            ),
        "patterns":
            build_patterns(signals),
        "ai_used":
            any(
                claim["by"] == "llm"
                for claim in claims
            ),
        "disclaimer": DISCLAIMER,
    }

    return result


# ============================================================
# LOCALIZATION
# ============================================================

TRANSLATIONS = {
    "kn": {
        "Likely scam": "ಬಹುಶಃ ವಂಚನೆ",
        "Uncertain": "ಖಚಿತವಾಗಿಲ್ಲ",
        "Likely legitimate": "ಬಹುಶಃ ನಂಬಬಹುದಾದ ಸಂದೇಶ",

        "Asks you to share an OTP, PIN or CVV":
            "OTP, PIN ಅಥವಾ CVV ಹಂಚಿಕೊಳ್ಳಲು ಕೇಳುತ್ತದೆ",

        "Asks for passwords, Aadhaar or bank/card details":
            "ಪಾಸ್‌ವರ್ಡ್, ಆಧಾರ್ ಅಥವಾ ಬ್ಯಾಂಕ್/ಕಾರ್ಡ್ ವಿವರಗಳನ್ನು ಕೇಳುತ್ತದೆ",

        "Uses urgency or threats to rush you":
            "ತುರ್ತು ಅಥವಾ ಬೆದರಿಕೆಯ ಮೂಲಕ ತಕ್ಷಣ ಕ್ರಮ ಕೈಗೊಳ್ಳಲು ಒತ್ತಾಯಿಸುತ್ತದೆ",

        "Promises money or prizes":
            "ಹಣ ಅಥವಾ ಬಹುಮಾನ ನೀಡುವುದಾಗಿ ಹೇಳುತ್ತದೆ",

        "Asks you to pay a fee or deposit":
            "ಶುಲ್ಕ ಅಥವಾ ಠೇವಣಿ ಪಾವತಿಸಲು ಕೇಳುತ್ತದೆ",

        "Uses a KYC, refund or fee lure":
            "KYC, ಮರುಪಾವತಿ ಅಥವಾ ಶುಲ್ಕದ ಆಮಿಷ ಬಳಸುತ್ತದೆ",

        "Possible impersonation of an organization":
            "ಸಂಸ್ಥೆಯ ಹೆಸರನ್ನು ಬಳಸಿಕೊಂಡು ವಂಚಿಸುವ ಸಾಧ್ಯತೆ ಇದೆ",

        "Link has risk signals (a signal, not proof of malice)":
            "ಲಿಂಕ್‌ನಲ್ಲಿ ಅಪಾಯದ ಸೂಚನೆಗಳಿವೆ",

        "No major scam pattern detected.":
            "ಪ್ರಮುಖ ವಂಚನೆ ಮಾದರಿ ಕಂಡುಬಂದಿಲ್ಲ.",
        "Do not click any link.": "ಯಾವುದೇ ಲಿಂಕ್ ಅನ್ನು ಕ್ಲಿಕ್ ಮಾಡಬೇಡಿ.",
        "Do not share OTP, PIN, password or Aadhaar details.":
            "OTP, PIN, ಪಾಸ್‌ವರ್ಡ್ ಅಥವಾ ಆಧಾರ್ ವಿವರಗಳನ್ನು ಹಂಚಿಕೊಳ್ಳಬೇಡಿ.",
        "Do not transfer money.": "ಹಣವನ್ನು ವರ್ಗಾಯಿಸಬೇಡಿ.",
        "Verify through the organization's official website or app.":
            "ಸಂಸ್ಥೆಯ ಅಧಿಕೃತ ವೆಬ್‌ಸೈಟ್ ಅಥವಾ ಆ್ಯಪ್ ಮೂಲಕ ಪರಿಶೀಲಿಸಿ.",
        "If you already acted, report at cybercrime.gov.in or call 1930.":
            "ನೀವು ಈಗಾಗಲೇ ಕ್ರಮ ಕೈಗೊಂಡಿದ್ದರೆ, cybercrime.gov.in ನಲ್ಲಿ ವರದಿ ಮಾಡಿ ಅಥವಾ 1930 ಗೆ ಕರೆ ಮಾಡಿ.",
        "Do not act immediately.": "ತಕ್ಷಣ ಕ್ರಮ ಕೈಗೊಳ್ಳಬೇಡಿ.",
        "Check the sender and official source.": "ಕಳುಹಿಸಿದವರನ್ನು ಮತ್ತು ಅಧಿಕೃತ ಮೂಲವನ್ನು ಪರಿಶೀಲಿಸಿ.",
        "Avoid sharing sensitive information.": "ಸೂಕ್ಷ್ಮ ಮಾಹಿತಿಯನ್ನು ಹಂಚಿಕೊಳ್ಳುವುದನ್ನು ತಪ್ಪಿಸಿ.",
        "Verify the request independently.": "ಈ ವಿನಂತಿಯನ್ನು ಸ್ವತಂತ್ರವಾಗಿ ಪರಿಶೀಲಿಸಿ.",
        "Still verify unexpected requests before acting.":
            "ಅನಿರೀಕ್ಷಿತ ವಿನಂತಿಗಳ ಮೇಲೆ ಕ್ರಮ ಕೈಗೊಳ್ಳುವ ಮೊದಲು ಪರಿಶೀಲಿಸಿ.",
        "ScamShield Verify is an assistive cybersecurity tool. It cannot guarantee that a message is safe or fraudulent. Always verify sensitive requests through the organization's official channels.":
            "ಇದು ಸೈಬರ್ ಸುರಕ್ಷತೆಗೆ ಸಹಾಯ ಮಾಡುವ ಸಾಧನವಾಗಿದೆ. ಸಂದೇಶ ಸುರಕ್ಷಿತವೇ ಅಥವಾ ವಂಚನೆಯೇ ಎಂದು ಇದು ಖಚಿತಪಡಿಸುವುದಿಲ್ಲ. ಸೂಕ್ಷ್ಮ ವಿನಂತಿಗಳನ್ನು ಸಂಸ್ಥೆಯ ಅಧಿಕೃತ ಮಾರ್ಗಗಳ ಮೂಲಕ ಯಾವಾಗಲೂ ಪರಿಶೀಲಿಸಿ.",
        "A pattern match shows similarity to a known scam style. It is not proof of fraud.":
            "ಮಾದರಿಯ ಹೊಂದಾಣಿಕೆಯು ಪರಿಚಿತ ವಂಚನೆ ಶೈಲಿಯ ಹೋಲಿಕೆಯನ್ನು ತೋರಿಸುತ್ತದೆ; ಇದು ವಂಚನೆಯ ಪುರಾವೆಯಲ್ಲ.",
        "Uncommon top-level domain": "ಅಪರೂಪದ ಉನ್ನತ-ಮಟ್ಟದ ಡೊಮೇನ್",
        "URL shortener hides the real destination": "URL ಸಂಕ್ಷಿಪ್ತಗೊಳಿಸುವ ಸೇವೆಯು ನಿಜವಾದ ಗಮ್ಯಸ್ಥಾನವನ್ನು ಮರೆಮಾಡುತ್ತದೆ",
        "Not using HTTPS": "HTTPS ಬಳಸುತ್ತಿಲ್ಲ",
        "Domain name looks unusual": "ಡೊಮೇನ್ ಹೆಸರು ಅಸಾಮಾನ್ಯವಾಗಿ ಕಾಣುತ್ತದೆ",
        "Bank OTP scam": "ಬ್ಯಾಂಕ್ OTP ವಂಚನೆ",
        "Fake KYC": "ನಕಲಿ KYC",
        "Government reward": "ಸರ್ಕಾರಿ ಬಹುಮಾನ",
        "Delivery or refund fraud": "ವಿತರಣೆ ಅಥವಾ ಮರುಪಾವತಿ ವಂಚನೆ",
        "Job-fee scam": "ಉದ್ಯೋಗ ಶುಲ್ಕ ವಂಚನೆ",
        "Organization impersonation": "ಸಂಸ್ಥೆಯ ಸೋಗು ಹಾಕುವುದು",
        "Pressure": "ಒತ್ತಡ",
        "Lure": "ಆಮಿಷ",
        "Data harvesting": "ಮಾಹಿತಿ ಸಂಗ್ರಹ",
        "Pretext": "ನೆಪ",
        "Payment demand": "ಪಾವತಿ ಬೇಡಿಕೆ",
        "Redirect to a link": "ಲಿಂಕ್‌ಗೆ ಮರುನಿರ್ದೇಶನ",
        "Borrowed authority": "ಸಂಸ್ಥೆಯ ಹೆಸರಿನ ದುರುಪಯೋಗ",
        "Password": "ಪಾಸ್‌ವರ್ಡ್",
        "Aadhaar": "ಆಧಾರ್",
        "Card/bank details": "ಕಾರ್ಡ್/ಬ್ಯಾಂಕ್ ವಿವರಗಳು",
        "Payment": "ಪಾವತಿ",
        "This message": "ಈ ಸಂದೇಶ",
        "claims to be": "ಇದೆಂದು ಹೇಳಿಕೊಳ್ಳುತ್ತದೆ",
        "contains link": "ಲಿಂಕ್ ಹೊಂದಿದೆ",
        "domain mismatch": "ಡೊಮೇನ್ ಹೊಂದಿಕೆಯಾಗುವುದಿಲ್ಲ",
        "gives number": "ಸಂಖ್ಯೆಯನ್ನು ನೀಡುತ್ತದೆ",
        "asks payment to": "ಪಾವತಿಯನ್ನು ಕೇಳುತ್ತದೆ",
        "asserts": "ಹೇಳುತ್ತದೆ",
    },

    "hi": {
        "Likely scam": "संभावित धोखाधड़ी",
        "Uncertain": "अनिश्चित",
        "Likely legitimate": "संभावित रूप से सुरक्षित संदेश",

        "Asks you to share an OTP, PIN or CVV":
            "OTP, PIN या CVV साझा करने के लिए कहता है",

        "Asks for passwords, Aadhaar or bank/card details":
            "पासवर्ड, आधार या बैंक/कार्ड विवरण मांगता है",

        "Uses urgency or threats to rush you":
            "जल्दबाजी या धमकी देकर तुरंत कार्रवाई करने को कहता है",

        "Promises money or prizes":
            "पैसे या पुरस्कार देने का वादा करता है",

        "Asks you to pay a fee or deposit":
            "शुल्क या जमा राशि देने के लिए कहता है",

        "Uses a KYC, refund or fee lure":
            "KYC, रिफंड या शुल्क का लालच देता है",

        "Possible impersonation of an organization":
            "किसी संस्था का रूप धारण करने की संभावना है",

        "Link has risk signals (a signal, not proof of malice)":
            "लिंक में जोखिम के संकेत हैं",

        "No major scam pattern detected.":
            "कोई प्रमुख धोखाधड़ी पैटर्न नहीं मिला।",
        "Do not click any link.": "किसी भी लिंक पर क्लिक न करें।",
        "Do not share OTP, PIN, password or Aadhaar details.":
            "OTP, PIN, पासवर्ड या आधार विवरण साझा न करें।",
        "Do not transfer money.": "पैसे ट्रांसफर न करें।",
        "Verify through the organization's official website or app.":
            "संस्था की आधिकारिक वेबसाइट या ऐप के माध्यम से सत्यापित करें।",
        "If you already acted, report at cybercrime.gov.in or call 1930.":
            "यदि आपने पहले ही कार्रवाई की है, तो cybercrime.gov.in पर रिपोर्ट करें या 1930 पर कॉल करें।",
        "Do not act immediately.": "तुरंत कार्रवाई न करें।",
        "Check the sender and official source.": "भेजने वाले और आधिकारिक स्रोत की जांच करें।",
        "Avoid sharing sensitive information.": "संवेदनशील जानकारी साझा करने से बचें।",
        "Verify the request independently.": "अनुरोध को स्वतंत्र रूप से सत्यापित करें।",
        "Still verify unexpected requests before acting.":
            "अप्रत्याशित अनुरोधों पर कार्रवाई करने से पहले सत्यापित करें।",
        "ScamShield Verify is an assistive cybersecurity tool. It cannot guarantee that a message is safe or fraudulent. Always verify sensitive requests through the organization's official channels.":
            "यह साइबर सुरक्षा में सहायता करने वाला उपकरण है। यह गारंटी नहीं दे सकता कि कोई संदेश सुरक्षित है या धोखाधड़ी है। संवेदनशील अनुरोधों को हमेशा संस्था के आधिकारिक माध्यमों से सत्यापित करें।",
        "A pattern match shows similarity to a known scam style. It is not proof of fraud.":
            "पैटर्न का मेल किसी ज्ञात धोखाधड़ी शैली से समानता दिखाता है; यह धोखाधड़ी का प्रमाण नहीं है।",
        "Uncommon top-level domain": "असामान्य शीर्ष-स्तरीय डोमेन",
        "URL shortener hides the real destination": "URL छोटा करने वाली सेवा वास्तविक गंतव्य छिपाती है",
        "Not using HTTPS": "HTTPS का उपयोग नहीं किया गया है",
        "Domain name looks unusual": "डोमेन नाम असामान्य लगता है",
        "Bank OTP scam": "बैंक OTP धोखाधड़ी",
        "Fake KYC": "नकली KYC",
        "Government reward": "सरकारी इनाम",
        "Delivery or refund fraud": "डिलीवरी या रिफंड धोखाधड़ी",
        "Job-fee scam": "नौकरी शुल्क धोखाधड़ी",
        "Organization impersonation": "संस्था का रूप धारण करना",
        "Pressure": "दबाव",
        "Lure": "लालच",
        "Data harvesting": "जानकारी जुटाना",
        "Pretext": "बहाना",
        "Payment demand": "भुगतान की मांग",
        "Redirect to a link": "लिंक पर भेजना",
        "Borrowed authority": "संस्था के नाम का दुरुपयोग",
        "Password": "पासवर्ड",
        "Aadhaar": "आधार",
        "Card/bank details": "कार्ड/बैंक विवरण",
        "Payment": "भुगतान",
        "This message": "यह संदेश",
        "claims to be": "होने का दावा करता है",
        "contains link": "इसमें लिंक है",
        "domain mismatch": "डोमेन मेल नहीं खाता",
        "gives number": "नंबर देता है",
        "asks payment to": "भुगतान मांगता है",
        "asserts": "दावा करता है",
    },
}


def localized_analysis(result, language):
    result = copy.deepcopy(result)

    if language == "en":
        result["output_language"] = language
        result["translation_status"] = "original"
        return result

    dictionary = TRANSLATIONS.get(
        language,
        {}
    )

    def localize_text(value):
        return dictionary.get(value, value)

    translated = llm_json(
        f"""
Translate the user-facing analysis text into {LANGUAGES[language]}.
Return JSON only, preserving every array length and all numeric/technical values.
Do not translate URLs, phone numbers, evidence, claims, organization names, or identifiers.
Required keys: classification, signal_labels, claim_reasons, actions,
timeline_labels, disclaimer. Keep array order unchanged.
Input:
{json.dumps({
    "classification": result.get("classification", ""),
    "signal_labels": [item.get("label", "") for item in result.get("signals", [])],
    "claim_reasons": [item.get("reason", "") for item in result.get("claims", [])],
    "actions": result.get("actions", []),
    "timeline_labels": [item.get("label", "") for item in result.get("timeline", [])],
    "disclaimer": result.get("disclaimer", ""),
}, ensure_ascii=False)}
"""
    )

    valid_translation = (
        isinstance(translated, dict)
        and isinstance(translated.get("classification"), str)
        and isinstance(translated.get("signal_labels"), list)
        and len(translated["signal_labels"]) == len(result.get("signals", []))
        and all(isinstance(item, str) for item in translated["signal_labels"])
        and isinstance(translated.get("claim_reasons"), list)
        and len(translated["claim_reasons"]) == len(result.get("claims", []))
        and all(isinstance(item, str) for item in translated["claim_reasons"])
        and isinstance(translated.get("actions"), list)
        and len(translated["actions"]) == len(result.get("actions", []))
        and all(isinstance(item, str) for item in translated["actions"])
        and isinstance(translated.get("timeline_labels"), list)
        and len(translated["timeline_labels"]) == len(result.get("timeline", []))
        and all(isinstance(item, str) for item in translated["timeline_labels"])
        and isinstance(translated.get("disclaimer"), str)
    )

    if valid_translation:
        source_values = [
            result.get("classification", ""),
            *[item.get("label", "") for item in result.get("signals", [])],
            *[item.get("reason", "") for item in result.get("claims", [])],
            *result.get("actions", []),
            *[item.get("label", "") for item in result.get("timeline", [])],
            result.get("disclaimer", ""),
        ]
        translated_values = [
            translated["classification"],
            *translated["signal_labels"],
            *translated["claim_reasons"],
            *translated["actions"],
            *translated["timeline_labels"],
            translated["disclaimer"],
        ]
        value_pattern = re.compile(
            r"https?://\S+|www\.\S+|\b\d+(?:[.,]\d+)*\b|"
            r"\b(?:OTP|PIN|CVV|Aadhaar|KYC)\b",
            re.IGNORECASE,
        )
        valid_translation = all(
            [value.lower() for value in value_pattern.findall(source)]
            == [value.lower() for value in value_pattern.findall(destination)]
            for source, destination in zip(source_values, translated_values)
        )

    if valid_translation:
        result["classification"] = translated["classification"]
        result["disclaimer"] = translated["disclaimer"]
        for item, label in zip(result.get("signals", []), translated["signal_labels"]):
            item["label"] = label
        for item, reason in zip(result.get("claims", []), translated["claim_reasons"]):
            item["reason"] = reason
        result["actions"] = translated["actions"]
        for item, label in zip(result.get("timeline", []), translated["timeline_labels"]):
            item["label"] = label
    else:
        result["classification"] = localize_text(result.get("classification", ""))
        result["disclaimer"] = localize_text(result.get("disclaimer", ""))
        for item in result.get("signals", []):
            item["label"] = localize_text(item.get("label", ""))
        for item in result.get("claims", []):
            status = item.get("status")
            evidence = item.get("evidence", [])
            if status == "UNSUPPORTED":
                item["reason"] = {
                    "kn": "ವಿಶ್ವಾಸಾರ್ಹ ಡೇಟಾಬೇಸ್‌ನಲ್ಲಿ ಇದಕ್ಕೆ ಹೊಂದುವ ಅಧಿಕೃತ ಮೂಲ ಕಂಡುಬಂದಿಲ್ಲ.",
                    "hi": "विश्वसनीय डेटाबेस में इससे मिलता-जुलता कोई आधिकारिक स्रोत नहीं मिला।",
                }[language]
            elif status == "CONTRADICTED":
                organization = evidence[0].get("org", "") if evidence else ""
                item["reason"] = {
                    "kn": f"{organization} ನೀಡಿರುವ ಅಧಿಕೃತ ಮಾರ್ಗದರ್ಶನವು ಇದನ್ನು ಶಿಫಾರಸು ಮಾಡುವುದಿಲ್ಲ.",
                    "hi": f"{organization} का आधिकारिक मार्गदर्शन इसकी सलाह नहीं देता।",
                }[language]
            else:
                item["reason"] = {
                    "kn": "ಸಂಬಂಧಿತ ಅಧಿಕೃತ ಮಾರ್ಗದರ್ಶನವಿದೆ, ಆದರೆ ಅದು ಈ ಹೇಳಿಕೆಯನ್ನು ದೃಢೀಕರಿಸಲು ಅಥವಾ ನಿರಾಕರಿಸಲು ಸಾಧ್ಯವಿಲ್ಲ.",
                    "hi": "संबंधित आधिकारिक मार्गदर्शन उपलब्ध है, लेकिन यह इस दावे की पुष्टि या खंडन नहीं कर सकता।",
                }[language]
        result["actions"] = [
            localize_text(action)
            for action in result.get("actions", [])
        ]
        for item in result.get("timeline", []):
            label = item.get("label", "")
            if label.startswith("Overall risk level: "):
                item["label"] = {
                    "kn": f"ಒಟ್ಟಾರೆ ಅಪಾಯದ ಮಟ್ಟ: {result.get('level', '')}",
                    "hi": f"कुल जोखिम स्तर: {result.get('level', '')}",
                }[language]
            else:
                item["label"] = localize_text(label)
    for item in result.get("urls", []):
        localized_reasons = []
        for reason in item.get("reasons", []):
            match = re.fullmatch(
                r"Contains '([^']+)' but is not that organization's domain",
                reason,
            )
            if match:
                domain = match.group(1)
                localized_reasons.append({
                    "kn": f"'{domain}' ಒಳಗೊಂಡಿದೆ, ಆದರೆ ಅದು ಆ ಸಂಸ್ಥೆಯ ಡೊಮೇನ್ ಅಲ್ಲ.",
                    "hi": f"इसमें '{domain}' है, लेकिन यह उस संस्था का डोमेन नहीं है।",
                }[language])
            else:
                localized_reasons.append(localize_text(reason))
        item["reasons"] = localized_reasons
    for item in result.get("impersonation", []):
        item["result"] = {
            "kn": "ಸಂಸ್ಥೆಯ ಸೋಗು ಹಾಕುವ ಸಾಧ್ಯತೆ",
            "hi": "संस्था का रूप धारण करने की संभावना",
        }[language]
        item["reason"] = {
            "kn": f"ಲಿಂಕ್‌ನ ಡೊಮೇನ್ {item.get('claimed_org', '')} ನ ತಿಳಿದಿರುವ ಅಧಿಕೃತ ಡೊಮೇನ್‌ಗಳಿಗೆ ಹೊಂದಿಕೆಯಾಗುವುದಿಲ್ಲ.",
            "hi": f"लिंक का डोमेन {item.get('claimed_org', '')} के ज्ञात आधिकारिक डोमेन से मेल नहीं खाता।",
        }[language]
    for item in result.get("patterns", []):
        item["name"] = localize_text(item.get("name", ""))
        if "detail" in item:
            item["detail"] = localize_text(item["detail"])
    for item in result.get("timeline", []):
        item["tactic"] = localize_text(item.get("tactic", ""))
    if result.get("pattern_note"):
        result["pattern_note"] = localize_text(result["pattern_note"])
    entities = result.get("entities", {})
    if "requested_info" in entities:
        entities["requested_info"] = [
            localize_text(value)
            for value in entities["requested_info"]
        ]
    graph = result.get("graph", {})
    for node in graph.get("nodes", []):
        node["label"] = localize_text(node.get("label", ""))
    for edge in graph.get("edges", []):
        edge["label"] = localize_text(edge.get("label", ""))

    result["output_language"] = language
    result["translation_status"] = "translated"

    return result


localize_analysis = localized_analysis


# ============================================================
# LANGUAGE ENDPOINTS
# ============================================================

@app.get("/api/languages")
def languages():
    return {
        "input": [
            {
                "code": "auto",
                "name": "Auto-detect"
            }
        ]
        + [
            {
                "code": code,
                "name": name
            }
            for code, name
            in LANGUAGES.items()
        ],

        "output": [
            {
                "code": code,
                "name": name
            }
            for code, name
            in LANGUAGES.items()
        ],

        "speech": [
            {
                "code": code,
                "name": name
            }
            for code, name
            in LANGUAGES.items()
        ],
    }


@app.post("/api/language/preferences")
def language_preferences(
    body: LanguagePreferencesIn
):
    return body.model_dump()


# ============================================================
# ANALYSIS
# ============================================================

@app.get("/api/health")
def health():
    return {
        "status": "ok",
        "llm_configured": LLM_ON,
        "mode":
            "AI + deterministic rules"
            if LLM_ON
            else "deterministic rules",
    }


@app.post("/api/auth/register", status_code=201)
def register(body: AuthRegisterIn, request: Request, response: Response):
    rate_check(request, "auth-register", 5)
    email = body.email.strip().casefold()
    name = body.name.strip()
    try:
        user_id = db_execute(
            """
            INSERT INTO users (name, email, password_hash, created_at)
            VALUES (?, ?, ?, ?)
            """,
            (name, email, password_hash(body.password), time.time()),
        )
    except sqlite3.IntegrityError as exc:
        raise HTTPException(
            status_code=409,
            detail="An account with this email already exists.",
        ) from exc

    user = {"id": user_id, "name": name, "email": email}
    token = issue_session(user_id, request, response)
    return {"user": user, "token": token}


@app.post("/api/auth/login")
def login(body: AuthLoginIn, request: Request, response: Response):
    rate_check(request, "auth-login", 10)
    email = body.email.strip().casefold()
    rows = db_execute(
        """
        SELECT id, name, email, password_hash
        FROM users
        WHERE email = ?
        """,
        (email,),
    )
    if not rows or not verify_password(body.password, rows[0][3]):
        raise HTTPException(
            status_code=401,
            detail="Email or password is incorrect.",
        )

    user = {"id": rows[0][0], "name": rows[0][1], "email": rows[0][2]}
    token = issue_session(user["id"], request, response)
    return {"user": user, "token": token}


@app.get("/api/auth/me")
def auth_me(request: Request):
    user = authenticated_user(request)
    return {"authenticated": user is not None, "user": user}


@app.post("/api/auth/logout")
def logout(request: Request, response: Response):
    authorization = request.headers.get("authorization", "")
    scheme, _, bearer_token = authorization.partition(" ")
    token = bearer_token.strip() if scheme.casefold() == "bearer" else request.cookies.get(AUTH_COOKIE_NAME)
    if token:
        db_execute(
            "DELETE FROM sessions WHERE token_hash = ?",
            (session_token_hash(token),),
        )
    response.delete_cookie(
        AUTH_COOKIE_NAME,
        path="/",
        secure=AUTH_COOKIE_SECURE or request.url.scheme == "https",
        httponly=True,
        samesite="lax",
    )
    return {"logged_out": True}


@app.post("/api/analyze/text")
def analyze_text(
    body: TextIn,
    request: Request
):
    rate_check(
        request,
        "analysis",
        30
    )

    text = clean_text(
        body.text
    )

    result = full_analysis(
        text,
        use_llm=True
    )

    result.update(
        intel.enrich(text, result)
    )

    result = localize_analysis(
        result,
        body.output_language
    )

    result["input_language"] = (
        body.input_language
    )

    input_type = (
        body.input_type
        if body.input_type
        in {
            "text",
            "screenshot",
            "url"
        }
        else "text"
    )

    snippet = re.sub(
        r"\d",
        "*",
        text[:100]
    )

    case_id = db_execute(
        """
        INSERT INTO cases
        (
            ts,
            input_type,
            language,
            score,
            level,
            patterns,
            snippet,
            result,
            user_id
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            time.time(),
            input_type,
            result["language"]["language"],
            result["score"],
            result["level"],
            json.dumps(
                result["patterns"],
                ensure_ascii=False
            ),
            snippet,
            json.dumps(
                result,
                ensure_ascii=False
            ),
            request.state.user["id"],
        )
    )

    result["id"] = case_id

    log.info(
        "Analyzed case=%s level=%s ai=%s",
        case_id,
        result["level"],
        result["ai_used"]
    )

    return result


# ============================================================
# IMAGE OCR
# ============================================================

def perform_ocr(
    data: bytes,
    ocr_language: str
):
    try:
        import pytesseract
        from PIL import Image
    except ImportError:
        raise HTTPException(
            status_code=503,
            detail=(
                "OCR libraries are not installed. "
                "Install pillow and pytesseract."
            )
        )

    tesseract_path = os.getenv(
        "TESSERACT_CMD",
        r"C:\Program Files\Tesseract-OCR\tesseract.exe"
    )

    if os.path.exists(tesseract_path):
        pytesseract.pytesseract.tesseract_cmd = (
            tesseract_path
        )

    try:
        image = Image.open(
            io.BytesIO(data)
        )

        image.load()

    except Exception:
        raise HTTPException(
            status_code=400,
            detail="That file is not a valid image."
        )

    language_map = {
        "auto": "eng+kan+hin",
        "en": "eng",
        "kn": "eng+kan",
        "hi": "eng+hin",
    }

    selected_lang = language_map[
        ocr_language
    ]

    fallback = False

    try:
        try:
            text = pytesseract.image_to_string(
                image,
                lang=selected_lang
            )
        except Exception:
            text = pytesseract.image_to_string(
                image,
                lang="eng"
            )
            fallback = (
                selected_lang != "eng"
            )

    except Exception as exc:
        log.warning(
            "OCR failed: %s",
            exc
        )

        raise HTTPException(
            status_code=503,
            detail=(
                "Tesseract OCR is not configured. "
                "You can paste the message text instead."
            )
        )

    return {
        "text": text.strip(),
        "ocr_language": ocr_language,
        "ocr_fallback": fallback,
    }


@app.post("/api/ocr")
async def ocr(
    file: UploadFile = File(...),
    ocr_language: Literal[
        "auto",
        "en",
        "kn",
        "hi"
    ] = Form("auto")
):
    if file.content_type not in {
        "image/png",
        "image/jpeg",
        "image/webp",
    }:
        raise HTTPException(
            status_code=415,
            detail="Upload a PNG, JPG or WebP screenshot."
        )

    data = await file.read()

    if len(data) > 5 * 1024 * 1024:
        raise HTTPException(
            status_code=413,
            detail="Image is larger than 5 MB."
        )

    return perform_ocr(
        data,
        ocr_language
    )


@app.post("/api/analyze/image")
async def analyze_image(
    request: Request,
    file: UploadFile = File(...),
    input_language: Literal[
        "auto",
        "en",
        "kn",
        "hi"
    ] = Form("auto"),
    output_language: Literal[
        "en",
        "kn",
        "hi"
    ] = Form("en"),
    ocr_language: Literal[
        "auto",
        "en",
        "kn",
        "hi"
    ] = Form("auto"),
):
    rate_check(
        request,
        "analysis",
        30
    )

    if file.content_type not in {
        "image/png",
        "image/jpeg",
        "image/webp",
    }:
        raise HTTPException(
            status_code=415,
            detail="Upload a PNG, JPG or WebP screenshot."
        )

    data = await file.read()

    if len(data) > 5 * 1024 * 1024:
        raise HTTPException(
            status_code=413,
            detail="Image is larger than 5 MB."
        )

    ocr_result = perform_ocr(
        data,
        ocr_language
    )

    text = clean_text(
        ocr_result["text"]
    )

    result = full_analysis(
        text,
        use_llm=True
    )

    result.update(
        intel.enrich(text, result)
    )

    result = localize_analysis(
        result,
        output_language
    )

    result["input_language"] = (
        input_language
    )

    result["input_type"] = "screenshot"
    result["ocr_text"] = text
    result["ocr_language"] = (
        ocr_language
    )

    snippet = re.sub(
        r"\d",
        "*",
        text[:100]
    )

    case_id = db_execute(
        """
        INSERT INTO cases
        (
            ts,
            input_type,
            language,
            score,
            level,
            patterns,
            snippet,
            result,
            user_id
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            time.time(),
            "screenshot",
            result["language"]["language"],
            result["score"],
            result["level"],
            json.dumps(
                result["patterns"],
                ensure_ascii=False
            ),
            snippet,
            json.dumps(
                result,
                ensure_ascii=False
            ),
            request.state.user["id"],
        )
    )

    result["id"] = case_id

    return result


# ============================================================
# CLAIM VERIFICATION API
# ============================================================

@app.post("/api/verify/claim")
def verify(body: ClaimIn):
    claim = clean_text(
        body.claim
    )[:300]

    return verify_claim(
        claim
    )


# ============================================================
# SOURCES
# ============================================================

@app.get("/api/sources")
def sources():
    return [
        {
            key: source.get(key)
            for key in (
                "id",
                "title",
                "org",
                "url",
                "category",
                "language",
            )
        }
        for source in SOURCES
    ]


# ============================================================
# SPEECH / TRANSLATION
# ============================================================


class TtsIn(BaseModel):
    text: str = Field(min_length=1, max_length=1500)
    language: Literal["en", "kn", "hi"] = "en"


@app.post("/api/speech/tts")
def speech_tts(body: TtsIn):
    try:
        from gtts import gTTS
    except ImportError:
        raise HTTPException(status_code=501, detail="Install gTTS: pip install gTTS")
    try:
        buf = io.BytesIO()
        gTTS(text=body.text, lang=body.language).write_to_fp(buf)
    except Exception as exc:
        log.warning("TTS failed: %s", exc)
        raise HTTPException(status_code=502, detail="Voice service unavailable (internet required).")
    return Response(content=buf.getvalue(), media_type="audio/mpeg")


@app.post("/api/speech/text")
def speech_text(
    body: SpeechIn,
    request: Request
):
    rate_check(
        request,
        "speech",
        20
    )

    if body.text:
        text = body.text.strip()

    elif body.analysis:
        text = (
            f"Risk level: "
            f"{body.analysis.get('level', '')}. "
            f"{body.analysis.get('classification', '')}. "
            f"Recommended actions: "
            + " ".join(
                body.analysis.get(
                    "actions",
                    []
                )
            )
        )

    else:
        raise HTTPException(
            status_code=400,
            detail="Provide text or analysis."
        )

    text = clean_text(text)

    if body.speech_language == "en":
        return {
            "text": text,
            "language": "en",
            "locale": LANGUAGE_LOCALES["en"],
            "translated": True,
        }

    translated = llm_text(
        f"""
Translate the following cybersecurity narration into
{LANGUAGES[body.speech_language]}.

Preserve:
- risk meaning
- numbers
- names
- URLs
- organization names

Return only the translated narration.

Text:
{text}
"""
    )

    if translated:
        return {
            "text": translated,
            "language":
                body.speech_language,
            "locale": LANGUAGE_LOCALES[body.speech_language],
            "translated": True,
        }

    return {
        "text": text,
        "language": body.speech_language,
        "locale": LANGUAGE_LOCALES[body.speech_language],
        "translated": False,
        "message": (
            "Translation requires an LLM configuration. "
            "The frontend can still use browser speech synthesis."
        ),
    }


# ============================================================
# ASSISTANCE / CONTACTS
# ============================================================

def official_assistance_contacts(
    retrieved_at
):
    return [
        {
            "name":
                "National Cyber Crime Helpline",
            "number":
                "1930",
            "purpose":
                "Report online financial cyber fraud promptly.",
            "source_url":
                "https://cybercrime.gov.in/",
            "source_name":
                "National Cyber Crime Reporting Portal",
            "retrieved_at":
                retrieved_at,
        },
        {
            "name":
                "Emergency Response Support System",
            "number":
                "112",
            "purpose":
                (
                    "Immediate police, fire or medical "
                    "emergency; not a cyber-fraud reporting line."
                ),
            "source_url":
                "https://112.gov.in/",
            "source_name":
                "Emergency Response Support System",
            "retrieved_at":
                retrieved_at,
        },
    ]


@app.get("/api/assistance/contacts")
def assistance_contacts():
    fetched_at = datetime.now(
        timezone.utc
    ).isoformat(
        timespec="seconds"
    )

    return {
        "official_contacts":
            official_assistance_contacts(
                fetched_at
            ),
        "retrieved_at":
            fetched_at,
    }


# ============================================================
# DISTANCE
# ============================================================

def distance_km(
    lat1,
    lon1,
    lat2,
    lon2
):
    radius = 6371.0

    lat1 = math.radians(lat1)
    lat2 = math.radians(lat2)

    dlat = lat2 - lat1
    dlon = math.radians(
        lon2 - lon1
    )

    value = (
        math.sin(dlat / 2) ** 2
        + math.cos(lat1)
        * math.cos(lat2)
        * math.sin(dlon / 2) ** 2
    )

    return (
        radius
        * 2
        * math.atan2(
            math.sqrt(value),
            math.sqrt(1 - value)
        )
    )


# ============================================================
# LOCATION ASSISTANCE
# ============================================================

OVERPASS_MIRRORS = [
    OVERPASS_URL,
    "https://overpass.kumi.systems/api/interpreter",
    "https://overpass.private.coffee/api/interpreter",
    "https://maps.mail.ru/osm/tools/overpass/api/interpreter",
]


def overpass_elements(query):
    """Try each Overpass server in turn. Returns a list, or None if all fail."""
    tried = set()
    for url in OVERPASS_MIRRORS:
        if url in tried:
            continue
        tried.add(url)
        try:
            r = httpx.post(
                url,
                data={"data": query},
                headers={"User-Agent": MAP_USER_AGENT},
                timeout=30,
            )
            if r.status_code == 200:
                return r.json().get("elements", [])
            log.warning("Overpass %s returned HTTP %s", url, r.status_code)
        except (httpx.HTTPError, ValueError) as exc:
            log.warning("Overpass %s failed: %s", url, exc)
    return None


def geocode_places(query):
    """Find a place by name: OpenStreetMap Nominatim first, Photon as backup."""
    failures = 0
    try:
        r = httpx.get(
            f"{NOMINATIM_URL}/search",
            params={"q": query, "format": "jsonv2", "limit": 1},
            headers={"User-Agent": MAP_USER_AGENT},
            timeout=12,
        )
        r.raise_for_status()
        data = r.json()
        if data:
            return data
    except (httpx.HTTPError, ValueError) as exc:
        failures += 1
        log.warning("Nominatim geocoding failed: %s", exc)
    try:
        r = httpx.get(
            "https://photon.komoot.io/api/",
            params={"q": query, "limit": 1},
            headers={"User-Agent": MAP_USER_AGENT},
            timeout=12,
        )
        r.raise_for_status()
        found = []
        for feature in r.json().get("features", [])[:1]:
            lon, lat = feature["geometry"]["coordinates"]
            props = feature.get("properties", {})
            name = ", ".join(
                str(x) for x in (props.get("name"), props.get("city"), props.get("state"), props.get("country")) if x
            )
            found.append({"lat": lat, "lon": lon, "display_name": name or query})
        return found
    except (httpx.HTTPError, ValueError, KeyError) as exc:
        failures += 1
        log.warning("Photon geocoding failed: %s", exc)
    if failures == 2:
        raise httpx.HTTPError("Both geocoding services are unreachable from this network.")
    return []



FALLBACK_FILE = Path(__file__).parent / "data" / "fallback_places.json"


def _record(osm_id, name, category, address, phone, website, lat, lon, centre, fetched_at, source_name):
    return {
        "id": osm_id, "name": name, "category": category,
        "address": address or "Address not listed",
        "phone": phone, "phone_verified": False, "official_source": website,
        "source_url": f"https://www.openstreetmap.org/{osm_id}" if str(osm_id).split("/")[0] in ("node", "way", "relation") else "https://www.openstreetmap.org/",
        "source_name": source_name, "verification_date": fetched_at,
        "latitude": lat, "longitude": lon,
        "directions_url": f"https://www.google.com/maps/dir/?api=1&destination={lat},{lon}",
        "distance_km": round(distance_km(centre[0], centre[1], lat, lon), 1),
    }


def nominatim_nearby(lat, lon, categories, fetched_at):
    """Second source: Nominatim bounded search (works when Overpass is blocked)."""
    d = 0.2
    box = f"{lon - d},{lat + d},{lon + d},{lat - d}"
    specs = []
    if {"police", "cybercrime"} & set(categories):
        specs += [("cyber crime police station", "cybercrime"), ("police station", "police")]
    if "emergency" in categories:
        specs += [("hospital", "emergency"), ("fire station", "emergency")]
    found, seen = [], set()
    for q, cat in specs:
        try:
            r = httpx.get(f"{NOMINATIM_URL}/search",
                          params={"q": q, "format": "jsonv2", "limit": 20, "bounded": 1,
                                  "viewbox": box, "extratags": 1},
                          headers={"User-Agent": MAP_USER_AGENT}, timeout=15)
            if r.status_code != 200:
                continue
            for it in r.json():
                oid = f"{it.get('osm_type', 'node')}/{it.get('osm_id')}"
                if oid in seen:
                    continue
                seen.add(oid)
                name = it.get("name") or str(it.get("display_name", "")).split(",")[0] or "Name not listed"
                c = "cybercrime" if re.search(r"cyber", name, re.I) else cat
                if c not in categories:
                    continue
                ex = it.get("extratags") or {}
                found.append(_record(oid, name, c, it.get("display_name", ""), ex.get("phone") or ex.get("contact:phone"),
                                     ex.get("website"), float(it["lat"]), float(it["lon"]), (lat, lon), fetched_at,
                                     "OpenStreetMap (Nominatim) listing, not independently verified"))
        except (httpx.HTTPError, ValueError, KeyError) as exc:
            log.warning("Nominatim nearby failed: %s", exc)
        time.sleep(1.1)
    return found


def curated_nearby(lat, lon, categories, fetched_at):
    """Last resort: small built-in list (approximate coordinates)."""
    try:
        items = json.loads(FALLBACK_FILE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    out = []
    for it in items:
        if it["category"] not in categories:
            continue
        if distance_km(lat, lon, it["lat"], it["lon"]) > 60:
            continue
        out.append(_record(f"curated/{it['name']}", it["name"], it["category"], it["address"], None, None,
                           it["lat"], it["lon"], (lat, lon), fetched_at,
                           "Built-in list, approximate location. Verify before travelling"))
    return out


@app.post("/api/assistance/search")
def assistance_search(
    body: AssistanceIn,
    request: Request
):
    rate_check(
        request,
        "assistance",
        8
    )

    center = None

    if (
        body.latitude is not None
        and body.longitude is not None
    ):
        center = (
            body.latitude,
            body.longitude
        )

    location_name = (
        "Current location"
        if center
        else (
            body.location_query or ""
        ).strip()
    )

    try:

        # ----------------------------------------------------
        # GEOCODE LOCATION
        # ----------------------------------------------------

        if center is None:

            places = geocode_places(location_name)

            if not places:
                raise HTTPException(
                    status_code=404,
                    detail=(
                        "Location could not be found. "
                        "Try a city, locality or PIN code."
                    )
                )

            center = (
                float(places[0]["lat"]),
                float(places[0]["lon"])
            )

            location_name = places[0].get(
                "display_name",
                location_name
            )

        lat, lon = center

        # ----------------------------------------------------
        # OVERPASS QUERY
        # ----------------------------------------------------

        clauses = []
        rad = min(int(body.radius_m), 15000)
        if set(body.categories) & {"police", "cybercrime"}:
            clauses.append(f'nwr(around:{rad},{lat},{lon})["amenity"="police"];')
            clauses.append(f'nwr(around:{rad},{lat},{lon})["office"~"police",i];')
        if "emergency" in body.categories:
            clauses.append(f'nwr(around:{rad},{lat},{lon})["amenity"~"^(fire_station|hospital)$"];')
            clauses.append(f'nwr(around:{rad},{lat},{lon})["emergency"="ambulance_station"];')
        query = "[out:json][timeout:25];(" + "".join(clauses) + ");out center tags 300;"
        elements = overpass_elements(query)
        lookup_failed = elements is None
        if lookup_failed:
            elements = []

        records = []
        seen = set()
        seen_places = set()

        fetched_at = datetime.now(
            timezone.utc
        ).isoformat(
            timespec="seconds"
        )

        # ----------------------------------------------------
        # PROCESS RESULTS
        # ----------------------------------------------------

        for item in elements:

            item_key = (
                item.get("type"),
                item.get("id")
            )

            if item_key in seen:
                continue

            seen.add(item_key)

            tags = item.get(
                "tags",
                {}
            )

            name = next(
                (
                    tags.get(field)
                    for field in (
                        "name",
                        "name:en",
                        "name:kn",
                        "name:hi",
                        "official_name",
                        "short_name",
                        "alt_name",
                    )
                    if tags.get(field)
                ),
                "Name not listed",
            )

            combined_name = " ".join([
                tags.get("name:en", ""),
                tags.get("name:kn", ""),
                tags.get("name:hi", ""),
                tags.get("official_name", ""),
                tags.get("short_name", ""),
                tags.get("alt_name", ""),
                tags.get("operator", ""),
                name,
                tags.get("police", ""),
                tags.get("office", ""),
                tags.get("description", ""),
            ])

            cyber_match = bool(
                re.search(
                    r"cyber\s*crime"
                    r"|cybercrime"
                    r"|cyber\s*cell"
                    r"|cyber\s*police",
                    combined_name,
                    re.IGNORECASE
                )
            )

            amenity = tags.get(
                "amenity",
                ""
            )

            police_tag = tags.get(
                "police",
                ""
            )

            if cyber_match:
                category = "cybercrime"

            elif (
                amenity == "police"
                or police_tag
            ):
                category = "police"

            elif amenity in {
                "fire_station",
                "hospital",
            } or tags.get(
                "emergency"
            ) == "ambulance_station":
                category = "emergency"

            else:
                continue

            if category not in body.categories:
                continue

            point = item.get(
                "center",
                item
            )

            if (
                "lat" not in point
                or "lon" not in point
            ):
                continue

            item_lat = float(
                point["lat"]
            )

            item_lon = float(
                point["lon"]
            )

            normalized_name = re.sub(
                r"\W+",
                "",
                name.casefold(),
            )
            place_key = (
                category,
                normalized_name if normalized_name != "namenotlisted" else item_key,
                round(item_lat, 3),
                round(item_lon, 3),
            )
            if place_key in seen_places:
                continue
            seen_places.add(place_key)

            address_parts = [
                tags.get(key, "")
                for key in (
                    "addr:housenumber",
                    "addr:street",
                    "addr:suburb",
                    "addr:city",
                    "addr:postcode",
                )
            ]

            address = ", ".join(
                part
                for part in address_parts
                if part
            )

            listed_phone = (
                tags.get("contact:phone")
                or tags.get("phone")
            )

            phone = (
                re.sub(
                    r"[^0-9+() ./-]",
                    "",
                    listed_phone
                )
                if listed_phone
                else None
            )

            website = (
                tags.get("website")
                or tags.get("contact:website")
            )

            if website and not website.startswith(
                ("http://", "https://")
            ):
                website = "https://" + website

            official_source = (
                website
                if website
                and urlparse(website).scheme
                in {"http", "https"}
                else None
            )

            osm_type = item.get(
                "type",
                "node"
            )

            osm_id = item.get(
                "id"
            )

            osm_url = (
                f"https://www.openstreetmap.org/"
                f"{osm_type}/{osm_id}"
            )

            records.append({
                "id":
                    f"{osm_type}/{osm_id}",

                "name":
                    name,

                "category":
                    category,

                "address":
                    address
                    or "Address not listed in OpenStreetMap",

                "phone":
                    phone,

                "phone_verified":
                    False,

                "official_source":
                    official_source,

                "source_url":
                    osm_url,

                "source_name":
                    "OpenStreetMap listing "
                    "(not independently verified)",

                "verification_date":
                    fetched_at,

                "latitude":
                    item_lat,

                "longitude":
                    item_lon,

                "directions_url":
                    (
                        "https://www.google.com/maps/dir/"
                        f"?api=1&destination="
                        f"{item_lat},{item_lon}"
                    ),

                "distance_km":
                    round(
                        distance_km(
                            lat,
                            lon,
                            item_lat,
                            item_lon
                        ),
                        1
                    ),
            })

        used_fallback = None
        if not records:
            records = nominatim_nearby(lat, lon, body.categories, fetched_at)
            used_fallback = "nominatim" if records else None
        if not records:
            records = curated_nearby(lat, lon, body.categories, fetched_at)
            used_fallback = "curated" if records else None
        records.sort(
            key=lambda item:
                item["distance_km"]
        )

    except HTTPException:
        raise

    except (
        httpx.HTTPError,
        KeyError,
        ValueError,
    ) as exc:

        log.warning(
            "Assistance lookup failed: %s",
            exc
        )

        raise HTTPException(
            status_code=502,
            detail=(
                "Location search is temporarily unavailable. "
                "Use the official national contacts below."
            )
        )

    # --------------------------------------------------------
    # IMPORTANT NOTE ABOUT CYBERCRIME BRANCHES
    # --------------------------------------------------------

    cybercrime_found = any(
        item["category"] == "cybercrime"
        for item in records
    )

    note = None

    if "cybercrime" in body.categories:
        if not cybercrime_found:
            note = (
                "No mapped cyber crime branch found nearby. "
                "Use the National Cyber Crime Reporting Portal at "
                "https://cybercrime.gov.in/ or call 1930."
            )

    return {
        "location":
            location_name,

        "center": {
            "latitude":
                center[0],
            "longitude":
                center[1],
        },

        "results":
            records,

        "cybercrime_found":
            cybercrime_found,

        "note": (
            "Live map data is slow right now; showing a small built-in list with approximate locations. Verify before travelling."
            if (lookup_failed and used_fallback == "curated")
            else "Nearby map data is temporarily unavailable. Use the official contacts below."
            if (lookup_failed and not records)
            else note
        ),

        "official_contacts":
            official_assistance_contacts(
                fetched_at
            ),

        "retrieved_at":
            fetched_at,

        "attribution":
            (
                "Map and place data © OpenStreetMap contributors. "
                "Listings and phone numbers are not independently verified."
            ),
    }


# ============================================================
# HISTORY
# ============================================================

def load_case(case_id: int, user_id: int):
    rows = db_execute(
        """
        SELECT result, ts
        FROM cases
        WHERE id = ? AND user_id = ?
        """,
        (case_id, user_id)
    )

    if not rows:
        raise HTTPException(
            status_code=404,
            detail="Case not found."
        )

    result = json.loads(
        rows[0][0]
    )

    result["id"] = case_id

    return result, rows[0][1]


@app.get("/api/history")
def history(
    request: Request,
    q: str = "",
    level: str = ""
):
    sql = """
        SELECT
            id,
            ts,
            language,
            score,
            level,
            patterns,
            snippet,
            input_type
        FROM cases
        WHERE user_id = ?
    """

    args = [request.state.user["id"]]

    if q:
        sql += """
            AND (
                snippet LIKE ?
                OR patterns LIKE ?
            )
        """

        args.extend([
            f"%{q}%",
            f"%{q}%",
        ])

    if level:
        sql += " AND level = ?"
        args.append(
            level.upper()
        )

    sql += """
        ORDER BY id DESC
        LIMIT 100
    """

    rows = db_execute(
        sql,
        args
    )

    result = []

    for row in rows:
        result.append({
            "id": row[0],
            "ts": row[1],
            "language": row[2],
            "score": row[3],
            "level": row[4],
            "patterns": [p.get("name", "") if isinstance(p, dict) else str(p) for p in json.loads(row[5])],
            "snippet": row[6],
            "input_type": row[7],
        })

    return result


@app.get("/api/history/{case_id}")
def get_case(case_id: int, request: Request):
    return load_case(
        case_id,
        request.state.user["id"],
    )[0]


@app.delete("/api/history/{case_id}")
def delete_case(case_id: int, request: Request):
    user_id = request.state.user["id"]
    load_case(case_id, user_id)

    db_execute(
        "DELETE FROM cases WHERE id = ? AND user_id = ?",
        (case_id, user_id)
    )

    return {
        "deleted": case_id
    }


@app.delete("/api/history")
def clear_cases(request: Request):
    db_execute(
        "DELETE FROM cases WHERE user_id = ?",
        (request.state.user["id"],)
    )

    return {
        "deleted": "all"
    }


@app.get(
    "/api/history/{case_id}/summary"
)
def case_summary(case_id: int, request: Request):
    result, timestamp = load_case(
        case_id,
        request.state.user["id"],
    )

    summary = (
        f"Analysis from "
        f"{time.strftime('%Y-%m-%d %H:%M', time.localtime(timestamp))}\n\n"
        f"Classification: "
        f"{result.get('classification', '')}\n"
        f"Risk level: "
        f"{result.get('level', '')}\n"
        f"Risk score: "
        f"{result.get('score', 0)}/100\n\n"
        f"Recommended actions:\n"
        + "\n".join(
            "- " + action
            for action in result.get(
                "actions",
                []
            )
        )
        + "\n\nNo report has been filed and no account has been secured by this tool."
    )

    return PlainTextResponse(
        summary
    )


# ============================================================
# STATS
# ============================================================

@app.get("/api/stats")
def stats(request: Request):
    levels = Counter()
    languages = Counter()
    patterns = Counter()
    days = Counter()

    claims_verified = 0
    impersonation_count = 0

    rows = db_execute(
        """
        SELECT
            ts,
            language,
            level,
            patterns,
            result
        FROM cases
        WHERE user_id = ?
        """,
        (request.state.user["id"],)
    )

    for (
        timestamp,
        language,
        level,
        pattern_json,
        result_json,
    ) in rows:

        levels[level] += 1
        languages[language] += 1

        try:
            pattern_data = json.loads(
                pattern_json
            )

            for pattern in pattern_data:
                if isinstance(
                    pattern,
                    dict
                ):
                    patterns[
                        pattern.get(
                            "name",
                            "Unknown"
                        )
                    ] += 1

        except Exception:
            pass

        days[
            time.strftime(
                "%Y-%m-%d",
                time.localtime(timestamp)
            )
        ] += 1

        try:
            result = json.loads(
                result_json
            )

            claims_verified += len(
                result.get(
                    "claims",
                    []
                )
            )

            if result.get(
                "impersonation"
            ):
                impersonation_count += 1

        except Exception:
            pass

    return {
        "total":
            sum(levels.values()),

        "levels":
            dict(levels),

        "patterns":
            dict(patterns),

        "languages":
            dict(languages),

        "claims_verified":
            claims_verified,

        "impersonation":
            impersonation_count,

        "trend":
            dict(sorted(days.items())),
    }


# ============================================================
# ASSISTANT
# ============================================================

def assistant_sources(
    question,
    k=4
):
    hits = retrieve(
        question,
        k
    )

    question_lower = question.lower()

    topic_ids = []

    if re.search(
        r"otp|pin|cvv|password|"
        r"ಬ್ಯಾಂಕ್|ಒಟಿಪಿ|पासवर्ड|ओटीपी",
        question_lower,
        re.IGNORECASE
    ):
        topic_ids.append(
            "rbi-1"
        )

    if re.search(
        r"link|phish|click|"
        r"ಫಿಶಿಂಗ್|ಲಿಂಕ್|फिशिंग|लिंक",
        question_lower,
        re.IGNORECASE
    ):
        topic_ids.append(
            "cert-1"
        )

    if re.search(
        r"aadhaar|aadhar|"
        r"ಆಧಾರ್|आधार",
        question_lower,
        re.IGNORECASE
    ):
        topic_ids.append(
            "uidai-1"
        )

    if re.search(
        r"report|fraud|scam|complain|1930|"
        r"ವಂಚನೆ|ವರದಿ|ದೂರು|धोखाधड़ी|रिपोर्ट",
        question_lower,
        re.IGNORECASE
    ):
        topic_ids.append(
            "cyber-1"
        )

    found = {
        hit["id"]
        for hit in hits
    }

    for source_id in topic_ids:

        source = next(
            (
                item
                for item in SOURCES
                if item["id"] == source_id
            ),
            None
        )

        if (
            source
            and source_id not in found
        ):
            hits.append({
                "id":
                    source["id"],
                "title":
                    source["title"],
                "org":
                    source["org"],
                "url":
                    source["url"],
                "text":
                    source["text"],
                "retrieved_on":
                    source.get(
                        "retrieved_on",
                        ""
                    ),
                "score":
                    1.0,
            })

            found.add(
                source_id
            )

    return hits[:k]


def assistant_fallback(question, analysis, language):
    q = question.lower()
    lang = language if language in ("en", "kn", "hi") else "en"
    texts = {
        "report": {
            "en": "You can report online financial fraud at https://cybercrime.gov.in/ or call 1930. This tool has not reported anything for you.",
            "kn": "ಆನ್‌ಲೈನ್ ಹಣಕಾಸು ವಂಚನೆಯನ್ನು https://cybercrime.gov.in/ ನಲ್ಲಿ ವರದಿ ಮಾಡಬಹುದು ಅಥವಾ 1930 ಗೆ ಕರೆ ಮಾಡಬಹುದು. ಈ ಸಾಧನವು ನಿಮ್ಮ ಪರವಾಗಿ ಏನನ್ನೂ ವರದಿ ಮಾಡಿಲ್ಲ.",
            "hi": "ऑनलाइन वित्तीय धोखाधड़ी की रिपोर्ट https://cybercrime.gov.in/ पर करें या 1930 पर कॉल करें। इस टूल ने आपकी ओर से कुछ भी रिपोर्ट नहीं किया है।",
        },
        "acted": {
            "en": "Contact your bank right away using the number on your card or official app, change affected passwords, and report at https://cybercrime.gov.in/ or call 1930.",
            "kn": "ನಿಮ್ಮ ಕಾರ್ಡ್ ಅಥವಾ ಅಧಿಕೃತ ಆ್ಯಪ್‌ನಲ್ಲಿರುವ ಸಂಖ್ಯೆಯ ಮೂಲಕ ತಕ್ಷಣ ನಿಮ್ಮ ಬ್ಯಾಂಕ್ ಅನ್ನು ಸಂಪರ್ಕಿಸಿ, ಪಾಸ್‌ವರ್ಡ್‌ಗಳನ್ನು ಬದಲಾಯಿಸಿ, ಮತ್ತು https://cybercrime.gov.in/ ನಲ್ಲಿ ವರದಿ ಮಾಡಿ ಅಥವಾ 1930 ಗೆ ಕರೆ ಮಾಡಿ.",
            "hi": "अपने कार्ड या आधिकारिक ऐप पर दिए नंबर से तुरंत बैंक से संपर्क करें, प्रभावित पासवर्ड बदलें, और https://cybercrime.gov.in/ पर रिपोर्ट करें या 1930 पर कॉल करें।",
        },
        "safe": {
            "en": "The rule-based score is {score}/100 ({level}). It is a risk estimate, not proof. Verify through the organization's official website or app.",
            "kn": "ನಿಯಮ ಆಧಾರಿತ ಅಂಕ {score}/100 ({level}). ಇದು ಅಪಾಯದ ಅಂದಾಜು, ಪುರಾವೆಯಲ್ಲ. ಸಂಸ್ಥೆಯ ಅಧಿಕೃತ ವೆಬ್‌ಸೈಟ್ ಅಥವಾ ಆ್ಯಪ್ ಮೂಲಕ ಪರಿಶೀಲಿಸಿ.",
            "hi": "नियम-आधारित स्कोर {score}/100 ({level}) है। यह जोखिम का अनुमान है, प्रमाण नहीं। संस्था की आधिकारिक वेबसाइट या ऐप से सत्यापित करें।",
        },
        "default": {
            "en": "Analyze a message first, or ask about reporting fraud, OTP safety or phishing. Verify unexpected requests through official channels.",
            "kn": "ಮೊದಲು ಒಂದು ಸಂದೇಶವನ್ನು ವಿಶ್ಲೇಷಿಸಿ, ಅಥವಾ ವಂಚನೆ ವರದಿ, OTP ಸುರಕ್ಷತೆ ಅಥವಾ ಫಿಶಿಂಗ್ ಬಗ್ಗೆ ಕೇಳಿ. ಅನಿರೀಕ್ಷಿತ ವಿನಂತಿಗಳನ್ನು ಅಧಿಕೃತ ಮಾರ್ಗಗಳ ಮೂಲಕ ಪರಿಶೀಲಿಸಿ.",
            "hi": "पहले किसी संदेश का विश्लेषण करें, या धोखाधड़ी की रिपोर्ट, OTP सुरक्षा या फ़िशिंग के बारे में पूछें। अप्रत्याशित अनुरोधों को आधिकारिक माध्यमों से सत्यापित करें।",
        },
    }
    if re.search(r"report|complain|police|1930|ವರದಿ|ದೂರು|रिपोर्ट|शिकायत", q):
        return texts["report"][lang]
    if re.search(r"clicked|already|shared|paid|lost|ಕ್ಲಿಕ್|ಈಗಾಗಲೇ|क्लिक|पहले ही", q):
        return texts["acted"][lang]
    if analysis and re.search(r"safe|legit|real|genuine|scam|ಸುರಕ್ಷಿತ|ವಂಚನೆ|सुरक्षित|धोखा", q):
        return texts["safe"][lang].format(score=analysis.get("score", 0), level=analysis.get("level", ""))
    if analysis and analysis.get("actions"):
        return " ".join(analysis["actions"][:2])
    return texts["default"][lang]


def assistant_answer_uses_only_verified_contacts(answer, evidence):
    allowed_urls = {
        source["url"].rstrip(".,);")
        for source in evidence
        if source.get("url")
    }
    answer_urls = re.findall(
        r"https?://[^\s<>\"']+|www\.[^\s<>\"']+",
        answer,
        re.IGNORECASE,
    )
    if any(url.rstrip(".,);") not in allowed_urls for url in answer_urls):
        return False

    allowed_numbers = {"1930", "112"}
    phone_numbers = re.findall(
        r"(?<!\d)(?:\+?91[-\s]?)?[6-9]\d{9}(?!\d)",
        answer,
    )
    return all(number.replace("+", "").replace(" ", "").replace("-", "") in allowed_numbers
               for number in phone_numbers)


@app.post("/api/assistant")
def assistant(
    body: AskIn,
    request: Request
):
    rate_check(
        request,
        "assistant",
        12
    )

    question = clean_text(
        body.question
    )[:500]

    analysis = None

    if body.analysis_id is not None:
        analysis, _ = load_case(
            body.analysis_id,
            request.state.user["id"],
        )

    elif body.context:
        allowed = {
            "level",
            "score",
            "classification",
            "signals",
            "impersonation",
            "claims",
            "actions",
        }

        analysis = {
            key: body.context[key]
            for key in allowed
            if key in body.context
        }

    # --------------------------------------------------------
    # EMERGENCY / HELPLINE
    # --------------------------------------------------------

    emergency_question = re.search(
        r"emergency|helpline|1930|112|"
        r"contact.*number|which.*number|"
        r"what.*number|"
        r"ಸಹಾಯವಾಣಿ|ತುರ್ತು|ಹೆಲ್ಪ್|"
        r"आपात|हेल्पलाइन|नंबर",
        question,
        re.IGNORECASE
    )

    if emergency_question:

        answers = {
            "en": (
                "For online financial cyber fraud, call 1930 promptly "
                "and report at https://cybercrime.gov.in/. "
                "For an immediate police, fire or medical emergency, "
                "call 112."
            ),

            "kn": (
                "ಆನ್‌ಲೈನ್ ಹಣಕಾಸು ಸೈಬರ್ ವಂಚನೆಗೆ ತಕ್ಷಣ 1930ಕ್ಕೆ ಕರೆ ಮಾಡಿ "
                "ಮತ್ತು https://cybercrime.gov.in/ ನಲ್ಲಿ ವರದಿ ಮಾಡಿ. "
                "ತಕ್ಷಣದ ಪೊಲೀಸ್, ಅಗ್ನಿಶಾಮಕ ಅಥವಾ ವೈದ್ಯಕೀಯ ತುರ್ತು ಪರಿಸ್ಥಿತಿಗೆ "
                "112ಕ್ಕೆ ಕರೆ ಮಾಡಿ."
            ),

            "hi": (
                "ऑनलाइन वित्तीय साइबर धोखाधड़ी के लिए तुरंत 1930 पर "
                "कॉल करें और https://cybercrime.gov.in/ पर रिपोर्ट करें। "
                "तत्काल पुलिस, अग्निशमन या चिकित्सा आपातस्थिति के लिए "
                "112 पर कॉल करें।"
            ),
        }

        return {
            "answer":
                answers[
                    body.output_language
                ],

            "by":
                "official-guidance",

            "sources": [
                {
                    "title":
                        "National Cyber Crime Reporting Portal",
                    "url":
                        "https://cybercrime.gov.in/",
                },
                {
                    "title":
                        "Emergency Response Support System",
                    "url":
                        "https://112.gov.in/",
                },
            ],

            "retrieved_at":
                datetime.now(
                    timezone.utc
                ).isoformat(
                    timespec="seconds"
                ),
        }

    # --------------------------------------------------------
    # RETRIEVE EVIDENCE
    # --------------------------------------------------------

    evidence = assistant_sources(
        question,
        k=4
    )

    if LLM_ON:

        analysis_context = json.dumps(
            analysis,
            ensure_ascii=False
        )[:6000] if analysis else (
            "No analysis context was supplied."
        )

        evidence_context = json.dumps(
            [
                {
                    key: source[key]
                    for key in (
                        "title",
                        "org",
                        "url",
                        "text",
                        "retrieved_on",
                    )
                }
                for source in evidence
            ],
            ensure_ascii=False
        )[:5000]

        answer = llm_text(
            f"""
You are ScamShield Verify's cyber-safety assistant.

Answer the user's actual question.

The user may ask:
- about the current scam analysis
- about OTPs
- phishing
- cybercrime reporting
- suspicious messages
- general cybersecurity questions

Use supplied evidence for factual claims.

Never invent:
- phone numbers
- URLs
- official procedures
- sources
- facts

If the supplied evidence is insufficient, clearly say that.

Respond in:
{LANGUAGES[body.output_language]}

Keep the response under 180 words.

Current analysis:
{analysis_context}

Trusted evidence:
{evidence_context}

User question:
{question}
"""
        )

        if answer and assistant_answer_uses_only_verified_contacts(answer, evidence):
            return {
                "answer":
                    answer,

                "by":
                    "llm",

                "sources": [
                    {
                        "title":
                            source["title"],
                        "org":
                            source["org"],
                        "url":
                            source["url"],
                        "retrieved_on":
                            source.get(
                                "retrieved_on",
                                ""
                            ),
                    }
                    for source in evidence
                ],

                "retrieved_at":
                    datetime.now(
                        timezone.utc
                    ).isoformat(
                        timespec="seconds"
                    ),
            }

    # --------------------------------------------------------
    # SAFE FALLBACK
    # --------------------------------------------------------

    answer = assistant_fallback(
        question,
        analysis,
        body.output_language
    )

    return {
        "answer":
            answer,

        "by":
            "verified-fallback",

        "sources": [
            {
                "title":
                    source["title"],
                "org":
                    source["org"],
                "url":
                    source["url"],
                "retrieved_on":
                    source.get(
                        "retrieved_on",
                        ""
                    ),
            }
            for source in evidence
        ],

        "retrieved_at":
            datetime.now(
                timezone.utc
            ).isoformat(
                timespec="seconds"
            ),
    }


# ============================================================
# EVALUATION
# ============================================================

@app.post("/api/evaluation/run")
def evaluation():
    rows = []

    for test in TESTS:

        result = full_analysis(
            test["text"],
            use_llm=False
        )

        actual = (
            test["label"].lower()
            == "scam"
        )

        predicted = (
            result["score"] >= 30
        )

        rows.append({
            "text":
                test["text"],
            "actual":
                actual,
            "pred":
                predicted,
            "language":
                test.get(
                    "language",
                    "en"
                ),
            "category":
                test.get(
                    "category",
                    "unknown"
                ),
            "score":
                result["score"],
        })

    tp = sum(
        row["actual"]
        and row["pred"]
        for row in rows
    )

    tn = sum(
        not row["actual"]
        and not row["pred"]
        for row in rows
    )

    fp = sum(
        not row["actual"]
        and row["pred"]
        for row in rows
    )

    fn = sum(
        row["actual"]
        and not row["pred"]
        for row in rows
    )

    total = len(rows)

    accuracy = (
        (tp + tn) / total
        if total
        else 0
    )

    precision = (
        tp / (tp + fp)
        if tp + fp
        else 0
    )

    recall = (
        tp / (tp + fn)
        if tp + fn
        else 0
    )

    false_positive_rate = (
        fp / (fp + tn)
        if fp + tn
        else 0
    )

    grouped_metrics = intel.metrics(rows)

    return {
        "overall":
            grouped_metrics["overall"],

        "by_language":
            grouped_metrics["by_language"],

        "by_category":
            grouped_metrics["by_category"],

        "total_cases":
            total,

        "true_positive":
            tp,

        "true_negative":
            tn,

        "false_positive":
            fp,

        "false_negative":
            fn,

        "accuracy":
            round(
                accuracy * 100,
                2
            ),

        "precision":
            round(
                precision * 100,
                2
            ),

        "recall":
            round(
                recall * 100,
                2
            ),

        "false_positive_rate":
            round(
                false_positive_rate * 100,
                2
            ),

        "cases": [
            {
                "text":
                    row["text"],
                "label":
                    "scam"
                    if row["actual"]
                    else "legit",
                "predicted":
                    "scam"
                    if row["pred"]
                    else "legit",
                "score":
                    row["score"],
                "language":
                    row["language"],
                "category":
                    row["category"],
            }
            for row in rows
        ],

        "note": (
            "Measured on the small built-in dataset "
            "using the deterministic rule layer. "
            "This is not a claim of real-world accuracy."
        ),
    }


# ============================================================
# FRONTEND
# ============================================================

@app.get("/")
def index():
    built_index = (
        FRONTEND_DIST / "index.html"
    )

    if built_index.is_file():
        return FileResponse(
            built_index
        )

    return RedirectResponse(
        "http://localhost:5173"
    )


if (
    FRONTEND_DIST / "assets"
).is_dir():

    app.mount(
        "/assets",
        StaticFiles(
            directory=
                FRONTEND_DIST / "assets"
        ),
        name="frontend-assets"
    )