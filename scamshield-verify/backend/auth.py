import base64, hashlib, hmac, json, os, re, secrets, sqlite3, time
from pathlib import Path
from dotenv import load_dotenv
from fastapi import APIRouter, Header, HTTPException
from pydantic import BaseModel, ConfigDict

load_dotenv()
router = APIRouter(prefix="/api/auth", tags=["auth"])
DB = Path(__file__).parent / "users.db"
SECRET = (os.getenv("JWT_SECRET") or secrets.token_hex(32)).encode()
TTL = 7 * 24 * 3600
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

class Creds(BaseModel):
    model_config = ConfigDict(extra="allow")
    email: str
    password: str
    name: str | None = None

def conn():
    c = sqlite3.connect(DB)
    c.execute("CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT UNIQUE, name TEXT, password_hash TEXT, created_at REAL)")
    return c

def hash_pw(pw, salt=None):
    salt = salt or secrets.token_hex(16)
    return salt + "$" + hashlib.pbkdf2_hmac("sha256", pw.encode(), salt.encode(), 200_000).hex()

def check_pw(pw, stored):
    salt = stored.split("$")[0]
    return hmac.compare_digest(hash_pw(pw, salt), stored)

b64 = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=").decode()
unb64 = lambda s: base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))

def make_token(uid):
    head = b64(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    body = b64(json.dumps({"sub": uid, "exp": int(time.time()) + TTL}).encode())
    sig = b64(hmac.new(SECRET, f"{head}.{body}".encode(), hashlib.sha256).digest())
    return f"{head}.{body}.{sig}"

def user_payload(row):
    return {"id": row[0], "email": row[1], "name": row[2] or row[1].split("@")[0]}

def respond(u):
    t = make_token(u["id"])
    return {"token": t, "access_token": t, "token_type": "bearer", "user": u, **u}

@router.post("/register")
def register(body: Creds):
    email = body.email.strip().lower()
    if not EMAIL_RE.match(email): raise HTTPException(400, "Enter a valid email address.")
    if len(body.password) < 8: raise HTTPException(400, "Password must be at least 8 characters.")
    try:
        with conn() as c:
            cur = c.execute("INSERT INTO users(email,name,password_hash,created_at) VALUES(?,?,?,?)",
                            (email, (body.name or "").strip()[:60], hash_pw(body.password), time.time()))
            row = c.execute("SELECT id,email,name FROM users WHERE id=?", (cur.lastrowid,)).fetchone()
    except sqlite3.IntegrityError:
        raise HTTPException(409, "Email already registered.")
    return respond(user_payload(row))

@router.post("/login")
def login(body: Creds):
    with conn() as c:
        row = c.execute("SELECT id,email,name,password_hash FROM users WHERE email=?", (body.email.strip().lower(),)).fetchone()
    if not row or not check_pw(body.password, row[3]): raise HTTPException(401, "Invalid email or password.")
    return respond(user_payload(row))

@router.get("/me")
def me(authorization: str | None = Header(None)):
    try:
        head, body, sig = (authorization or "").removeprefix("Bearer ").strip().split(".")
        good = b64(hmac.new(SECRET, f"{head}.{body}".encode(), hashlib.sha256).digest())
        data = json.loads(unb64(body))
        if not hmac.compare_digest(sig, good) or data["exp"] < time.time(): raise ValueError
        with conn() as c:
            row = c.execute("SELECT id,email,name FROM users WHERE id=?", (data["sub"],)).fetchone()
        if not row: raise ValueError
    except Exception:
        raise HTTPException(401, "Not signed in.")
    u = user_payload(row)
    return {**u, "user": u}

@router.post("/logout")
def logout(): return {"ok": True}