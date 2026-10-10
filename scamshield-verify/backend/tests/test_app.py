import sys, pathlib
import sqlite3
from io import BytesIO
import pytest
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from fastapi.testclient import TestClient
import main, intel
from PIL import Image

c = TestClient(main.app)
SCAM = "Dear customer, your SBI account will be blocked today. Verify KYC immediately at http://sbi-kyc-update.xyz and share your OTP."

@pytest.fixture(autouse=True)
def authenticated_test_client(tmp_path, monkeypatch):
    global c
    monkeypatch.setattr(main, "DB", tmp_path / "history.db")
    monkeypatch.setattr(main, "AUTH_COOKIE_SECURE", False)
    monkeypatch.setattr(main, "LLM_ON", False)
    main.RATE_BUCKETS.clear()
    main.init_db()
    c = TestClient(main.app)
    response = c.post("/api/auth/register", json={
        "name": "Test User",
        "email": "test-user@example.com",
        "password": "test-password-123",
        "confirm_password": "test-password-123",
    })
    assert response.status_code == 201
    yield
    c.close()


def test_auth_register_login_logout_and_password_hashing():
    anonymous = TestClient(main.app)
    assert anonymous.get("/api/auth/me").json() == {"authenticated": False, "user": None}
    assert anonymous.get("/api/history").status_code == 401
    anonymous.close()

    payload = {
        "name": "New Account",
        "email": "new-account@example.com",
        "password": "long-enough-password",
        "confirm_password": "long-enough-password",
    }
    registered = c.post("/api/auth/register", json=payload)
    assert registered.status_code == 201
    assert registered.json()["token"]
    assert "password" not in registered.text and "password_hash" not in registered.text
    assert c.post("/api/auth/register", json=payload).status_code == 409

    stored = main.db_execute(
        "SELECT password_hash FROM users WHERE email = ?",
        ("new-account@example.com",),
    )[0][0]
    assert stored.startswith("pbkdf2_sha256$") and stored != payload["password"]
    assert main.verify_password(payload["password"], stored)

    token_only_client = TestClient(main.app)
    headers = {"Authorization": f"Bearer {registered.json()['token']}"}
    assert token_only_client.get("/api/auth/me", headers=headers).json()["user"]["email"] == payload["email"]
    assert token_only_client.get("/api/history", headers=headers).status_code == 200

    c.post("/api/auth/logout")
    assert c.get("/api/auth/me").json()["authenticated"] is False
    assert c.post("/api/auth/login", json={"email": payload["email"], "password": "wrong-password"}).status_code == 401
    assert c.post("/api/auth/login", json={"email": payload["email"], "password": payload["password"]}).status_code == 200
    assert c.get("/api/auth/me").json()["user"]["email"] == payload["email"]
    assert c.post("/api/auth/logout").json() == {"logged_out": True}
    assert c.get("/api/auth/me").json()["authenticated"] is False
    assert c.get("/api/history").status_code == 401
    assert token_only_client.post("/api/auth/logout", headers=headers).json() == {"logged_out": True}
    assert token_only_client.get("/api/auth/me", headers=headers).json()["authenticated"] is False
    assert token_only_client.get("/api/history", headers=headers).status_code == 401
    token_only_client.close()


def test_auth_rejects_invalid_and_mismatched_registration():
    assert c.post("/api/auth/register", json={
        "name": "Invalid", "email": "not-an-email", "password": "password-123",
        "confirm_password": "password-123",
    }).status_code == 422
    assert c.post("/api/auth/register", json={
        "name": "Mismatch", "email": "mismatch@example.com", "password": "password-123",
        "confirm_password": "different-password",
    }).status_code == 422
    assert c.post("/api/auth/register", json={
        "name": "", "email": "empty@example.com", "password": "password-123",
        "confirm_password": "password-123",
    }).status_code == 422


def test_cors_allows_both_local_frontend_hosts():
    for origin in ("http://localhost:5173", "http://127.0.0.1:5173"):
        response = c.options(
            "/api/auth/login",
            headers={
                "Origin": origin,
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "authorization,content-type",
            },
        )
        assert response.status_code == 200
        assert response.headers["access-control-allow-origin"] == origin
        assert "authorization" in response.headers["access-control-allow-headers"].lower()


def test_history_is_private_per_user(monkeypatch):
    monkeypatch.setattr(main, "LLM_ON", False)
    analysis = c.post("/api/analyze/text", json={"text": SCAM}).json()
    assert [row["id"] for row in c.get("/api/history").json()] == [analysis["id"]]

    c.post("/api/auth/logout")
    registered = c.post("/api/auth/register", json={
        "name": "Second User", "email": "second@example.com", "password": "password-12345",
        "confirm_password": "password-12345",
    })
    assert registered.status_code == 201
    assert c.get("/api/history").json() == []
    assert c.get(f"/api/history/{analysis['id']}").status_code == 404
    assert c.get("/api/stats").json()["total"] == 0


def test_existing_case_table_migrates_without_data_loss(tmp_path, monkeypatch):
    legacy_db = tmp_path / "legacy.db"
    with sqlite3.connect(legacy_db) as connection:
        connection.execute("""
            CREATE TABLE cases (
                id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, input_type TEXT,
                language TEXT, score INTEGER, level TEXT, patterns TEXT, snippet TEXT, result TEXT
            )
        """)
        connection.execute(
            "INSERT INTO cases (ts, input_type, language, score, level, patterns, snippet, result) VALUES (1, 'text', 'en', 1, 'LOW', '[]', 'old case', '{}')"
        )
    monkeypatch.setattr(main, "DB", legacy_db)
    main.init_db()
    with sqlite3.connect(legacy_db) as connection:
        columns = {row[1] for row in connection.execute("PRAGMA table_info(cases)")}
        old_row = connection.execute("SELECT snippet, user_id FROM cases").fetchone()
    assert "user_id" in columns and old_row == ("old case", None)


def test_scam_scores_high_with_rules():
    r = main.full_analysis(SCAM, use_llm=False)
    types = {s["type"] for s in r["signals"]}
    assert r["score"] >= 60 and {"OTP_REQUEST", "SUSPICIOUS_URL", "IMPERSONATION"} <= types

def test_legit_otp_notice_is_low():
    assert main.full_analysis("Your OTP is 482913. Do not share it with anyone. - SBI", use_llm=False)["level"] == "LOW"

def test_claim_without_evidence_is_unsupported():
    v = main.verify_claim("The moon is made of cheese", use_llm=False)
    assert v["status"] == "UNSUPPORTED" and v["evidence"] == []

def test_claim_contradicted_by_official_guidance():
    assert main.verify_claim("Bank requires you to share OTP to verify", use_llm=False)["status"] == "CONTRADICTED"

def test_empty_text_rejected():
    assert c.post("/api/analyze/text", json={"text": "  "}).status_code == 400

def test_case_lifecycle():
    r = c.post("/api/analyze/text", json={"text": SCAM}).json()
    assert c.get(f"/api/history/{r['id']}").status_code == 200
    assert "No report has been filed" in c.get(f"/api/history/{r['id']}/summary").text
    assert c.delete(f"/api/history/{r['id']}").status_code == 200
    assert c.get(f"/api/history/{r['id']}").status_code == 404

def test_metrics_math():
    rows = [{"actual": True, "pred": True, "language": "en", "category": "a"}, {"actual": True, "pred": False, "language": "en", "category": "a"},
            {"actual": False, "pred": True, "language": "kn", "category": "b"}, {"actual": False, "pred": False, "language": "kn", "category": "b"}]
    o = intel.metrics(rows)["overall"]
    assert (o["tp"], o["fp"], o["tn"], o["fn"]) == (1, 1, 1, 1) and o["precision"] == 0.5 and o["f1"] == 0.5

def test_evaluation_endpoint_counts_match():
    o = c.post("/api/evaluation/run").json()["overall"]
    assert o["total"] == len(main.TESTS) == o["tp"] + o["fp"] + o["tn"] + o["fn"]

def test_language_preferences_are_validated():
    assert c.get("/api/languages").status_code == 200
    r = c.post("/api/language/preferences", json={"input_language": "kn", "output_language": "hi", "speech_language": "en"})
    assert r.json() == {"input_language": "kn", "output_language": "hi", "speech_language": "en"}
    assert c.post("/api/language/preferences", json={"output_language": "xx"}).status_code == 422

def test_localization_never_changes_score_or_evidence(monkeypatch):
    monkeypatch.setattr(main, "llm_json", lambda prompt: None)
    original = main.full_analysis(SCAM, use_llm=False)
    localized = main.localized_analysis(main.full_analysis(SCAM, use_llm=False), "kn")
    assert localized["score"] == original["score"]
    assert [x["evidence"] for x in localized["signals"]] == [x["evidence"] for x in original["signals"]]
    assert [x["url"] for x in localized["urls"]] == [x["url"] for x in original["urls"]]
    assert localized["translation_status"] == "translated"
    assert localized["classification"] != original["classification"]
    assert localized["actions"] != original["actions"]
    assert localized["disclaimer"] != original["disclaimer"]

def test_emergency_assistant_works_without_analysis_or_llm(monkeypatch):
    monkeypatch.setattr(main, "LLM_ON", False)
    r = c.post("/api/assistant", json={"question": "Is there any emergency number to contact?", "output_language": "en"})
    assert r.status_code == 200
    assert "1930" in r.json()["answer"] and "112" in r.json()["answer"]
    assert {source["url"] for source in r.json()["sources"]} == {"https://cybercrime.gov.in/", "https://112.gov.in/"}

def test_general_chat_fallback_is_not_analysis_gated(monkeypatch):
    monkeypatch.setattr(main, "LLM_ON", False)
    r = c.post("/api/assistant", json={"question": "How can I report online payment fraud?", "output_language": "hi"})
    assert r.status_code == 200
    assert "1930" in r.json()["answer"] and "API key" not in r.json()["answer"]

def test_speech_endpoint_falls_back_without_translating_evidence(monkeypatch):
    monkeypatch.setattr(main, "LLM_ON", False)
    text = "High risk. Evidence: OTP 482913."
    for language, locale in (("kn", "kn-IN"), ("hi", "hi-IN")):
        result = c.post("/api/speech/text", json={"text": text, "speech_language": language}).json()
        assert result["text"] == text
        assert result["language"] == language and result["locale"] == locale
        assert result["translated"] is False
    english = c.post("/api/speech/text", json={"text": text, "speech_language": "en"}).json()
    assert english["text"] == text and english["locale"] == "en-IN"

def test_assistance_search_returns_no_invented_places_on_empty_lookup(monkeypatch):
    class Response:
        def raise_for_status(self): pass
        def json(self): return [{"lat": "12.9", "lon": "77.6", "display_name": "Bengaluru"}] if hasattr(self, "is_geo") else {"elements": []}

    def fake_get(*args, **kwargs):
        response = Response()
        response.is_geo = True
        return response

    monkeypatch.setattr(main.httpx, "get", fake_get)
    monkeypatch.setattr(main.httpx, "post", lambda *args, **kwargs: Response())
    r = c.post("/api/assistance/search", json={"location_query": "Bengaluru"})
    assert r.status_code == 200 and r.json()["results"] == []
    assert r.json()["note"].startswith("No mapped cyber crime branch found nearby.")
    assert {item["number"] for item in r.json()["official_contacts"]} == {"1930", "112"}
    assert c.post("/api/assistance/search", json={}).status_code == 422

def test_mixed_kannada_english_message_is_detected():
    result = main.full_analysis("SBI account ತಕ್ಷಣ blocked ಆಗುತ್ತದೆ. Share your OTP now.", use_llm=False)
    assert result["language"]["language"] == "Mixed: Kannada + English"
    assert result["score"] > 0

def test_ocr_uses_selected_language_and_returns_editable_text(monkeypatch):
    import pytesseract
    image = BytesIO()
    Image.new("RGB", (12, 12), "white").save(image, format="PNG")
    seen = []
    monkeypatch.setattr(pytesseract, "image_to_string", lambda img, lang: (seen.append(lang) or "ನಿಮ್ಮ SBI account"))
    response = c.post("/api/ocr", data={"ocr_language": "kn"}, files={"file": ("message.png", image.getvalue(), "image/png")})
    assert response.status_code == 200
    assert response.json() == {"text": "ನಿಮ್ಮ SBI account", "ocr_language": "kn", "ocr_fallback": False}
    assert seen == ["eng+kan"]

def test_ocr_discloses_english_only_fallback_when_language_data_is_missing(monkeypatch):
    import pytesseract
    image = BytesIO()
    Image.new("RGB", (12, 12), "white").save(image, format="PNG")
    def fake_ocr(img, lang):
        if lang == "eng+hin": raise pytesseract.TesseractError(1, "Hindi data missing")
        return "English-only result"
    monkeypatch.setattr(pytesseract, "image_to_string", fake_ocr)
    response = c.post("/api/ocr", data={"ocr_language": "hi"}, files={"file": ("message.png", image.getvalue(), "image/png")})
    assert response.status_code == 200
    assert response.json() == {"text": "English-only result", "ocr_language": "hi", "ocr_fallback": True}

def test_complete_localization_preserves_claim_and_source_evidence(monkeypatch):
    original = main.full_analysis(SCAM, use_llm=False)
    monkeypatch.setattr(main, "llm_json", lambda prompt: None)
    localized = main.localized_analysis(main.full_analysis(SCAM, use_llm=False), "kn")
    assert localized["translation_status"] == "translated"
    assert localized["score"] == original["score"]
    assert localized["classification"] != original["classification"]
    assert localized["actions"] != original["actions"]
    assert localized["disclaimer"] != original["disclaimer"]
    assert [item["claim"] for item in localized["claims"]] == [item["claim"] for item in original["claims"]]
    assert [item["evidence"] for item in localized["signals"]] == [item["evidence"] for item in original["signals"]]
    assert [[item["url"] for item in claim["evidence"]] for claim in localized["claims"]] == [[item["url"] for item in claim["evidence"]] for claim in original["claims"]]

def test_malformed_translation_is_discarded_atomically(monkeypatch):
    monkeypatch.setattr(main, "llm_json", lambda prompt: {"classification": "translated", "signal_labels": ["only one"]})
    original = main.full_analysis(SCAM, use_llm=False)
    result = main.localized_analysis(main.full_analysis(SCAM, use_llm=False), "hi")
    assert result["translation_status"] == "translated"
    assert result["score"] == original["score"]
    assert result["classification"] != original["classification"]

@pytest.mark.parametrize(("language", "localized_classification"), [
    ("kn", "ಬಹುಶಃ ವಂಚನೆ"),
    ("hi", "संभावित धोखाधड़ी"),
])
def test_analysis_api_returns_localized_content_without_llm(monkeypatch, language, localized_classification):
    monkeypatch.setattr(main, "LLM_ON", False)
    response = c.post("/api/analyze/text", json={"text": SCAM, "output_language": language})
    assert response.status_code == 200
    result = response.json()
    assert result["output_language"] == language
    assert result["translation_status"] == "translated"
    assert result["classification"] == localized_classification
    assert result["score"] >= 60
    original = main.full_analysis(SCAM, use_llm=False)
    assert result["entities"]["urls"] == [item["url"] for item in original["urls"]]
    assert all(item["tactic"] != "Data harvesting" for item in result["timeline"])
    assert result["disclaimer"] != main.DISCLAIMER

def test_cybercrime_search_matches_name_fields_and_deduplicates(monkeypatch):
    class GeoResponse:
        def raise_for_status(self): pass
        def json(self): return [{"lat": "12.9", "lon": "77.6", "display_name": "Bengaluru"}]
    class OSMResponse:
        def raise_for_status(self): pass
        def json(self): return {"elements": [
            {"type": "node", "id": 1, "lat": 12.91, "lon": 77.61,
             "tags": {"amenity": "police", "name:en": "Cyber Crime Police Station"}},
            {"type": "way", "id": 2, "center": {"lat": 12.9101, "lon": 77.6101},
             "tags": {"amenity": "police", "official_name": "Cyber Crime Police Station"}},
        ]}
    query = {}
    monkeypatch.setattr(main.httpx, "get", lambda *args, **kwargs: GeoResponse())
    def fake_post(*args, **kwargs):
        query.update(kwargs.get("data", {}))
        return OSMResponse()
    monkeypatch.setattr(main.httpx, "post", fake_post)
    response = c.post("/api/assistance/search", json={"location_query": "Bengaluru"})
    assert response.status_code == 200
    result = response.json()
    assert len(result["results"]) == 1
    assert result["results"][0]["category"] == "cybercrime"
    assert result["results"][0]["name"] == "Cyber Crime Police Station"
    assert "name:en" in query["data"] and "official_name" in query["data"]
    assert result["cybercrime_found"] is True

def test_phishing_question_gets_related_verified_fallback(monkeypatch):
    monkeypatch.setattr(main, "LLM_ON", False)
    result = c.post("/api/assistant", json={"question": "What is phishing?", "output_language": "en"}).json()
    assert "unexpected messages" in result["answer"]
    assert any(source["url"] == "https://www.cert-in.org.in/" for source in result["sources"])

def test_app_serves_built_frontend_assets():
    response = c.get("/", follow_redirects=False)
    if main.FRONTEND_DIST.joinpath("index.html").is_file():
        assert response.status_code == 200 and 'id="root"' in response.text
        asset = __import__("re").search(r'src="(/assets/[^\"]+\.js)"', response.text)
        assert asset and c.get(asset.group(1)).status_code == 200
    else:
        assert response.status_code == 307 and response.headers["location"] == "http://localhost:5173"

def test_assistance_listing_marks_phone_unverified(monkeypatch):
    class GeoResponse:
        def raise_for_status(self): pass
        def json(self): return [{"lat": "12.9", "lon": "77.6", "display_name": "Bengaluru"}]
    class OSMResponse:
        def raise_for_status(self): pass
        def json(self): return {"elements": [{"type": "node", "id": 123, "lat": 12.91, "lon": 77.61,
                                                "tags": {"amenity": "police", "name": "Listed station"}}]}
    monkeypatch.setattr(main.httpx, "get", lambda *args, **kwargs: GeoResponse())
    monkeypatch.setattr(main.httpx, "post", lambda *args, **kwargs: OSMResponse())
    result = c.post("/api/assistance/search", json={"location_query": "Bengaluru"}).json()
    place = result["results"][0]
    assert place["name"] == "Listed station" and place["phone"] is None
    assert place["phone_verified"] is False and "not independently verified" in place["source_name"]
    assert place["distance_km"] >= 0 and place["source_url"].endswith("/node/123")

def test_chat_rejects_unretrieved_url_and_phone_number(monkeypatch):
    monkeypatch.setattr(main, "LLM_ON", True)
    monkeypatch.setattr(main, "llm_text", lambda prompt: "Call the hotline at 9876543210 or visit https://fake-help.example")
    result = c.post("/api/assistant", json={"question": "How do I avoid phishing links?", "output_language": "en"}).json()
    assert result["by"] == "verified-fallback"
    assert "9876543210" not in result["answer"] and "fake-help.example" not in result["answer"]
    assert any(source["url"] == "https://www.cert-in.org.in/" for source in result["sources"])

def test_assistance_emergency_filter_returns_tagged_real_facility_types(monkeypatch):
    class GeoResponse:
        def raise_for_status(self): pass
        def json(self): return [{"lat": "12.9", "lon": "77.6", "display_name": "Bengaluru"}]
    class OSMResponse:
        def raise_for_status(self): pass
        def json(self): return {"elements": [
            {"type": "node", "id": 1, "lat": 12.91, "lon": 77.61, "tags": {"amenity": "fire_station", "name": "Listed fire station"}},
            {"type": "node", "id": 2, "lat": 12.92, "lon": 77.62, "tags": {"amenity": "hospital", "name": "Listed hospital"}},
            {"type": "node", "id": 3, "lat": 12.93, "lon": 77.63, "tags": {"emergency": "ambulance_station", "name": "Listed ambulance station"}},
            {"type": "node", "id": 4, "lat": 12.94, "lon": 77.64, "tags": {"amenity": "police", "name": "Not an emergency service"}},
        ]}
    monkeypatch.setattr(main.httpx, "get", lambda *args, **kwargs: GeoResponse())
    monkeypatch.setattr(main.httpx, "post", lambda *args, **kwargs: OSMResponse())
    result = c.post("/api/assistance/search", json={"location_query": "Bengaluru", "categories": ["emergency"]}).json()
    assert len(result["results"]) == 3
    assert {item["category"] for item in result["results"]} == {"emergency"}
    assert {item["number"] for item in result["official_contacts"]} == {"1930", "112"}

def test_official_contacts_are_timestamped_without_location():
    result = c.get("/api/assistance/contacts").json()
    assert {item["number"] for item in result["official_contacts"]} == {"1930", "112"}
    assert all(item["retrieved_at"] == result["retrieved_at"] for item in result["official_contacts"])
    assert {item["source_url"] for item in result["official_contacts"]} == {"https://cybercrime.gov.in/", "https://112.gov.in/"}
