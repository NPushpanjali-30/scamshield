import re
from collections import Counter

PHONE_RE = re.compile(r"(?<!\d)(?:\+?91[-\s]?)?[6-9]\d{9}(?!\d)")
EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
UPI_RE = re.compile(r"\b[\w.-]{2,}@(?:ok\w+|ybl|ibl|axl|paytm|upi|sbi|hdfcbank|icici|apl)\b", re.I)
JOB = re.compile(r"registration fee|joining fee|processing fee|security deposit|work from home|job offer|part[- ]time job", re.I)
ASK = [("OTP", r"\botp\b|ಒಟಿಪಿ"), ("PIN/CVV", r"\b(?:pin|cvv)\b"), ("Password", r"password|ಪಾಸ್ವರ್ಡ್"),
       ("Aadhaar", r"aadhaar|aadhar|ಆಧಾರ್"), ("Card/bank details", r"card number|bank details"), ("Payment", r"\b(?:pay|fee|transfer)\b")]
TACTIC = {"URGENCY_THREAT": "Pressure", "REWARD_BAIT": "Lure", "OTP_REQUEST": "Data harvesting", "CREDENTIAL_REQUEST": "Data harvesting",
          "KYC_REFUND_LURE": "Pretext", "FEE_REQUEST": "Payment demand", "SUSPICIOUS_URL": "Redirect to a link", "IMPERSONATION": "Borrowed authority"}
PATTERNS = {
    "Bank OTP scam": {"OTP_REQUEST", "URGENCY_THREAT", "IMPERSONATION"},
    "Fake KYC": {"KYC_REFUND_LURE", "URGENCY_THREAT", "SUSPICIOUS_URL"},
    "Government reward": {"REWARD_BAIT", "CREDENTIAL_REQUEST", "SUSPICIOUS_URL"},
    "Delivery or refund fraud": {"KYC_REFUND_LURE", "SUSPICIOUS_URL", "IMPERSONATION"},
    "Job-fee scam": {"FEE_REQUEST", "JOB_FEE", "URGENCY_THREAT"},
    "Organization impersonation": {"IMPERSONATION", "SUSPICIOUS_URL", "CREDENTIAL_REQUEST"},
}

def enrich(text, res):
    sigs = res["signals"]; types = {s["type"] for s in sigs}; tags = set(types)
    if JOB.search(text): tags.add("JOB_FEE")
    upis = UPI_RE.findall(text)
    emails = [e for e in EMAIL_RE.findall(text) if e not in upis]
    asks = [n for n, p in ASK if re.search(p, text, re.I)] if (types & {"OTP_REQUEST", "CREDENTIAL_REQUEST", "FEE_REQUEST"}) else []
    spans, order = [], []
    for s in sigs:
        i = text.find(s["evidence"]) if s["type"] != "IMPERSONATION" else -1
        if i >= 0: spans.append({"start": i, "end": i + len(s["evidence"]), "type": s["type"]})
        order.append((i if i >= 0 else 10**6, s))
    timeline = [{"step": n + 1, "tactic": TACTIC.get(s["type"], s["type"]), "label": s["label"], "quote": s["evidence"]}
                for n, (_, s) in enumerate(sorted(order, key=lambda x: x[0]))]
    pats = []
    for name, req in PATTERNS.items():
        hit = req & tags
        if len(hit) / len(req) >= 0.34:
            pats.append({"name": name, "similarity": round(len(hit) / len(req), 2), "matched": sorted(hit), "missing": sorted(req - tags)})
    pats.sort(key=lambda p: -p["similarity"])
    nodes = [{"id": "msg", "label": "This message", "kind": "message"}]; edges = []
    for i, o in enumerate(res["impersonation"]):
        nodes.append({"id": f"o{i}", "label": o["claimed_org"], "kind": "org"}); edges.append({"from": "msg", "to": f"o{i}", "label": "claims to be"})
    for i, u in enumerate(res["urls"]):
        nodes.append({"id": f"u{i}", "label": u["host"], "kind": "url"}); edges.append({"from": "msg", "to": f"u{i}", "label": "contains link"})
        for j, o in enumerate(res["impersonation"]):
            if u["host"] in o["hosts"]: edges.append({"from": f"o{j}", "to": f"u{i}", "label": "domain mismatch"})
    phones = list(dict.fromkeys(PHONE_RE.findall(text)))
    for i, p in enumerate(phones): nodes.append({"id": f"p{i}", "label": p, "kind": "contact"}); edges.append({"from": "msg", "to": f"p{i}", "label": "gives number"})
    for i, p in enumerate(upis): nodes.append({"id": f"v{i}", "label": p, "kind": "contact"}); edges.append({"from": "msg", "to": f"v{i}", "label": "asks payment to"})
    for i, c in enumerate(res["claims"][:3]):
        nodes.append({"id": f"c{i}", "label": c["claim"][:40] + " [" + c["status"] + "]", "kind": "claim"}); edges.append({"from": "msg", "to": f"c{i}", "label": "asserts"})
    return {"entities": {"phones": phones, "emails": emails, "upi_ids": upis, "orgs": [o["claimed_org"] for o in res["impersonation"]],
                         "requested_info": asks, "urls": [u["url"] for u in res["urls"]]},
            "highlights": spans, "timeline": timeline, "patterns": pats, "graph": {"nodes": nodes, "edges": edges},
            "pattern_note": "A pattern match shows similarity to a known scam style. It is not proof of fraud."}

def _m(rs):
    tp = sum(r["actual"] and r["pred"] for r in rs); fp = sum((not r["actual"]) and r["pred"] for r in rs)
    tn = sum((not r["actual"]) and (not r["pred"]) for r in rs); fn = sum(r["actual"] and (not r["pred"]) for r in rs)
    d = lambda a, b: round(a / b, 3) if b else None
    p, rc = d(tp, tp + fp), d(tp, tp + fn)
    return {"total": len(rs), "tp": tp, "fp": fp, "tn": tn, "fn": fn, "accuracy": d(tp + tn, len(rs)), "precision": p, "recall": rc,
            "f1": round(2 * p * rc / (p + rc), 3) if p and rc else None, "false_positive_rate": d(fp, fp + tn)}

def metrics(rows):
    group = lambda k: {g: _m([r for r in rows if r[k] == g]) for g in sorted({r[k] for r in rows})}
    return {"overall": _m(rows), "by_language": group("language"), "by_category": group("category")}

def summary(r, created):
    L = ["ScamShield Verify - incident summary", f"Created: {created}", f"Risk: {r['level']} ({r['score']}/100) - {r['classification']}",
         f"Language: {r['language']['language']}", "", "Rules triggered:"]
    L += [f"- {s['label']} (+{s['weight']}): \"{s['evidence']}\"" for s in r["signals"]] or ["- none"]
    L += ["", "Claims checked:"] + [f"- [{c['status']}] {c['claim']}" for c in r["claims"]] + ["", "Recommended actions:"] + [f"- {a}" for a in r["actions"]]
    L += ["", "This is an automated assessment. No report has been filed and no account has been secured by this tool.",
          "To report fraud: cybercrime.gov.in or call 1930.", r["disclaimer"]]
    return "\n".join(L)

def assistant_fallback(q, r=None, language="en"):
    ql = q.lower()
    if any(w in ql for w in ("otp", "one-time password", "pin", "cvv", "ಒಟಿಪಿ", "ಪಿನ್", "पासवर्ड", "ओटीपी", "पिन")):
        return {
            "en": "Never share an OTP, PIN, CVV or password with someone who contacts you. The RBI says banks do not ask for these details by call, SMS, email or link. Verify requests through your bank's official app or website.",
            "kn": "ನಿಮ್ಮನ್ನು ಸಂಪರ್ಕಿಸುವವರೊಂದಿಗೆ OTP, PIN, CVV ಅಥವಾ ಪಾಸ್‌ವರ್ಡ್ ಹಂಚಿಕೊಳ್ಳಬೇಡಿ. ಕರೆ, SMS, ಇಮೇಲ್ ಅಥವಾ ಲಿಂಕ್ ಮೂಲಕ ಬ್ಯಾಂಕ್ ಇವುಗಳನ್ನು ಕೇಳುವುದಿಲ್ಲ ಎಂದು RBI ಸೂಚಿಸುತ್ತದೆ. ಬ್ಯಾಂಕ್‌ನ ಅಧಿಕೃತ ಆ್ಯಪ್ ಅಥವಾ ವೆಬ್‌ಸೈಟ್‌ನಲ್ಲಿ ಪರಿಶೀಲಿಸಿ.",
            "hi": "किसी संपर्क करने वाले व्यक्ति के साथ OTP, PIN, CVV या पासवर्ड साझा न करें। RBI के अनुसार बैंक कॉल, SMS, ईमेल या लिंक से ये विवरण नहीं मांगते। बैंक की आधिकारिक ऐप या वेबसाइट पर सत्यापित करें।",
        }.get(language, "Never share your OTP, PIN, CVV or password. Verify requests through your bank's official app or website.")
    if any(w in ql for w in ("phishing", "suspicious link", "fake link", "फिशिंग", "फ़िशिंग", "ಫಿಶಿಂಗ್", "ಅನುಮಾನಾಸ್ಪದ ಲಿಂಕ್")):
        return {
            "en": "Phishing messages try to lure you into opening a link or sharing information. Do not use links in unexpected messages; check the address and visit the organization's official site or app yourself.",
            "kn": "ಫಿಶಿಂಗ್ ಸಂದೇಶಗಳು ಲಿಂಕ್ ತೆರೆಯಲು ಅಥವಾ ಮಾಹಿತಿ ಹಂಚಿಕೊಳ್ಳಲು ನಿಮ್ಮನ್ನು ಪ್ರೇರೇಪಿಸುತ್ತವೆ. ಅನಿರೀಕ್ಷಿತ ಸಂದೇಶದ ಲಿಂಕ್ ಬಳಸಬೇಡಿ; ವಿಳಾಸ ಪರಿಶೀಲಿಸಿ, ಸಂಸ್ಥೆಯ ಅಧಿಕೃತ ತಾಣ ಅಥವಾ ಆ್ಯಪ್ ಅನ್ನು ನೀವೇ ತೆರೆಯಿರಿ.",
            "hi": "फ़िशिंग संदेश आपको लिंक खोलने या जानकारी साझा करने के लिए लुभाते हैं। अनपेक्षित संदेशों के लिंक का उपयोग न करें; पता जांचें और संस्था की आधिकारिक साइट या ऐप स्वयं खोलें।",
        }.get(language, "Do not open links in unexpected messages. Check the address and use the organization's official site or app.")
    if any(w in ql for w in ("protect my account", "secure my account", "account security", "ಖಾತೆ ಸುರಕ್ಷತೆ", "ಖಾತೆಯನ್ನು ಸುರಕ್ಷಿತ", "खाता सुरक्षित", "खाते की सुरक्षा")):
        return {
            "en": "Use a unique password, turn on multi-factor authentication where available, keep recovery details current, and never share OTPs. Contact the service through its official app or website if you suspect access was misused.",
            "kn": "ಪ್ರತಿ ಖಾತೆಗೆ ವಿಭಿನ್ನ ಪಾಸ್‌ವರ್ಡ್ ಬಳಸಿ, ಲಭ್ಯವಿದ್ದರೆ ಬಹು-ಹಂತದ ದೃಢೀಕರಣ ಸಕ್ರಿಯಗೊಳಿಸಿ, ಮರುಪಡೆಯುವ ವಿವರಗಳನ್ನು ನವೀಕರಿಸಿ ಮತ್ತು OTP ಹಂಚಿಕೊಳ್ಳಬೇಡಿ. ದುರುಪಯೋಗ ಅನುಮಾನಿಸಿದರೆ ಅಧಿಕೃತ ಆ್ಯಪ್ ಅಥವಾ ವೆಬ್‌ಸೈಟ್ ಮೂಲಕ ಸಂಪರ್ಕಿಸಿ.",
            "hi": "हर खाते के लिए अलग पासवर्ड रखें, उपलब्ध होने पर बहु-कारक प्रमाणीकरण चालू करें, पुनर्प्राप्ति जानकारी अपडेट रखें और OTP साझा न करें। दुरुपयोग का संदेह हो तो सेवा की आधिकारिक ऐप या वेबसाइट से संपर्क करें।",
        }.get(language, "Use a unique password, enable multi-factor authentication where available, and contact the service through its official site if concerned.")
    if any(w in ql for w in ("report", "complain", "police", "ವರದಿ", "ದೂರು", "ಪೊಲೀಸ್", "रिपोर्ट", "शिकायत", "पुलिस")):
        return {
            "en": "For online financial cyber fraud, report at https://cybercrime.gov.in/ or call 1930 promptly. This tool has not filed a report.",
            "kn": "ಆನ್‌ಲೈನ್ ಹಣಕಾಸು ಸೈಬರ್ ವಂಚನೆಗೆ https://cybercrime.gov.in/ ನಲ್ಲಿ ವರದಿ ಮಾಡಿ ಅಥವಾ ತಕ್ಷಣ 1930ಕ್ಕೆ ಕರೆ ಮಾಡಿ. ಈ ಸಾಧನ ಯಾವುದೇ ವರದಿ ಸಲ್ಲಿಸಿಲ್ಲ.",
            "hi": "ऑनलाइन वित्तीय साइबर धोखाधड़ी की रिपोर्ट https://cybercrime.gov.in/ पर करें या तुरंत 1930 पर कॉल करें। इस टूल ने कोई रिपोर्ट दर्ज नहीं की है.",
        }.get(language, "For online financial cyber fraud, report at https://cybercrime.gov.in/ or call 1930 promptly. This tool has not filed a report.")
    if any(w in ql for w in ("clicked", "already", "shared", "lost money", "paid", "ಕ್ಲಿಕ್", "ಹಂಚಿಕೊಂಡ", "ಹಣ ಕಳೆದು", "क्लिक", "साझा", "पैसे गंवा")):
        return {
            "en": "Contact your bank using its official app or the number on your card, secure affected accounts, and report financial cyber fraud at https://cybercrime.gov.in/ or 1930. Do not share an OTP with anyone.",
            "kn": "ನಿಮ್ಮ ಬ್ಯಾಂಕ್‌ನ ಅಧಿಕೃತ ಆ್ಯಪ್ ಅಥವಾ ಕಾರ್ಡ್‌ನಲ್ಲಿರುವ ಸಂಖ್ಯೆಯ ಮೂಲಕ ಬ್ಯಾಂಕ್ ಅನ್ನು ಸಂಪರ್ಕಿಸಿ, ಸಂಬಂಧಿತ ಖಾತೆಗಳನ್ನು ಸುರಕ್ಷಿತಗೊಳಿಸಿ ಮತ್ತು ಹಣಕಾಸು ಸೈಬರ್ ವಂಚನೆಯನ್ನು https://cybercrime.gov.in/ ಅಥವಾ 1930 ಮೂಲಕ ವರದಿ ಮಾಡಿ. OTP ಹಂಚಿಕೊಳ್ಳಬೇಡಿ.",
            "hi": "बैंक के आधिकारिक ऐप या कार्ड पर दिए नंबर से बैंक से संपर्क करें, प्रभावित खातों को सुरक्षित करें और वित्तीय साइबर धोखाधड़ी की रिपोर्ट https://cybercrime.gov.in/ या 1930 पर करें। OTP किसी से साझा न करें।",
        }.get(language, "Contact your bank through its official app and report financial cyber fraud at https://cybercrime.gov.in/ or 1930.")
    if r and any(w in ql for w in ("safe", "legit", "real", "genuine", "scam", "ಸುರಕ್ಷಿತ", "ನಿಜ", "ಮೋಸ", "सुरक्षित", "असली", "धोखा")):
        return {
            "en": f"The rule-based score is {r['score']}/100 ({r['level']}); it is a risk estimate, not proof. Verify unexpected requests using the organization's official app or website.",
            "kn": f"ನಿಯಮ ಆಧಾರಿತ ಅಪಾಯ ಅಂಕ {r['score']}/100 ({r['level']}); ಇದು ಅಂದಾಜು ಮಾತ್ರ, ದೃಢೀಕರಣವಲ್ಲ. ಸಂಸ್ಥೆಯ ಅಧಿಕೃತ ಆ್ಯಪ್ ಅಥವಾ ವೆಬ್‌ಸೈಟ್ ಮೂಲಕ ಪರಿಶೀಲಿಸಿ.",
            "hi": f"नियम-आधारित जोखिम स्कोर {r['score']}/100 ({r['level']}); यह अनुमान है, प्रमाण नहीं। संस्था की आधिकारिक ऐप या वेबसाइट से सत्यापित करें।",
        }.get(language, f"The rule-based score is {r['score']}/100 ({r['level']}); it is an estimate, not proof.")
    if r:
        actions = " ".join(r.get("actions", [])[:2])
        return f"For this analysis ({r['level']} risk, {r['score']}/100): {actions} This is a rule-based assessment, not proof."
    return {
        "en": "I can't verify a reliable answer to that question from the available official guidance. For online financial fraud, use https://cybercrime.gov.in/ or call 1930; for an immediate emergency, call 112.",
        "kn": "ಲಭ್ಯವಿರುವ ಅಧಿಕೃತ ಮಾರ್ಗದರ್ಶನದಿಂದ ಈ ಪ್ರಶ್ನೆಗೆ ವಿಶ್ವಾಸಾರ್ಹ ಉತ್ತರವನ್ನು ಪರಿಶೀಲಿಸಲು ಸಾಧ್ಯವಾಗಲಿಲ್ಲ. ಆನ್‌ಲೈನ್ ಹಣಕಾಸು ವಂಚನೆಗೆ https://cybercrime.gov.in/ ಅಥವಾ 1930 ಬಳಸಿ; ತಕ್ಷಣದ ತುರ್ತು ಪರಿಸ್ಥಿತಿಗೆ 112 ಕರೆ ಮಾಡಿ.",
        "hi": "उपलब्ध आधिकारिक मार्गदर्शन से इस प्रश्न का विश्वसनीय उत्तर सत्यापित नहीं कर सका। ऑनलाइन वित्तीय धोखाधड़ी के लिए https://cybercrime.gov.in/ या 1930 का उपयोग करें; तत्काल आपातस्थिति में 112 पर कॉल करें।",
    }.get(language, "I can't verify a reliable answer from the available official guidance.")
