import { useEffect, useRef, useState } from "react";
import {
  Activity, AlertTriangle, AudioLines, BarChart3, Check, ChevronLeft, ChevronRight, CircleHelp,
  ClipboardList, Download, FileImage, FlaskConical, Headphones, LoaderCircle,
  LogOut, MapPin, Menu, MessageSquareText, Pause, Play, Shield, ShieldAlert, Square, Upload, Volume2, X,
} from "lucide-react";
import ChatPanel from "./ChatPanel";
import SafetyHub from "./SafetyHub";
import Assistance from "./Assistance";
import { api, clearAuthToken, languageName, post, setAuthToken } from "./api";
import type { Analysis, InputLanguage, Language } from "./types";
import AuthPage, { type AuthMode, type AuthUser } from "./AuthPage";

type Page = "investigate" | "history" | "analytics" | "evaluation" | "assistance" | "safety";
interface Preferences { inputLanguage: InputLanguage; outputLanguage: Language; speechLanguage: Language }
interface HistoryEntry { id: number; ts: number; language: string; score: number; level: Analysis["level"]; patterns: string[]; snippet: string; input_type: string }
const COLORS: Record<Analysis["level"], string> = { LOW: "var(--mint)", MEDIUM: "var(--amber)", HIGH: "var(--orange)", CRITICAL: "var(--red)" };
const defaults: Preferences = { inputLanguage: "auto", outputLanguage: "en", speechLanguage: "en" };

function getPreferences(): Preferences {
  try { return { ...defaults, ...JSON.parse(localStorage.getItem("scamshield-language") ?? "{}") } as Preferences; }
  catch { return defaults; }
}

function formatSpeech(analysis: Analysis) {
  const templates: Record<Language, { risk: string; signals: string; evidence: string; none: string; claims: string; noClaims: string; actions: string }> = {
    en: { risk: `${analysis.level} risk, ${analysis.score} out of 100. ${analysis.classification}.`, signals: "Detected signals:", evidence: "Evidence:", none: "No major risk signals were detected.", claims: "Claim checks:", noClaims: "No checkable claims were found.", actions: "Recommended actions:" },
    kn: { risk: `ಅಪಾಯದ ಮಟ್ಟ ${analysis.level}, 100ರಲ್ಲಿ ${analysis.score}. ${analysis.classification}.`, signals: "ಪತ್ತೆಯಾದ ಸೂಚನೆಗಳು:", evidence: "ಸಾಕ್ಷ್ಯ:", none: "ಪ್ರಮುಖ ಅಪಾಯದ ಸೂಚನೆಗಳು ಪತ್ತೆಯಾಗಿಲ್ಲ.", claims: "ಹೇಳಿಕೆಗಳ ಪರಿಶೀಲನೆ:", noClaims: "ಪರಿಶೀಲಿಸಬಹುದಾದ ಹೇಳಿಕೆಗಳು ಕಂಡುಬಂದಿಲ್ಲ.", actions: "ಶಿಫಾರಸು ಮಾಡಿದ ಕ್ರಮಗಳು:" },
    hi: { risk: `जोखिम स्तर ${analysis.level}, 100 में से ${analysis.score}। ${analysis.classification}।`, signals: "पहचाने गए संकेत:", evidence: "साक्ष्य:", none: "जोखिम के कोई प्रमुख संकेत नहीं मिले।", claims: "दावों की जांच:", noClaims: "जांचने योग्य कोई दावा नहीं मिला।", actions: "सुझाए गए कदम:" },
  };
  const text = templates[analysis.output_language];
  return [
    text.risk,
    analysis.signals.length ? `${text.signals} ${analysis.signals.map((item) => `${item.label}. ${text.evidence} ${item.evidence}`).join(". ")}` : text.none,
    analysis.claims.length ? `${text.claims} ${analysis.claims.map((item) => `${item.status}: ${item.claim}. ${item.reason}`).join(". ")}` : text.noClaims,
    `${text.actions} ${analysis.actions.join(". ")}`,
  ].join(" ");
}

function App() {
  const [authUser, setAuthUser] = useState<AuthUser | null>(null);
  const [authChecked, setAuthChecked] = useState(false);
  const [authMode, setAuthMode] = useState<AuthMode>("login");
  const [authError, setAuthError] = useState("");
  const [authNotice, setAuthNotice] = useState("");
  const [authBusy, setAuthBusy] = useState(false);
  const [page, setPage] = useState<Page>("investigate");
  const [preferences, setPreferences] = useState<Preferences>(getPreferences);
  const [analysis, setAnalysis] = useState<Analysis | null>(null);
  const [text, setText] = useState("");
  const [inputType, setInputType] = useState<"text" | "screenshot">("text");
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState("");
  const [error, setError] = useState("");
  const [chatCollapsed, setChatCollapsed] = useState(() => window.matchMedia("(max-width: 1030px)").matches);
  const [mobileNav, setMobileNav] = useState(false);
  const [health, setHealth] = useState("Connecting to analysis service");
  const [speechText, setSpeechText] = useState("");
  const [speechTextLanguage, setSpeechTextLanguage] = useState<Language>("en");
  const [speechStatus, setSpeechStatus] = useState("idle");
  const [speechNote, setSpeechNote] = useState("");
  const speechRequest = useRef(0);
  const ttsAudio = useRef<HTMLAudioElement | null>(null);

  useEffect(() => {
    let active = true;
    void api<{ authenticated: boolean; user: AuthUser | null }>("/api/auth/me")
      .then((result) => {
        if (!active) return;
        if (result.authenticated && result.user) setAuthUser(result.user);
        else { clearAuthToken(); setAuthUser(null); }
      })
      .catch((issue) => {
        if (active) {
          clearAuthToken();
          setAuthUser(null);
          setAuthMode("login");
          setAuthError(issue instanceof Error ? issue.message : "Could not verify your account session.");
        }
      })
      .finally(() => { if (active) setAuthChecked(true); });
    return () => { active = false; };
  }, []);
  useEffect(() => {
    const handleUnauthorized = () => {
      clearAuthToken();
      setAuthUser(null);
      setAuthMode("login");
      setAuthNotice("");
      setAuthError("Your session expired. Please sign in again.");
    };
    window.addEventListener("scamshield-unauthorized", handleUnauthorized);
    return () => window.removeEventListener("scamshield-unauthorized", handleUnauthorized);
  }, []);
  useEffect(() => { localStorage.setItem("scamshield-language", JSON.stringify(preferences)); }, [preferences]);
  useEffect(() => {
    if (!authUser) return;
    void post("/api/language/preferences", {
      input_language: preferences.inputLanguage,
      output_language: preferences.outputLanguage,
      speech_language: preferences.speechLanguage,
    }).catch(() => undefined);
  }, [authUser, preferences]);
  useEffect(() => {
    void api<{ mode: string }>("/api/health").then((result) => setHealth(result.mode)).catch(() => setHealth("Backend unavailable"));
  }, []);
  useEffect(() => () => { speechRequest.current += 1; window.speechSynthesis?.cancel(); }, []);
  useEffect(() => {
    const narrow = window.matchMedia("(max-width: 1030px)");
    const collapseDrawer = (event: MediaQueryListEvent) => { if (event.matches) setChatCollapsed(true); };
    narrow.addEventListener("change", collapseDrawer);
    return () => narrow.removeEventListener("change", collapseDrawer);
  }, []);

  function updatePreference<K extends keyof Preferences>(key: K, value: Preferences[K]) {
    setPreferences((current) => ({ ...current, [key]: value }));
  }

  async function extractScreenshot(file?: File) {
    if (!file) return;
    setError(""); setNotice(""); setBusy(true); setAnalysis(null);
    const form = new FormData();
    form.append("file", file);
    form.append("ocr_language", preferences.inputLanguage);
    try {
      const result = await api<{ text: string; ocr_fallback?: boolean }>("/api/ocr", { method: "POST", body: form });
      setText(result.text);
      setInputType("screenshot");
      setNotice(result.ocr_fallback ? "Requested OCR language data was unavailable; English-only OCR was used. Review the extracted text carefully before analysis." : result.text ? "Text extracted. Review or edit it below, choose the explanation language, then analyze." : "No text was found. You can type or paste the message below.");
    } catch (issue) { setError(issue instanceof Error ? issue.message : "Screenshot OCR failed."); }
    finally { setBusy(false); }
  }

  async function analyze() {
    setBusy(true); setError(""); setNotice(""); setAnalysis(null);
    try {
      const result = await post<Analysis>("/api/analyze/text", {
        text, input_type: inputType, input_language: preferences.inputLanguage, output_language: preferences.outputLanguage,
      });
      setAnalysis(result);
    } catch (issue) { setError(issue instanceof Error ? issue.message : "Analysis failed."); }
    finally { setBusy(false); }
  }

  async function speak(value: string, contentLanguage: Language = speechTextLanguage) {
    const engine = window.speechSynthesis;
    if (!engine) { setSpeechNote("Speech synthesis is not supported in this browser."); return; }
    const requestId = ++speechRequest.current;
    engine.cancel(); ttsAudio.current?.pause(); setSpeechStatus("loading"); setSpeechNote(""); setSpeechText(value);
    let spokenText = value;
    let language = preferences.speechLanguage;
    if (language !== contentLanguage) {
      try {
        const result = await post<{ text: string; language: string; translated: boolean }>("/api/speech/text", { text: value, speech_language: language });
        if (requestId !== speechRequest.current) return;
        spokenText = result.text;
        if (!result.translated) setSpeechNote(`Translation to ${languageName[language]} is unavailable; the original text will be read using the selected speech language.`);
      } catch {
        if (requestId !== speechRequest.current) return;
        setSpeechNote(`Speech translation to ${languageName[language]} is unavailable; the original text will be read using the selected speech language.`);
      }
    }
    let voices = engine.getVoices();
    if (!voices.length) {
      voices = await new Promise<SpeechSynthesisVoice[]>((resolve) => {
        const finish = () => { engine.removeEventListener("voiceschanged", finish); resolve(engine.getVoices()); };
        engine.addEventListener("voiceschanged", finish, { once: true });
        window.setTimeout(finish, 1400);
      });
    }
    if (requestId !== speechRequest.current) return;
    const locale: Record<Language, string> = { en: "en-IN", kn: "kn-IN", hi: "hi-IN" };
    const targetLocale = locale[language].toLowerCase();
    const voice = voices.find((item) => item.lang.toLowerCase() === targetLocale)
      ?? voices.find((item) => item.lang.toLowerCase() === language || item.lang.toLowerCase().startsWith(`${language}-`))
      ?? voices.find((item) => item.lang.toLowerCase().endsWith("-in"))
      ?? voices.find((item) => item.default)
      ?? voices[0];
    const hasMatch = !!voice && (voice.lang.toLowerCase() === language || voice.lang.toLowerCase().startsWith(`${language}-`));
    if (!hasMatch && language !== "en") {
      try {
        const token = localStorage.getItem("scamshield-auth-token");
        const res = await fetch("/api/speech/tts", { method: "POST", credentials: "include", headers: { "Content-Type": "application/json", ...(token ? { Authorization: `Bearer ${token}` } : {}) }, body: JSON.stringify({ text: spokenText.slice(0, 1400), language }) });
        if (!res.ok) throw new Error("tts");
        const blob = await res.blob();
        if (requestId !== speechRequest.current) return;
        const audio = new Audio(URL.createObjectURL(blob));
        ttsAudio.current = audio;
        audio.onplay = () => setSpeechStatus("speaking");
        audio.onended = () => setSpeechStatus("idle");
        audio.onerror = () => { setSpeechStatus("idle"); setSpeechNote("Could not play the voice audio."); };
        setSpeechNote(`Using online ${languageName[language]} voice.`);
        await audio.play();
        return;
      } catch { setSpeechNote(`Online ${languageName[language]} voice unavailable; trying the browser voice.`); }
    }
    const matchingLanguageVoice = voice && (voice.lang.toLowerCase() === language || voice.lang.toLowerCase().startsWith(`${language}-`));
    if (voice && !matchingLanguageVoice) {
      setSpeechNote((current) => [current, `No ${languageName[language]} voice is installed; using the closest available ${voice.lang} voice.`].filter(Boolean).join(" "));
    } else if (!voice) {
      setSpeechNote((current) => [current, `No installed voice is listed; the browser will use its default voice with ${locale[language]} language settings.`].filter(Boolean).join(" "));
    }
    const utterance = new SpeechSynthesisUtterance(spokenText);
    if (voice) utterance.voice = voice;
    utterance.lang = locale[language];
    utterance.onstart = () => { if (requestId === speechRequest.current) setSpeechStatus("speaking"); };
    utterance.onpause = () => { if (requestId === speechRequest.current) setSpeechStatus("paused"); };
    utterance.onresume = () => { if (requestId === speechRequest.current) setSpeechStatus("speaking"); };
    utterance.onend = () => { if (requestId === speechRequest.current) setSpeechStatus("idle"); };
    utterance.onerror = () => { if (requestId === speechRequest.current) { setSpeechStatus("idle"); setSpeechNote("The selected browser voice could not read this text."); } };
    engine.speak(utterance);
  }

  function stopSpeech() {
    speechRequest.current += 1;
    window.speechSynthesis?.cancel();
    ttsAudio.current?.pause(); ttsAudio.current = null;
    setSpeechStatus("idle");
  }

  function readAloud(value: string, language: Language) {
    setSpeechText(value);
    setSpeechTextLanguage(language);
    void speak(value, language);
  }

  async function logout() {
    setAuthBusy(true);
    setAuthError("");
    try {
      await api("/api/auth/logout", { method: "POST" });
      clearAuthToken();
      setAuthUser(null);
      setAuthMode("login");
      setAuthNotice("");
      setPage("investigate");
      setAnalysis(null);
      setText("");
      stopSpeech();
      setSpeechText("");
      setSpeechTextLanguage("en");
    } catch (issue) {
      setAuthError(issue instanceof Error ? issue.message : "Could not sign out. Please try again.");
    } finally {
      setAuthBusy(false);
    }
  }

  if (!authChecked) {
    return <main className="auth-shell"><div className="auth-loading"><LoaderCircle className="spin" size={20} /> Checking your ScamShield session…</div></main>;
  }
  if (!authUser) {
    return <AuthPage mode={authMode} initialError={authError} onModeChange={(mode) => { setAuthMode(mode); setAuthError(""); }} onAuthenticated={(user, token, message) => { setAuthToken(token); setAuthUser(user); setAuthError(""); setAuthNotice(message); }} />;
  }

  function navigate(next: Page) { setPage(next); setMobileNav(false); }

  return <div className={`app-shell ${chatCollapsed ? "app-shell--chat-collapsed" : ""}`}>
    <aside className={`primary-nav ${mobileNav ? "primary-nav--open" : ""}`}>
      <div className="brand-lockup"><div className="brand-mark"><Shield size={21} /></div><div><strong>ScamShield</strong><span>VERIFY / INDIA</span></div></div>
      <div className="nav-label">WORKSPACE</div>
      <nav aria-label="Main navigation">
        <NavButton active={page === "investigate"} icon={<ShieldAlert size={17} />} onClick={() => navigate("investigate")}>Investigate</NavButton>
        <NavButton active={page === "history"} icon={<ClipboardList size={17} />} onClick={() => navigate("history")}>Case history</NavButton>
        <NavButton active={page === "analytics"} icon={<BarChart3 size={17} />} onClick={() => navigate("analytics")}>Analytics</NavButton>
        <NavButton active={page === "evaluation"} icon={<FlaskConical size={17} />} onClick={() => navigate("evaluation")}>Evaluation lab</NavButton>
        <NavButton active={page === "safety"} icon={<ShieldAlert size={17} />} onClick={() => navigate("safety")}>Safety hub</NavButton>
        <NavButton active={page === "assistance"} icon={<MapPinIcon />} onClick={() => navigate("assistance")}>Cyber help near me</NavButton>
      </nav>
      <div className="nav-bottom"><div className="service-indicator"><span className={health === "Backend unavailable" ? "service-dot service-dot--bad" : "service-dot"} /><div><small>ANALYSIS SERVICE</small><strong>{health}</strong></div></div><p>Detect · Verify · Explain · Protect</p></div>
    </aside>
    {mobileNav && <button className="nav-scrim" aria-label="Close navigation" onClick={() => setMobileNav(false)} />}
    <main className="main-column">
      <header className="topbar">
        <div className="topbar-start"><button className="icon-button mobile-menu" onClick={() => setMobileNav((open) => !open)} aria-label="Toggle navigation"><Menu size={19} /></button><div className="crumb"><span>SCAMSHIELD</span><ChevronRight size={14} /><b>{pageLabels[page]}</b></div></div>
        <div className="speech-toolbar" aria-label="Text-to-speech controls">
          <label className="speech-select"><Headphones size={15} /><span className="sr-only">Speech language</span><select aria-label="Speech language" value={preferences.speechLanguage} onChange={(event) => updatePreference("speechLanguage", event.target.value as Language)}>{languageOptions.map(([code, label]) => <option key={code} value={code}>{label}</option>)}</select></label>
          <button className="icon-button" title="Play selected result or response" aria-label="Play selected result or response" disabled={!speechText || speechStatus === "loading"} onClick={() => void speak(speechText, speechTextLanguage)}>{speechStatus === "loading" ? <LoaderCircle className="spin" size={15} /> : <Play size={15} />}</button>
          <button className="icon-button" title="Pause speech" aria-label="Pause speech" disabled={speechStatus !== "speaking"} onClick={() => { window.speechSynthesis?.pause(); ttsAudio.current?.pause(); setSpeechStatus("paused"); }}><Pause size={15} /></button>
          <button className="icon-button" title="Resume speech" aria-label="Resume speech" disabled={speechStatus !== "paused"} onClick={() => { window.speechSynthesis?.resume(); void ttsAudio.current?.play(); setSpeechStatus("speaking"); }}><AudioLines size={15} /></button>
          <button className="icon-button" title="Stop speech" aria-label="Stop speech" disabled={speechStatus === "idle"} onClick={stopSpeech}><Square size={14} /></button>
        </div>
        <div className="chat-toggle user-session" title={`Signed in as ${authUser.email}`}><span className="user-greeting">{authUser.name}</span></div>
        <button className="icon-button logout-button" onClick={() => void logout()} disabled={authBusy} title="Log out" aria-label="Log out"><LogOut size={16} /></button>
        <button className="chat-toggle" onClick={() => setChatCollapsed((value) => !value)} aria-label={chatCollapsed ? "Open cyber safety assistant" : "Close cyber safety assistant"} aria-expanded={!chatCollapsed}><MessageSquareText size={16} /><span>Assistant</span>{chatCollapsed ? <ChevronLeft size={15} /> : <ChevronRight size={15} />}</button>
      </header>
      <div className="content-scroll">
        {authNotice && <div className="notice notice--success" role="status">{authNotice}<button className="tiny-icon" aria-label="Dismiss notice" onClick={() => setAuthNotice("")}><X size={14} /></button></div>}
        {speechNote && <div className="speech-note" role="status"><Volume2 size={15} />{speechNote}<button className="tiny-icon" aria-label="Dismiss speech notice" onClick={() => setSpeechNote("")}><X size={14} /></button></div>}
        {page === "investigate" && <Investigation
          text={text} setText={setText} inputType={inputType} busy={busy} analysis={analysis} error={error} notice={notice}
          preferences={preferences} updatePreference={updatePreference} onAnalyze={analyze} onImage={extractScreenshot} onRead={(result) => readAloud(result, analysis?.output_language ?? preferences.outputLanguage)}
          onClear={() => { setText(""); setAnalysis(null); setInputType("text"); setError(""); setNotice(""); }}
          onDownload={async () => {
            if (!analysis) return;
            try { const summary = await api<{ text: string }>(`/api/history/${analysis.id}/summary`); const link = document.createElement("a"); link.href = URL.createObjectURL(new Blob([summary.text], { type: "text/plain" })); link.download = `incident-${analysis.id}.txt`; link.click(); URL.revokeObjectURL(link.href); }
            catch (issue) { setError(issue instanceof Error ? issue.message : "Summary download failed."); }
          }} />}
        {page === "history" && <HistoryPage onOpen={(result) => { setAnalysis(result); setPage("investigate"); setText(""); setInputType("text"); }} />}
        {page === "analytics" && <AnalyticsPage />}
        {page === "evaluation" && <EvaluationPage />}
        {page === "safety" && <SafetyHub onAsk={() => setChatCollapsed(false)} />}
        {page === "assistance" && <Assistance />}
      </div>
      <footer className="main-footer"><span>Assistive assessment only. Verify sensitive requests independently.</span><span><CircleHelp size={13} /> Not an official government service</span></footer>
    </main>
    <ChatPanel analysis={analysis} language={preferences.outputLanguage} userId={authUser.id} onRead={(value, language) => readAloud(value, language)} collapsed={chatCollapsed} onToggle={() => setChatCollapsed((value) => !value)} onLanguage={(value) => updatePreference("outputLanguage", value)} />
    {!chatCollapsed && <button className="chat-scrim" aria-label="Close assistant" onClick={() => setChatCollapsed(true)} />}
  </div>;
}

const languageOptions: [Language, string][] = [["en", "English"], ["kn", "ಕನ್ನಡ"], ["hi", "हिन्दी"]];
const pageLabels: Record<Page, string> = { investigate: "Investigate", history: "Case history", analytics: "Analytics", evaluation: "Evaluation lab", assistance: "Cyber help near me", safety: "Safety hub" };

function MapPinIcon() { return <span className="nav-map-icon"><MapPin size={17} /></span>; }

function NavButton({ active, icon, onClick, children }: { active: boolean; icon: React.ReactNode; onClick: () => void; children: React.ReactNode }) {
  return <button className={`nav-button ${active ? "nav-button--active" : ""}`} onClick={onClick}>{icon}<span>{children}</span>{active && <span className="nav-indicator" />}</button>;
}

function Investigation(props: {
  text: string; setText: (text: string) => void; inputType: "text" | "screenshot"; busy: boolean; analysis: Analysis | null; error: string; notice: string;
  preferences: Preferences; updatePreference: <K extends keyof Preferences>(key: K, value: Preferences[K]) => void;
  onAnalyze: () => void; onImage: (file?: File) => void; onRead: (text: string) => void; onClear: () => void; onDownload: () => void;
}) {
  const [dragging, setDragging] = useState(false);
  const chooseImage = (event: React.ChangeEvent<HTMLInputElement>) => { props.onImage(event.target.files?.[0]); event.target.value = ""; };

  return <div className="page-stack investigate-page">
    <div className="page-heading"><div><span className="eyebrow">THREAT TRIAGE / 01</span><h1>Investigate a message</h1><p>Check suspicious texts, emails, links, and screenshots before you act.</p></div><div className="workflow"><span className="workflow-active">DETECT</span><span>VERIFY</span><span>EXPLAIN</span><span>PROTECT</span></div></div>
    <section className="input-panel" aria-labelledby="message-label">
      <div className="language-row">
        <label><span>Message language</span><select value={props.preferences.inputLanguage} onChange={(event) => props.updatePreference("inputLanguage", event.target.value as InputLanguage)}><option value="auto">Auto-detect</option><option value="en">English</option><option value="kn">Kannada</option><option value="hi">Hindi</option></select></label>
        <label><span>Explanation language</span><select value={props.preferences.outputLanguage} onChange={(event) => props.updatePreference("outputLanguage", event.target.value as Language)}>{languageOptions.map(([code, name]) => <option key={code} value={code}>{name}</option>)}</select></label>
        <span className="language-note">Risk score and source evidence stay unchanged.</span>
      </div>
      <label id="message-label" className="field-label" htmlFor="message-text">Message or link <span>Do not enter passwords or active credentials.</span></label>
      <textarea id="message-text" className="message-input" maxLength={5000} value={props.text} onChange={(event) => props.setText(event.target.value)} onDragOver={(event) => { event.preventDefault(); setDragging(true); }} onDragLeave={() => setDragging(false)} onDrop={(event) => { event.preventDefault(); setDragging(false); props.onImage(event.dataTransfer.files[0]); }} placeholder="Paste a suspicious message here. English, Kannada, Hindi, and mixed-language text are supported." />
      <div className="input-footer"><span>{props.text.length.toLocaleString()} / 5,000 characters {props.inputType === "screenshot" && <span className="ocr-chip"><Check size={12} /> Screenshot text</span>}</span><span>Links are analyzed, never opened.</span></div>
      <div className={`upload-strip ${dragging ? "upload-strip--active" : ""}`}>
        <div className="upload-copy"><span className="upload-icon"><FileImage size={18} /></span><div><strong>Analyze a screenshot</strong><small>PNG or JPEG · max 5 MB · OCR text stays editable</small></div></div>
        <label className="button button--secondary upload-button"><Upload size={15} /> Choose image<input type="file" accept="image/png,image/jpeg" onChange={chooseImage} disabled={props.busy} /></label>
      </div>
      {props.notice && <div className="notice notice--success" role="status"><Check size={16} />{props.notice}</div>}
      {props.error && <div className="notice notice--error" role="alert"><AlertTriangle size={17} />{props.error}</div>}
      <div className="analysis-actions"><span>Rule-based score · trusted-source claim checks</span><div><button className="button button--secondary" onClick={props.onClear} disabled={!props.text && !props.analysis}>Clear</button><button className="button button--primary" onClick={props.onAnalyze} disabled={props.busy || !props.text.trim()}>{props.busy ? <><LoaderCircle className="spin" size={16} /> Analyzing…</> : <><Activity size={16} /> Analyze message</>}</button></div></div>
    </section>
    {props.analysis && <AnalysisResult analysis={props.analysis} text={props.text} onRead={props.onRead} onDownload={props.onDownload} />}
  </div>;
}

function AnalysisResult({ analysis, text, onRead, onDownload }: { analysis: Analysis; text: string; onRead: (text: string) => void; onDownload: () => void }) {
  const [expanded, setExpanded] = useState(true);
  const indicators = ["phones", "emails", "upi_ids", "orgs", "requested_info", "urls"] as const;
  const labels: Record<(typeof indicators)[number], string> = { phones: "Phone numbers", emails: "Email addresses", upi_ids: "UPI IDs", orgs: "Organizations", requested_info: "Requested data", urls: "Links" };
  return <section className="results-section" aria-label="Analysis results">
    <div className="result-heading"><div><span className="eyebrow">CASE #{analysis.id} / ANALYSIS</span><h2>Assessment</h2></div><button className="button button--secondary button--small" onClick={() => onRead(formatSpeech(analysis))}><Volume2 size={15} /> Read aloud</button></div>
    {analysis.translation_status === "english_fallback" && analysis.output_language !== "en" && <div className="notice notice--warning"><AlertTriangle size={16} />Explanation translation is unavailable. The English explanation is shown; score, evidence, and claims were not changed.</div>}
    <div className="risk-overview" style={{ "--risk-color": COLORS[analysis.level] } as React.CSSProperties}>
      <div className="risk-main"><span className="risk-eyebrow">DETERMINISTIC RISK SCORE</span><div className="risk-score"><strong>{analysis.score}</strong><span>/ 100</span></div><span className="risk-level">{analysis.level} RISK</span></div>
      <div className="risk-summary"><h3>{analysis.classification}</h3><p>Detected language: {analysis.language.language} ({analysis.language.confidence}% confidence)</p><div className="risk-meter"><span style={{ width: `${analysis.score}%` }} /></div><small>Fixed rules score this message. It is an estimate, not proof.</small></div>
      <button className="risk-toggle" onClick={() => setExpanded((value) => !value)} aria-expanded={expanded} title={expanded ? "Collapse details" : "Expand details"}>{expanded ? <ChevronLeft size={18} /> : <ChevronRight size={18} />}</button>
    </div>
    {expanded && <>
      {text && <details className="result-block"><summary>Analyzed message</summary><p className="quoted-message">{text}</p></details>}
      <div className="result-block"><div className="block-heading"><div><span className="eyebrow">SIGNALS</span><h3>Detected indicators</h3></div><span className="count-badge">{analysis.signals.length}</span></div>
        {analysis.signals.length ? <div className="signal-list">{analysis.signals.map((signal, index) => <article className="signal-row" key={`${signal.type}-${index}`}><span className="signal-mark"><ShieldAlert size={16} /></span><div><strong>{signal.label}</strong><p>Message evidence: <q>{signal.evidence}</q></p></div><span className="signal-weight">+{signal.weight}</span></article>)}</div> : <div className="empty-inline"><Check size={16} />No major scam signals detected.</div>}
      </div>
      <div className="result-block"><div className="block-heading"><div><span className="eyebrow">ENTITY EXTRACTION</span><h3>Message indicators</h3></div></div>
        <div className="indicator-grid">{indicators.map((key) => <div className="indicator-cell" key={key}><small>{labels[key]}</small><div>{analysis.entities[key].length ? analysis.entities[key].map((item) => <span className="data-chip" key={item}>{item}</span>) : <span className="not-found">None found</span>}</div></div>)}</div>
      </div>
      <div className="result-block"><div className="block-heading"><div><span className="eyebrow">CLAIM CHECKS</span><h3>Retrieved evidence</h3></div><span className="count-badge">{analysis.claims.length}</span></div>
        {analysis.claims.length ? analysis.claims.map((claim, index) => <details className="claim-row" key={`${index}-${claim.claim}`}><summary><span className={`verdict verdict--${claim.status.toLowerCase()}`}>{claim.status}</span><span>{claim.claim}</span></summary><p>{claim.reason}</p>{claim.evidence.map((evidence) => <div className="evidence-row" key={evidence.url}><strong>{evidence.org}: {evidence.title}</strong><p>{evidence.text}</p><a href={evidence.url} target="_blank" rel="noreferrer">{evidence.url}</a><small>Dataset entry date: {evidence.retrieved_on || "not provided"}</small></div>)}</details>) : <div className="empty-inline">No checkable claims found in this message.</div>}
      </div>
      <div className="result-block"><div className="block-heading"><div><span className="eyebrow">NEXT STEPS</span><h3>Protective actions</h3></div></div><ol className="action-list">{analysis.actions.map((action, index) => <li key={`${index}-${action}`}><span>{String(index + 1).padStart(2, "0")}</span>{action}</li>)}</ol></div>
      {analysis.urls.length > 0 && <div className="result-block"><div className="block-heading"><div><span className="eyebrow">LINK INSPECTION</span><h3>Address signals</h3></div></div>{analysis.urls.map((url) => <div className="url-row" key={url.url}><div><strong>{url.host}</strong><p>{url.reasons.length ? url.reasons.join(" · ") : "No address-pattern indicators found."}</p></div><span>Not opened</span></div>)}<small className="source-note">No live reputation lookup was performed.</small></div>}
      {analysis.impersonation.length > 0 && <div className="result-block"><div className="block-heading"><div><span className="eyebrow">IDENTITY SIGNAL</span><h3>Possible impersonation</h3></div></div>{analysis.impersonation.map((item) => <p className="impersonation-row" key={item.claimed_org}><strong>{item.claimed_org}</strong> · {item.reason}</p>)}</div>}
      <div className="result-bottom"><p>{analysis.disclaimer}</p><button className="button button--secondary button--small" onClick={onDownload}><Download size={15} /> Download incident summary</button></div>
    </>}
  </section>;
}

function HistoryPage({ onOpen }: { onOpen: (analysis: Analysis) => void }) {
  const [rows, setRows] = useState<HistoryEntry[]>([]);
  const [search, setSearch] = useState("");
  const [level, setLevel] = useState("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  async function refresh() {
    setLoading(true); setError("");
    try { setRows(await api<HistoryEntry[]>(`/api/history?q=${encodeURIComponent(search)}&level=${encodeURIComponent(level)}`)); }
    catch (issue) { setError(issue instanceof Error ? issue.message : "Could not load case history."); }
    finally { setLoading(false); }
  }
  useEffect(() => { void refresh(); }, []);
  async function remove(id: number) {
    if (!window.confirm(`Delete saved case #${id}?`)) return;
    try { await api(`/api/history/${id}`, { method: "DELETE" }); await refresh(); }
    catch (issue) { setError(issue instanceof Error ? issue.message : "Could not delete case."); }
  }
  async function clear() {
    if (!window.confirm("Delete all saved cases? This cannot be undone.")) return;
    try { await api("/api/history", { method: "DELETE" }); await refresh(); }
    catch (issue) { setError(issue instanceof Error ? issue.message : "Could not clear case history."); }
  }
  return <div className="page-stack"><PageHeading eyebrow="INVESTIGATION RECORDS" title="Case history" subtitle="Review and manage recent saved analyses." />
    <div className="history-tools"><form onSubmit={(event) => { event.preventDefault(); void refresh(); }}><label className="sr-only" htmlFor="history-search">Search cases</label><input id="history-search" value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Search masked snippet or signal" /><select aria-label="Filter by risk level" value={level} onChange={(event) => setLevel(event.target.value)}><option value="">All risk levels</option>{["LOW", "MEDIUM", "HIGH", "CRITICAL"].map((item) => <option key={item}>{item}</option>)}</select><button className="button button--secondary" type="submit">Search</button></form><button className="button button--danger" onClick={() => void clear()} disabled={!rows.length}>Delete all</button></div>
    {error && <div className="notice notice--error" role="alert">{error}</div>}{loading && <div className="loading-line"><span className="spinner" />Loading cases…</div>}
    {!loading && !rows.length && <div className="empty-state"><ClipboardList size={24} /><strong>No saved cases</strong><p>New analyses appear here with a masked snippet. Original message text is not stored.</p></div>}
    <div className="history-list">{rows.map((item) => <article className="history-row" key={item.id}><div className="history-score" style={{ color: COLORS[item.level] }}><strong>{item.level}</strong><span>{item.score}/100</span></div><div className="history-description"><strong>Case #{item.id} <span className="history-type">{item.input_type}</span></strong><p>{item.snippet || "No saved snippet"}</p><div>{item.patterns.map((pattern) => <span className="data-chip" key={pattern}>{pattern}</span>)}</div><small>{new Date(item.ts * 1000).toLocaleString()} · {item.language}</small></div><div className="history-actions"><button className="button button--secondary button--small" onClick={async () => { try { onOpen(await api<Analysis>(`/api/history/${item.id}`)); } catch (issue) { setError(issue instanceof Error ? issue.message : "Could not open case."); } }}>Open</button><button className="icon-button" onClick={() => void remove(item.id)} title="Delete case" aria-label={`Delete case ${item.id}`}><X size={16} /></button></div></article>)}</div>
  </div>;
}

function AnalyticsPage() {
  const [stats, setStats] = useState<Record<string, any> | null>(null);
  const [error, setError] = useState("");
  useEffect(() => { void api<Record<string, any>>("/api/stats").then(setStats).catch((issue) => setError(issue.message)); }, []);
  if (error) return <div className="page-stack"><PageHeading eyebrow="CASE TRENDS" title="Analytics" subtitle="Saved case counts and risk indicators." /><div className="notice notice--error">{error}</div></div>;
  if (!stats) return <div className="page-stack"><PageHeading eyebrow="CASE TRENDS" title="Analytics" subtitle="Saved case counts and risk indicators." /><div className="loading-line"><span className="spinner" />Loading analytics…</div></div>;
  const high = (stats.levels.HIGH ?? 0) + (stats.levels.CRITICAL ?? 0);
  return <div className="page-stack"><PageHeading eyebrow="CASE TRENDS" title="Analytics" subtitle="Saved case counts and risk indicators." />
    <div className="metric-grid">{[["All cases", stats.total], ["High or critical", high], ["Claims checked", stats.claims_verified], ["Possible impersonation", stats.impersonation]].map(([label, value]) => <div className="metric-card" key={label}><small>{label}</small><strong>{value}</strong></div>)}</div>
    <div className="analytics-grid"><StatBars title="Risk levels" values={stats.levels} /><StatBars title="Detected patterns" values={stats.patterns} /><StatBars title="Detected languages" values={stats.languages} /><StatBars title="Cases by day" values={stats.trend} /></div>
  </div>;
}

function StatBars({ title, values }: { title: string; values: Record<string, number> }) {
  const max = Math.max(1, ...Object.values(values));
  return <section className="stats-panel"><div className="block-heading"><h3>{title}</h3></div>{Object.entries(values).length ? Object.entries(values).map(([name, count]) => <div className="stat-item" key={name}><div><span>{name}</span><small>{count}</small></div><div className="stat-track"><span style={{ width: `${count / max * 100}%` }} /></div></div>) : <p className="not-found">No saved data yet.</p>}</section>;
}

function EvaluationPage() {
  const [result, setResult] = useState<Record<string, any> | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  async function run() {
    setBusy(true); setError("");
    try { setResult(await api<Record<string, any>>("/api/evaluation/run", { method: "POST" })); }
    catch (issue) { setError(issue instanceof Error ? issue.message : "Evaluation failed."); }
    finally { setBusy(false); }
  }
  const overall = result?.overall;
  return <div className="page-stack"><PageHeading eyebrow="RULE PERFORMANCE" title="Evaluation lab" subtitle="Measure the rule-based layer against the built-in sample dataset." />
    <div className="evaluation-intro"><div><FlaskConical size={19} /><div><strong>Small built-in dataset</strong><p>Evaluation runs locally against included examples. It does not estimate real-world accuracy.</p></div></div><button className="button button--primary" onClick={() => void run()} disabled={busy}>{busy ? <><LoaderCircle className="spin" size={16} /> Running…</> : <><Activity size={16} /> Run evaluation</>}</button></div>
    {error && <div className="notice notice--error">{error}</div>}
    {overall && <><div className="metric-grid">{[["Test cases", overall.total], ["Accuracy", percent(overall.accuracy)], ["Precision", percent(overall.precision)], ["Recall", percent(overall.recall)], ["F1", percent(overall.f1)], ["False-positive rate", percent(overall.false_positive_rate)]].map(([label, value]) => <div className="metric-card" key={label}><small>{label}</small><strong>{value}</strong></div>)}</div>
      <section className="stats-panel"><div className="block-heading"><h3>Confusion matrix</h3></div><div className="matrix-grid"><span /> <strong>Predicted scam</strong><strong>Predicted legitimate</strong><b>Actual scam</b><span>{overall.tp}</span><span>{overall.fn}</span><b>Actual legitimate</b><span>{overall.fp}</span><span>{overall.tn}</span></div><p className="source-note">{result.note}</p></section>
      <div className="analytics-grid"><MetricTable title="By language" values={result.by_language} /><MetricTable title="By category" values={result.by_category} /></div>
    </>}
  </div>;
}

function MetricTable({ title, values }: { title: string; values: Record<string, any> }) {
  return <section className="stats-panel"><div className="block-heading"><h3>{title}</h3></div><div className="table-scroll"><table><thead><tr><th>Group</th><th>Cases</th><th>Accuracy</th><th>Precision</th><th>Recall</th><th>F1</th></tr></thead><tbody>{Object.entries(values).map(([name, value]) => <tr key={name}><td>{name}</td><td>{value.total}</td><td>{percent(value.accuracy)}</td><td>{percent(value.precision)}</td><td>{percent(value.recall)}</td><td>{percent(value.f1)}</td></tr>)}</tbody></table></div></section>;
}

function percent(value: number | null) { return value == null ? "n/a" : `${(value * 100).toFixed(0)}%`; }

function PageHeading({ eyebrow, title, subtitle }: { eyebrow: string; title: string; subtitle: string }) {
  return <div className="page-heading"><div><span className="eyebrow">{eyebrow}</span><h1>{title}</h1><p>{subtitle}</p></div></div>;
}

export default App;