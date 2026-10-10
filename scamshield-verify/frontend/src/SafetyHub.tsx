import { useState } from "react";

type Tab = "emergency" | "tactics" | "guides" | "quiz";

const EMERGENCY = [
  { key: "otp", title: "I shared an OTP / PIN / password", steps: ["Call your bank's official number (on your card) and ask to block cards, UPI and net banking.", "Change passwords and UPI PIN from a safe device; log out of all sessions.", "Report at cybercrime.gov.in or call 1930 immediately.", "Never share another OTP, even with 'bank staff'."] },
  { key: "paid", title: "I already made a payment", steps: ["Call 1930 right away — fast reporting improves the chance of freezing funds.", "Tell your bank the transaction ID, amount, time and receiver.", "Keep screenshots, chats, numbers and payment receipts.", "File a complaint at cybercrime.gov.in."] },
  { key: "link", title: "I clicked a suspicious link", steps: ["Disconnect from the internet if an app or file was installed.", "Do not enter any details; close the page.", "Change passwords of accounts you may have used, starting with email and banking.", "Run a security scan and uninstall unknown apps; report at 1930 if money is involved."] },
];

const TACTICS: { name: string; re: RegExp; tip: string }[] = [
  { name: "Urgency", re: /urgent|immediately|within \d+ ?(hours?|minutes?)|last chance|expires? (today|soon)|act now/i, tip: "Scammers rush you so you can't think." },
  { name: "Impersonation", re: /bank|rbi|police|customs|cbi|income tax|courier|support team|kyc/i, tip: "Verify via the organisation's official website or number." },
  { name: "Fake prize", re: /lottery|winner|won\b|prize|reward|cashback|gift/i, tip: "Real prizes never ask for a fee." },
  { name: "Phishing link", re: /https?:\/\/|bit\.ly|tinyurl|click (here|the link)|\.(xyz|top|click)\b/i, tip: "Do not open links in unexpected messages." },
  { name: "Credential theft", re: /otp|pin\b|password|cvv|card number|aadhaar|pan\b/i, tip: "No genuine agent asks for OTP, PIN or CVV." },
  { name: "Payment pressure", re: /upi|pay (now|a fee)|transfer|processing fee|registration fee|send money|scan (the )?qr/i, tip: "Never pay to receive money." },
];

const GUIDES = [
  { t: "UPI scams", p: ["You never enter a PIN to receive money.", "Ignore 'collect request' you did not expect.", "Verify the payee name before paying."] },
  { t: "Banking & KYC fraud", p: ["Banks never ask for OTP/PIN/CVV by call or SMS.", "KYC updates are done in the official app or branch.", "Call the number printed on your card."] },
  { t: "Fake jobs", p: ["Genuine employers don't charge registration or training fees.", "Be wary of easy 'like and earn' tasks.", "Check the company on its official website."] },
  { t: "Delivery & courier scams", p: ["Don't pay 'redelivery' fees via unknown links.", "Track parcels only in the courier's official app.", "'Drugs found in your parcel' calls are a scam."] },
  { t: "Government impersonation", p: ["No agency arrests people over video call ('digital arrest').", "Police and CBI don't ask for money to 'settle' cases.", "Hang up and dial 1930 / 112."] },
];

const QUIZ = [
  { q: "SMS: 'Your account will be blocked today. Update KYC at http://kyc-bank-update.xyz'. What do you do?", o: ["Click and update quickly", "Ignore the link and check in your bank's official app", "Reply with your OTP"], a: 1, e: "Urgency + an unofficial domain are classic phishing signs." },
  { q: "A caller says you won ₹25 lakh but must pay a ₹5,000 'processing fee' by UPI.", o: ["Pay — it's small compared to the prize", "Ask for a discount", "Refuse; real prizes never need a fee"], a: 2, e: "Advance-fee requests are the core of prize scams." },
  { q: "'Officer' on video call says you're under 'digital arrest' and must transfer money to stay safe.", o: ["Comply and stay on the call", "Hang up and call 1930", "Share Aadhaar to prove identity"], a: 1, e: "No Indian agency conducts digital arrests." },
  { q: "A job offer asks ₹2,000 'registration' before the interview.", o: ["Pay, it seems legitimate", "Decline and verify the company independently", "Pay half"], a: 1, e: "Legitimate employers don't charge candidates." },
  { q: "You receive a UPI 'collect request' you didn't expect.", o: ["Decline it", "Approve — maybe it's a refund", "Enter PIN to check"], a: 0, e: "Refunds are credited without entering a PIN." },
];

export default function SafetyHub({ onAsk }: { onAsk: () => void }) {
  const [tab, setTab] = useState<Tab>("emergency");
  const [text, setText] = useState("");
  const [qi, setQi] = useState(0);
  const [pick, setPick] = useState<number | null>(null);
  const [score, setScore] = useState(0);
  const found = text.trim() ? TACTICS.filter((t) => t.re.test(text)) : [];
  const done = qi >= QUIZ.length;
  const q = QUIZ[qi];

  return <div className="page-stack">
    <div className="page-heading"><div><span className="eyebrow">SAFETY HUB</span><h1>Safety hub</h1><p>Emergency steps, scam tactics, safety guides and a practice quiz. Examples are fictional.</p></div></div>
    <div className="safety-tabs" role="tablist">
      {([["emergency", "🚨 Emergency help"], ["tactics", "🕵️ Tactic detector"], ["guides", "📚 Knowledge base"], ["quiz", "🎮 Spot the scam"]] as [Tab, string][]).map(([k, l]) => <button key={k} aria-pressed={tab === k} onClick={() => setTab(k)}>{l}</button>)}
    </div>
    {tab === "emergency" && <>
      <div className="safety-card safety-card--urgent"><h3>Lost money? Call 1930 now</h3><p>India's cyber-fraud helpline. Report at cybercrime.gov.in. Call 112 for immediate danger.</p><button className="safety-btn" onClick={onAsk}>Ask the assistant</button></div>
      {EMERGENCY.map((e) => <div className="safety-card" key={e.key}><h3>{e.title}</h3><ol>{e.steps.map((s) => <li key={s}>{s}</li>)}</ol></div>)}
    </>}
    {tab === "tactics" && <div className="safety-card"><h3>Paste a message to see scam tactics</h3><p>Runs in your browser only — nothing is sent or stored.</p>
      <textarea style={{ width: "100%", minHeight: 110, background: "#0b151c", color: "#e9f0f3", border: "1px solid var(--line-light)", borderRadius: 6, padding: 10, fontSize: 13 }} value={text} onChange={(e) => setText(e.target.value)} placeholder="Paste suspicious message…" aria-label="Message to check" />
      {text.trim() && (found.length ? <ul style={{ marginTop: 10 }}>{found.map((f) => <li key={f.name}><b>{f.name}</b> — {f.tip}</li>)}</ul> : <p>No common tactics detected. Stay cautious and verify the sender.</p>)}
    </div>}
    {tab === "guides" && GUIDES.map((g) => <div className="safety-card" key={g.t}><h3>{g.t}</h3><ul>{g.p.map((x) => <li key={x}>{x}</li>)}</ul></div>)}
    {tab === "quiz" && <div className="safety-card">
      {done ? <><h3>Score: {score}/{QUIZ.length}</h3><button className="safety-btn" onClick={() => { setQi(0); setScore(0); setPick(null); }}>Try again</button></> : <>
        <h3>Question {qi + 1} of {QUIZ.length}</h3><p>{q.q}</p>
        {q.o.map((o, i) => <button key={o} className={`quiz-opt ${pick !== null ? (i === q.a ? "quiz-opt--ok" : i === pick ? "quiz-opt--bad" : "") : ""}`} disabled={pick !== null} onClick={() => { setPick(i); if (i === q.a) setScore((s) => s + 1); }}>{o}</button>)}
        {pick !== null && <><p><b>{pick === q.a ? "Correct. " : "Not quite. "}</b>{q.e}</p><button className="safety-btn" onClick={() => { setQi(qi + 1); setPick(null); }}>Next</button></>}
      </>}
    </div>}
  </div>;
}
