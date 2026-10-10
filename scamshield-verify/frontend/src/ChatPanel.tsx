import { useEffect, useRef, useState, type FormEvent } from "react";
import { ArrowUp, Bot, PanelRightClose, PanelRightOpen, Trash2, Volume2 } from "lucide-react";
import { post } from "./api";
import type { Analysis, ChatMessage, Language } from "./types";

interface ChatReply { answer: string; by: string; sources: { title: string; url: string }[]; retrieved_at: string }

interface Props {
  analysis: Analysis | null;
  language: Language;
  userId: number;
  onRead: (text: string, language: Language) => void;
  collapsed: boolean;
  onToggle: () => void;
}

const SUGGESTIONS = [
  "I shared an OTP — what now?",
  "How do I report cyber fraud?",
  "Is this link safe to open?",
  "Spot a fake job offer",
];

function loadConversation(userId: number): ChatMessage[] {
  try { return JSON.parse(sessionStorage.getItem(`scamshield-chat:${userId}`) ?? "[]") as ChatMessage[]; }
  catch { return []; }
}

export default function ChatPanel({ analysis, language, userId, onRead, collapsed, onToggle }: Props) {
  const [messages, setMessages] = useState<ChatMessage[]>(() => loadConversation(userId));
  const [question, setQuestion] = useState("");
  const [pending, setPending] = useState(false);
  const [error, setError] = useState("");
  const bottom = useRef<HTMLDivElement>(null);

  useEffect(() => { sessionStorage.setItem(`scamshield-chat:${userId}`, JSON.stringify(messages)); }, [messages, userId]);
  useEffect(() => { bottom.current?.scrollIntoView({ behavior: "smooth" }); }, [messages, pending]);

  async function send(event: FormEvent | null, preset?: string) {
    event?.preventDefault();
    const text = (preset ?? question).trim();
    if (!text || pending) return;
    setQuestion("");
    setError("");
    setMessages((items) => [...items, { role: "user", text }]);
    setPending(true);
    try {
      const reply = await post<ChatReply>("/api/assistant", {
        question: text,
        analysis_id: analysis?.id ?? null,
        output_language: language,
      });
      setMessages((items) => [...items, { role: "assistant", text: reply.answer, language, sources: reply.sources, retrievedAt: reply.retrieved_at }]);
    } catch (issue) {
      setError(issue instanceof Error ? issue.message : "The assistant could not answer right now.");
    } finally { setPending(false); }
  }

  return (
    <aside className={`chat-panel ${collapsed ? "chat-panel--collapsed" : ""}`} aria-label="Cyber safety assistant">
      <div className="chat-head">
        {collapsed && <button className="icon-button chat-expand" title="Open assistant" aria-label="Open assistant" onClick={onToggle}><PanelRightOpen size={18} /></button>}
        {!collapsed && <><span className="assistant-mark"><Bot size={17} /></span><div><strong>Safety assistant</strong><small>{analysis ? "Analysis available" : "General guidance"}</small></div></>}
        {!collapsed && <button className="icon-button chat-clear" title="Clear conversation" aria-label="Clear conversation" onClick={() => setMessages([])}><Trash2 size={16} /></button>}
        {!collapsed && <button className="icon-button" title="Collapse assistant" aria-label="Collapse assistant" onClick={onToggle}><PanelRightClose size={18} /></button>}
      </div>
      {!collapsed && <>
        <div className="chat-thread" aria-live="polite">
          {messages.length === 0 && <div className="chat-welcome"><p>Ask about a message, reporting fraud, or staying safer online.</p><span>Answers use official sources where available.</span></div>}
          {messages.length === 0 && <div className="chat-suggest" aria-label="Suggested questions">{SUGGESTIONS.map((item) => <button type="button" key={item} disabled={pending} onClick={() => void send(null, item)}>{item}</button>)}</div>}
          {messages.map((message, index) => <article className={`chat-message chat-message--${message.role}`} key={`${index}-${message.text.slice(0, 10)}`}>
            <div className="chat-message-top"><b>{message.role === "user" ? "You" : "Assistant"}</b>{message.role === "assistant" && <button className="tiny-icon" title="Read response aloud" aria-label="Read response aloud" onClick={() => onRead(message.text, message.language ?? language)}><Volume2 size={14} /></button>}</div>
            <p>{message.text}</p>
            {!!message.sources?.length && <div className="chat-sources">{message.sources.map((source) => <a href={source.url} target="_blank" rel="noreferrer" key={source.url}>{source.title}</a>)}{message.retrievedAt && <small>Retrieved {new Date(message.retrievedAt).toLocaleString()}</small>}</div>}
          </article>)}
          {pending && <div className="chat-pending"><span className="spinner" /> Checking reliable guidance…</div>}
          <div ref={bottom} />
        </div>
        {error && <p className="inline-error" role="alert">{error}</p>}
        <form className="chat-compose" onSubmit={(event) => void send(event)}>
          <label className="sr-only" htmlFor="chat-question">Ask a cyber safety question</label>
          <textarea id="chat-question" rows={2} maxLength={500} value={question} onChange={(event) => setQuestion(event.target.value)} onKeyDown={(event) => { if (event.key === "Enter" && !event.shiftKey) void send(event); }} placeholder="Ask a question…" />
          <button className="send-button" type="submit" disabled={pending || !question.trim()} title="Send question" aria-label="Send question"><ArrowUp size={18} /></button>
        </form>
        <p className="chat-footnote">Not an emergency service. No reports are filed here.</p>
      </>}
    </aside>
  );
}