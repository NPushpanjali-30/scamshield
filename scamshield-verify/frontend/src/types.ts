export type Language = "en" | "kn" | "hi";
export type InputLanguage = "auto" | Language;

export interface Analysis {
  id: number;
  score: number;
  level: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  classification: string;
  language: { language: string; confidence: number };
  input_language: InputLanguage;
  output_language: Language;
  translation_status: "original" | "translated" | "english_fallback";
  signals: { type: string; label: string; weight: number; evidence: string }[];
  urls: { url: string; host: string; reasons: string[] }[];
  impersonation: { claimed_org: string; result: string; hosts: string[]; reason: string }[];
  claims: { claim: string; status: string; reason: string; evidence: { title: string; org: string; url: string; text: string; retrieved_on: string }[]; by: string }[];
  actions: string[];
  disclaimer: string;
  entities: { phones: string[]; emails: string[]; upi_ids: string[]; orgs: string[]; requested_info: string[]; urls: string[] };
  highlights: { start: number; end: number; type: string }[];
  timeline: { step: number; tactic: string; label: string; quote: string }[];
  graph: { nodes: { id: string; label: string; kind: string }[]; edges: { from: string; to: string; label: string }[] };
  patterns: { name: string; similarity: number; matched: string[]; missing: string[] }[];
  pattern_note: string;
  ai_used: boolean;
}

export interface ChatMessage { role: "user" | "assistant"; text: string; language?: Language; sources?: { title: string; url: string }[]; retrievedAt?: string }