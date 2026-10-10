import { useState, type FormEvent } from "react";
import { ArrowRight, LoaderCircle, LockKeyhole, Mail, Shield, UserRound } from "lucide-react";
import { post } from "./api";

export interface AuthUser {
  id: number;
  name: string;
  email: string;
}

export type AuthMode = "login" | "register";

interface Props {
  mode: AuthMode;
  initialError?: string;
  onModeChange: (mode: AuthMode) => void;
  onAuthenticated: (user: AuthUser, token: string, message: string) => void;
}

export default function AuthPage({ mode, initialError = "", onModeChange, onAuthenticated }: Props) {
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");

  async function submit(event: FormEvent) {
    event.preventDefault();
    setError("");
    setNotice("");

    const normalizedEmail = email.trim();
    if (mode === "register" && !name.trim()) { setError("Enter your name."); return; }
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(normalizedEmail)) { setError("Enter a valid email address."); return; }
    if (!password) { setError("Enter your password."); return; }
    if (mode === "register" && password.length < 8) { setError("Use a password with at least 8 characters."); return; }
    if (mode === "register" && password !== confirmPassword) { setError("Passwords do not match."); return; }

    setBusy(true);
    try {
      const result = mode === "register"
        ? await post<{ user: AuthUser; token: string }>("/api/auth/register", {
          name: name.trim(), email: normalizedEmail, password, confirm_password: confirmPassword,
        })
        : await post<{ user: AuthUser; token: string }>("/api/auth/login", { email: normalizedEmail, password });
      if (!result.token) throw new Error("The server did not return a session token. Please restart the backend and try again.");
      setNotice(mode === "register" ? "Account created. Opening your ScamShield workspace…" : "Signed in. Opening your ScamShield workspace…");
      onAuthenticated(result.user, result.token, mode === "register" ? "Account created successfully." : `Welcome back, ${result.user.name}.`);
    } catch (issue) {
      setError(issue instanceof Error ? issue.message : "Authentication failed. Please try again.");
    } finally {
      setBusy(false);
    }
  }

  const isRegister = mode === "register";
  const visibleError = error || initialError;

  return <main className="auth-shell">
    <section className="auth-card" aria-labelledby="auth-title">
      <div className="brand-lockup auth-brand"><div className="brand-mark"><Shield size={21} /></div><div><strong>ScamShield</strong><span>VERIFY / INDIA</span></div></div>
      <span className="eyebrow">SECURE INVESTIGATION WORKSPACE</span>
      <h1 id="auth-title">{isRegister ? "Create your account" : "Welcome back"}</h1>
      <p className="auth-intro">{isRegister ? "Register to keep your case history private to your account." : "Sign in to continue to ScamShield Verify."}</p>
      <form className="auth-form" onSubmit={(event) => void submit(event)} noValidate>
        {isRegister && <label className="auth-field"><span>Name</span><span className="auth-input"><UserRound size={16} /><input autoComplete="name" maxLength={80} value={name} onChange={(event) => setName(event.target.value)} placeholder="Your name" required /></span></label>}
        <label className="auth-field"><span>Email</span><span className="auth-input"><Mail size={16} /><input type="email" autoComplete="email" maxLength={254} value={email} onChange={(event) => setEmail(event.target.value)} placeholder="you@example.com" required /></span></label>
        <label className="auth-field"><span>Password</span><span className="auth-input"><LockKeyhole size={16} /><input type="password" autoComplete={isRegister ? "new-password" : "current-password"} maxLength={128} value={password} onChange={(event) => setPassword(event.target.value)} placeholder={isRegister ? "At least 8 characters" : "Your password"} required /></span></label>
        {isRegister && <label className="auth-field"><span>Confirm password</span><span className="auth-input"><LockKeyhole size={16} /><input type="password" autoComplete="new-password" maxLength={128} value={confirmPassword} onChange={(event) => setConfirmPassword(event.target.value)} placeholder="Enter the password again" required /></span></label>}
        {visibleError && <div className="notice notice--error" role="alert">{visibleError}</div>}
        {notice && <div className="notice notice--success" role="status">{notice}</div>}
        <button className="button button--primary auth-submit" type="submit" disabled={busy}>{busy ? <><LoaderCircle className="spin" size={16} /> Working…</> : <>{isRegister ? "Create account" : "Sign in"} <ArrowRight size={16} /></>}</button>
      </form>
      <p className="auth-switch">{isRegister ? "Already have an account?" : "New to ScamShield?"}{" "}
        <button type="button" onClick={() => { setError(""); setNotice(""); setPassword(""); setConfirmPassword(""); onModeChange(isRegister ? "login" : "register"); }}>{isRegister ? "Sign in" : "Create an account"}</button>
      </p>
      <p className="auth-footnote">Passwords are protected with one-way hashing. ScamShield Verify is an assistive service, not an official government portal.</p>
    </section>
  </main>;
}
