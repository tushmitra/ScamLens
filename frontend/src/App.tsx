import { useEffect, useRef, useState } from "react";
import { AnalysisResults } from "./components/AnalysisResults";
import { analyzeMessage } from "./services/scamLensApi";
import { ScamLensApiError, type ScamLensResponse } from "./types/api";

const SAMPLE_MESSAGE = "Your bank account will be blocked. Share your OTP now: https://bit.ly/example.";

function BrandMark({ small = false }: { small?: boolean }) {
  return <span className={`brand-mark${small ? " brand-mark-small" : ""}`} aria-hidden="true"><svg viewBox="0 0 40 40" fill="none"><rect width="40" height="40" rx="13" fill="currentColor"/><path d="M20 7.5 30 11v8.2c0 6.9-4.1 11.8-10 15.2-5.9-3.4-10-8.3-10-15.2V11l10-3.5Z" stroke="#F8F5EF" strokeWidth="1.7"/><path d="m15.5 20 3 3 6-6.5" stroke="#F8F5EF" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/></svg></span>;
}

function ScanIcon() {
  return <svg viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="M8 3H5a2 2 0 0 0-2 2v3m13-5h3a2 2 0 0 1 2 2v3M3 16v3a2 2 0 0 0 2 2h3m13-5v3a2 2 0 0 1-2 2h-3M6 12h12m-9-4v8m6-8v8" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round"/></svg>;
}

export default function App() {
  const [message, setMessage] = useState(SAMPLE_MESSAGE);
  const [result, setResult] = useState<ScamLensResponse | null>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [theme, setTheme] = useState<"dark" | "light">(() => {
    try {
      const saved = window.localStorage.getItem("scamlens-theme");
      return saved === "light" ? "light" : "dark";
    } catch { return "dark"; }
  });
  const controllerRef = useRef<AbortController | null>(null);
  const requestIdRef = useRef(0);

  useEffect(() => () => controllerRef.current?.abort(), []);

  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    try { window.localStorage.setItem("scamlens-theme", theme); } catch { /* storage can be disabled */ }
  }, [theme]);

  // A restrained cursor follower for mouse/trackpad users; native cursor stays visible.
  useEffect(() => {
    // Some test environments and embedded browsers do not implement matchMedia.
    const matchMedia = typeof window.matchMedia === "function"
      ? window.matchMedia.bind(window)
      : (_query: string) => ({ matches: false, media: _query, onchange: null, addListener: () => {}, removeListener: () => {}, addEventListener: () => {}, removeEventListener: () => {}, dispatchEvent: () => false } as MediaQueryList);
    const finePointer = matchMedia("(hover: hover) and (pointer: fine)");
    const reducedMotion = matchMedia("(prefers-reduced-motion: reduce)");
    const dot = document.querySelector<HTMLElement>(".pointer-dot");
    const ring = document.querySelector<HTMLElement>(".pointer-ring");
    if (!finePointer.matches || reducedMotion.matches || !dot || !ring) return;

    let frame = 0;
    let x = -100, y = -100;
    const move = (event: PointerEvent) => {
      x = event.clientX;
      y = event.clientY;
      if (frame) cancelAnimationFrame(frame);
      frame = requestAnimationFrame(() => {
        dot.style.transform = `translate3d(${x}px, ${y}px, 0) translate(-50%, -50%)`;
        ring.style.transform = `translate3d(${x}px, ${y}px, 0) translate(-50%, -50%)`;
      });
    };
    const over = (event: PointerEvent) => {
      const target = event.target;
      if (target instanceof Element && target.closest("a, button, textarea, input, label, summary")) {
        ring.classList.add("is-interactive");
      }
    };
    const out = (event: PointerEvent) => {
      const target = event.target;
      if (target instanceof Element && target.closest("a, button, textarea, input, label, summary")) {
        ring.classList.remove("is-interactive");
      }
    };
    const leave = () => { dot.classList.add("is-hidden"); ring.classList.add("is-hidden"); };
    const enter = () => { dot.classList.remove("is-hidden"); ring.classList.remove("is-hidden"); };
    window.addEventListener("pointermove", move, { passive: true });
    document.addEventListener("pointerover", over);
    document.addEventListener("pointerout", out);
    document.addEventListener("pointerleave", leave);
    document.addEventListener("pointerenter", enter);
    return () => {
      window.removeEventListener("pointermove", move);
      document.removeEventListener("pointerover", over);
      document.removeEventListener("pointerout", out);
      document.removeEventListener("pointerleave", leave);
      document.removeEventListener("pointerenter", enter);
      if (frame) cancelAnimationFrame(frame);
    };
  }, []);

  // Keep the thin reading-progress line in sync with page scroll.
  useEffect(() => {
    const progress = document.querySelector<HTMLElement>(".scroll-progress span");
    if (!progress) return;
    let frame = 0;
    const update = () => {
      if (frame) cancelAnimationFrame(frame);
      frame = requestAnimationFrame(() => {
        const max = document.documentElement.scrollHeight - window.innerHeight;
        const amount = max > 0 ? Math.min(100, Math.max(0, window.scrollY / max * 100)) : 0;
        progress.style.width = `${amount}%`;
      });
    };
    update();
    window.addEventListener("scroll", update, { passive: true });
    window.addEventListener("resize", update);
    return () => {
      window.removeEventListener("scroll", update);
      window.removeEventListener("resize", update);
      if (frame) cancelAnimationFrame(frame);
    };
  }, []);

  useEffect(() => {
    const items = document.querySelectorAll<HTMLElement>(".reveal");
    if (!("IntersectionObserver" in window)) {
      items.forEach(item => item.classList.add("is-visible"));
      return;
    }
    const observer = new IntersectionObserver(entries => {
      entries.forEach(entry => {
        if (entry.isIntersecting) {
          entry.target.classList.add("is-visible");
          observer.unobserve(entry.target);
        }
      });
    }, { threshold: 0.12, rootMargin: "0px 0px -36px 0px" });
    items.forEach(item => observer.observe(item));
    return () => observer.disconnect();
  }, []);

  async function handleAnalyze() {
    controllerRef.current?.abort();
    const controller = new AbortController();
    controllerRef.current = controller;
    const requestId = ++requestIdRef.current;
    setResult(null);
    setError("");
    if (!message.trim()) { setError("Paste a message before starting the scan."); return; }
    if (message.trim().length > 10000) { setError("The message must be 10,000 characters or fewer."); return; }
    setLoading(true);
    try {
      const data = await analyzeMessage(message, controller.signal);
      if (requestId === requestIdRef.current) setResult(data);
    } catch (caught) {
      if (caught instanceof DOMException && caught.name === "AbortError") return;
      if (requestId === requestIdRef.current) setError(caught instanceof ScamLensApiError || caught instanceof Error ? caught.message : "The scan could not be completed. Please try again.");
    } finally {
      if (requestId === requestIdRef.current) setLoading(false);
    }
  }

  function updateMessage(value: string) {
    controllerRef.current?.abort();
    requestIdRef.current += 1;
    setLoading(false);
    setMessage(value);
    setResult(null);
    setError("");
  }

  return <div className="app-shell">
    <div className="scroll-progress" aria-hidden="true"><span /></div>
    <span className="pointer-ring" aria-hidden="true" />
    <span className="pointer-dot" aria-hidden="true" />
    <header className="topbar" id="top">
      <a className="brand" href="#top" aria-label="ScamLens home"><BrandMark /><span>ScamLens</span></a>
      <nav aria-label="Main navigation"><a href="#scanner">Scanner</a><a href="#how-it-works">How it works</a><a href="#connect">Connect</a></nav>
      <button type="button" className="theme-toggle" onClick={() => setTheme(current => current === "dark" ? "light" : "dark")} aria-label={`Switch to ${theme === "dark" ? "light" : "dark"} mode`} aria-pressed={theme === "dark"}>
        <span aria-hidden="true">{theme === "dark" ? "☀" : "☾"}</span>{theme === "dark" ? "Light" : "Dark"}
      </button>
    </header>

    <main className="page-content">
      <section className="hero reveal">
        <p className="eyebrow">MESSAGE SAFETY, MADE SIMPLE</p>
        <h1>Not sure about a message?<br /><span>Check before you act.</span></h1>
        <p className="hero-description">Paste a text, email, or chat message. Get a clear result, understand the warning signs, and learn what to do next.</p>
      </section>

      <section className="scanner-spread reveal" id="scanner" aria-label="Message scanner and analysis">
        <div className="scanner-card">
          <div className="card-heading"><div><span className="card-icon"><ScanIcon /></span><div><h2>Message scanner</h2><p>Paste the message exactly as you received it.</p></div></div><span className="ready-label"><span /> Ready to scan</span></div>
          <label htmlFor="message-input">Message content</label>
          <textarea id="message-input" value={message} onChange={event => updateMessage(event.target.value)} maxLength={10000} rows={6} placeholder="Paste an SMS, email, or chat message…" />
          <div className="input-meta"><span>{message.length.toLocaleString()} <span className="muted">/ 10,000 characters</span></span><button type="button" className="text-button" onClick={() => updateMessage("")}>Clear text <span aria-hidden="true">×</span></button></div>
          <div className="action-row"><button type="button" className="sample-button" onClick={() => updateMessage(SAMPLE_MESSAGE)}>Use sample message</button><button type="button" className="primary-button" onClick={handleAnalyze} disabled={loading || !message.trim()}>{loading ? <><span className="button-spinner" /> Analyzing…</> : <><ScanIcon /> Analyze message <span aria-hidden="true">↗</span></>}</button></div>
          <p className="privacy-note"><span aria-hidden="true">◇</span> Your text is sent to your configured ScamLens API only when you scan. Links are not opened.</p>
        </div>
        <section className="analysis-card-shell" aria-labelledby="results-title">
          <div className="analysis-card-head"><h2>Analysis</h2><p>{result ? "Here’s what ScamLens found in your message." : "Your results will appear here after you scan a message."}</p></div>
          <div className="analysis-scroll" key={result ? "results" : loading ? "loading" : error ? "error" : "empty"}>
            {error && <section className="error-panel" role="alert"><span className="alert-mark">!</span><div><h3>We couldn’t complete the scan</h3><p>{error}</p><button type="button" className="secondary-button" onClick={handleAnalyze} disabled={loading}>Try again ↗</button></div></section>}
            {loading && <section className="status-panel" role="status" aria-live="polite"><span className="button-spinner" /><div><h3>Looking for warning signs</h3><p>Waiting for a response from the configured ScamLens API…</p></div></section>}
            {!result && !loading && !error && <section className="empty-result"><div className="empty-mark"><BrandMark small /></div><div><p className="eyebrow">YOUR RESULTS WILL APPEAR HERE</p><h3>Insight, not assumptions.</h3><p>Paste a message and select <strong>Analyze message</strong>. We’ll show a clear assessment, explain the warning signs, and suggest practical next steps.</p></div></section>}
            {result && <div className="result-enter"><AnalysisResults result={result} /></div>}
          </div>
        </section>
      </section>

      <section className="how-section reveal" id="how-it-works">
        <div className="how-heading">
          <div>
            <p className="eyebrow">A CLEARER WAY TO CHECK</p>
            <h2>How ScamLens works.</h2>
          </div>
        </div>
        <div className="how-grid">
          <article className="how-card"><div className="how-card-top"><span className="how-number">01</span><span className="how-symbol" aria-hidden="true">↳</span></div><h3>Bring the message</h3><p>Paste the original SMS, email, or chat text. Keep the sender’s wording and any link exactly as received so the context is not lost.</p><span className="how-caption">YOUR INPUT</span></article>
          <article className="how-card"><div className="how-card-top"><span className="how-number">02</span><span className="how-symbol" aria-hidden="true">⌕</span></div><h3>Look for warning signs</h3><p>The message is screened for suspicious requests, urgent pressure, threats, and other patterns worth checking. A signal is a clue—not proof on its own.</p><span className="how-caption">TEXT REVIEW</span></article>
          <article className="how-card"><div className="how-card-top"><span className="how-number">03</span><span className="how-symbol" aria-hidden="true">↗</span></div><h3>Notice link clues</h3><p>If the message contains a URL, available link details can add context, such as whether it appears shortened. ScamLens does not open links for you.</p><span className="how-caption">LINK AWARENESS</span></article>
          <article className="how-card"><div className="how-card-top"><span className="how-number">04</span><span className="how-symbol" aria-hidden="true">◌</span></div><h3>Build a risk picture</h3><p>Text and available link clues are considered together. This gives you a single screening assessment instead of asking you to interpret each warning sign alone.</p><span className="how-caption">RISK REVIEW</span></article>
          <article className="how-card"><div className="how-card-top"><span className="how-number">05</span><span className="how-symbol" aria-hidden="true">＝</span></div><h3>Get a plain result</h3><p>The result explains the level of concern and highlights the reasons that mattered. Technical details stay secondary so the main guidance is easy to understand.</p><span className="how-caption">CLEAR LANGUAGE</span></article>
          <article className="how-card"><div className="how-card-top"><span className="how-number">06</span><span className="how-symbol" aria-hidden="true">↗</span></div><h3>Choose your next step</h3><p>Use the advice to slow down, avoid risky links, and verify claims through an official app or a phone number you find yourself. Never share passwords or one-time codes.</p><span className="how-caption">SAFER ACTION</span></article>
        </div>
      </section>

      <section className="connect-section reveal" id="connect" aria-labelledby="connect-heading">
        <div className="connect-heading">
          <div>
            <p className="eyebrow">SAY HELLO</p>
            <h2 id="connect-heading">Connect with me.</h2>
          </div>
          <p className="connect-intro">ScamLens is built by Tushar Mitra. Find me around the web or explore the code and projects.</p>
        </div>
        <div className="connect-links">
          <a className="connect-link" href="https://github.com/tushmitra" target="_blank" rel="noopener noreferrer" aria-label="Visit Tushar Mitra on GitHub (opens in a new tab)">
            <span className="connect-link-label">CODE & PROJECTS</span><span className="connect-link-title">GitHub</span><span className="connect-link-url">github.com/tushmitra</span><span className="connect-arrow" aria-hidden="true">↗</span>
          </a>
          <a className="connect-link" href="https://www.linkedin.com/in/tusharmitra01/" target="_blank" rel="noopener noreferrer" aria-label="Connect with Tushar Mitra on LinkedIn (opens in a new tab)">
            <span className="connect-link-label">PROFESSIONAL NETWORK</span><span className="connect-link-title">LinkedIn</span><span className="connect-link-url">linkedin.com/in/tusharmitra01</span><span className="connect-arrow" aria-hidden="true">↗</span>
          </a>
        </div>
      </section>

      <footer>
        <a className="footer-brand" href="#top"><BrandMark small /> ScamLens</a>
        <span className="footer-credit">Created by <strong>Tushar Mitra</strong> · Screening guidance, not a guarantee</span>
        <a className="footer-back" href="#top">Back to top ↑</a>
        <small className="copyright">© {new Date().getFullYear()} Tushar Mitra. All rights reserved.</small>
      </footer>
    </main>
  </div>;
}
