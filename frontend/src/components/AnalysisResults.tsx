import type { ScamLensResponse, UrlFinding } from "../types/api";

type Verdict = "scam" | "clear" | "caution";

function stringArray(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((item): item is string => typeof item === "string" && item.trim().length > 0) : [];
}

function getVerdict(result: ScamLensResponse): Verdict {
  const flags = stringArray(result.rule_analysis?.flags).map((flag) => flag.toLowerCase());
  const risk = String(result.overall_risk ?? "").toLowerCase().replaceAll("_", " ");
  const category = String(result.category ?? "").toLowerCase();
  const combined = `${risk} ${category}`;

  // Respect explicit high-risk API labels. Also escalate a suspicious result when
  // multiple high-signal rules occur together (e.g. credential request + threat).
  // This is a cautious user-facing heuristic, not proof that a message is fraudulent.
  if (/\b(scam|fraud|phishing|malicious|high risk|critical|dangerous|confirmed)\b/.test(combined)) return "scam";
  const asksForCredential = flags.includes("credential_request");
  const threatensOrPressures = flags.includes("threat_or_consequence") || flags.includes("urgent_action");
  const hasShortenedLink = flags.includes("url_shortener") || (Array.isArray(result.url_analysis?.urls) && result.url_analysis.urls.some((item) => stringArray(item.flags).includes("url_shortener")));
  if (risk.includes("suspicious") && ((asksForCredential && (threatensOrPressures || hasShortenedLink)) || (flags.includes("threat_or_consequence") && hasShortenedLink))) return "scam";
  if (/\b(low risk|benign|no strong indicators|no scam detected|not a scam|safe)\b/.test(risk)) return "clear";
  return "caution";
}

function labelForUrl(item: UrlFinding): string {
  if (typeof item.url === "string") return item.url;
  if (typeof item.original_url === "string") return item.original_url;
  return "Link checked";
}

function ShieldIcon({ verdict }: { verdict: Verdict }) {
  return <svg viewBox="0 0 48 48" fill="none" aria-hidden="true"><path d="M24 4 40 10v12c0 10.2-6.5 17.3-16 22C14.5 39.3 8 32.2 8 22V10L24 4Z" stroke="currentColor" strokeWidth="2.5" strokeLinejoin="round"/><path d={verdict === "scam" ? "M18 18l12 12M30 18 18 30" : verdict === "clear" ? "m16 24 5 5 11-12" : "M24 15v11m0 6h.01"} stroke="currentColor" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round"/></svg>;
}

export function AnalysisResults({ result }: { result: ScamLensResponse }) {
  const verdict = getVerdict(result);
  const reasons = stringArray(result.reasons);
  const flags = stringArray(result.rule_analysis?.flags);
  const ruleReasons = stringArray(result.rule_analysis?.reasons);
  const urls = Array.isArray(result.url_analysis?.urls) ? result.url_analysis.urls : [];
  const advice = stringArray(result.advice);
  const modelScore = typeof result.model_scam_score_percent === "number" ? result.model_scam_score_percent : null;

  const hasCredentialFlag = flags.includes("credential_request");
  const highRiskLabel = String(result.overall_risk ?? "").toLowerCase().replaceAll("_", " ").includes("high risk");
  const heading = verdict === "scam"
    ? highRiskLabel ? "This looks like a potential scam" : hasCredentialFlag ? "Likely scam — don't share your OTP" : "Likely scam — don't act on this message"
    : verdict === "clear" ? "No strong scam signs found" : "Pause and check before acting";
  const subheading = verdict === "scam"
    ? "Several warning signs match common scam patterns. Do not follow the message's instructions; verify independently."
    : verdict === "clear"
      ? "The scanner did not find strong scam indicators. This is not a guarantee that the message is safe."
      : "The result is not conclusive. Verify the sender independently before you click, reply, or share information.";

  return (
    <section className={`results-panel verdict-${verdict}`} aria-live="polite" aria-labelledby="results-title">
      <div className="verdict-hero">
        <div className="verdict-icon"><ShieldIcon verdict={verdict} /></div>
        <div className="verdict-copy">
          <p className="verdict-kicker">SCAMLENS RESULT</p>
          <h2 id="results-title">{heading}</h2>
          <p>{subheading}</p>
        </div>
        <span className="verdict-pill">{verdict === "scam" ? "High caution" : verdict === "clear" ? "Lower concern" : "Needs review"}</span>
      </div>

      {verdict === "scam" && <div className="next-step-banner"><strong>What to do now</strong><p>{hasCredentialFlag ? "Do not share your OTP, PIN, password, or bank details. Do not click the link. Verify the claim through your bank’s official app or the number printed on your card." : "Do not click links, send money, or share sensitive information. Verify the sender through the organisation’s official app or contact details you find independently."}</p></div>}
      {verdict === "clear" && <div className="next-step-banner"><strong>Still stay alert</strong><p>Never share passwords or OTPs. If the message asks for money or urgent action, verify it through an official channel.</p></div>}

      <div className="result-section">
        <h3>Why this result?</h3>
        {reasons.length > 0 ? <ul className="plain-list">{reasons.slice(0, 4).map((reason, i) => <li key={`${i}-${reason}`}>{reason}</li>)}</ul> : <p className="section-muted">The API did not return a specific explanation for this result.</p>}
      </div>

      {advice.length > 0 && <div className="result-section"><h3>Your next steps</h3><ul className="plain-list">{advice.slice(0, 4).map((item, i) => <li key={`${i}-${item}`}>{item}</li>)}</ul></div>}

      <details className="technical-details">
        <summary>View technical details</summary>
        <div className="technical-content">
          {typeof result.overall_risk === "string" && <p><strong>API risk label:</strong> {result.overall_risk}</p>}
          {modelScore !== null && <p><strong>Model scam score (not a probability):</strong> {modelScore}%{result.model_score_is_calibrated ? " (calibrated)" : " (not calibrated; not a probability)"}</p>}
          {result.model_available === false || (result.model_scam_score === null && modelScore === null) ? <p className="section-muted">The text-classification model does not appear to be loaded. This result may rely on rule and link checks only.</p> : null}
          {(flags.length > 0 || ruleReasons.length > 0) && <div><h4>Rule indicators</h4><ul className="plain-list">{flags.map(flag => <li key={flag}>{flag.replaceAll("_", " ")}</li>)}{ruleReasons.slice(0, 5).map((reason, i) => <li key={`rule-${i}`}>{reason}</li>)}</ul></div>}
          {urls.length > 0 && <div><h4>Links found</h4>{urls.slice(0, 5).map((item, i) => <article className="url-item" key={`${labelForUrl(item)}-${i}`}><p className="url-text">{labelForUrl(item)}</p>{stringArray(item.flags).length > 0 && <p>Signals: {stringArray(item.flags).map(flag => flag.replaceAll("_", " ")).join(", ")}</p>}{stringArray(item.reasons).slice(0, 3).map((reason, j) => <p key={j}>{reason}</p>)}</article>)}</div>}
          {typeof result.warning === "string" && <p className="section-muted">{result.warning}</p>}
        </div>
      </details>
      <p className="result-disclaimer">Automated screening can make mistakes. When in doubt, do not act on the message until you verify it.</p>
    </section>
  );
}

