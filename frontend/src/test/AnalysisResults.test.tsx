import { render, screen } from "@testing-library/react";
import { expect, it } from "vitest";
import { AnalysisResults } from "../components/AnalysisResults";
import type { ScamLensResponse } from "../types/api";

const base: ScamLensResponse = {
  project: "ScamLens",
  version: "1.3.0",
  model_available: true,
  predicted_label: 3,
  category: "general",
  model_scam_score: 0.64,
  model_scam_score_percent: 64,
  model_score_is_calibrated: false,
  rule_analysis: { flags: ["credential_request"], reasons: ["Asks for a credential."], flag_count: 1 },
  url_analysis: { urls: [{ url: "https://bit.ly/x", flags: ["url_shortener"], reasons: ["Shortener."] }] },
  overall_risk: "Suspicious",
  reasons: ["Asks for a credential."],
  advice: ["Never share an OTP with anyone."],
  warning: "Experimental screening. No strong indicators does not mean safe.",
};

it("escalates suspicious messages with multiple strong warning signs", () => {
  const { container } = render(<AnalysisResults result={base} />);
  expect(screen.getByText("Likely scam — don't share your OTP")).toBeInTheDocument();
  expect(container.querySelector(".verdict-scam")).toBeInTheDocument();
  expect(screen.getByText("What to do now")).toBeInTheDocument();
  expect(screen.getByText("Why this result?")).toBeInTheDocument();
  expect(screen.getByText("Why this result?")).toBeInTheDocument();
  expect(screen.getByText("Never share an OTP with anyone.")).toBeInTheDocument();
});

it("uses red for scam-like API results", () => {
  const { container } = render(<AnalysisResults result={{ ...base, overall_risk: "High Risk", category: "phishing" }} />);
  expect(screen.getByText("This looks like a potential scam")).toBeInTheDocument();
  expect(container.querySelector(".verdict-scam")).toBeInTheDocument();
  expect(screen.getByText("What to do now")).toBeInTheDocument();
});

it("uses green when the API says no strong indicators were found", () => {
  const { container } = render(<AnalysisResults result={{ ...base, overall_risk: "No strong indicators found", category: null, reasons: [] }} />);
  expect(screen.getByText("No strong scam signs found")).toBeInTheDocument();
  expect(container.querySelector(".verdict-clear")).toBeInTheDocument();
  expect(screen.getByText(/not a guarantee that the message is safe/i)).toBeInTheDocument();
});

it("puts technical model information behind a disclosure", () => {
  render(<AnalysisResults result={{ ...base, model_available: false, model_scam_score: null, model_scam_score_percent: null }} />);
  expect(screen.getByText("View technical details")).toBeInTheDocument();
  expect(screen.queryByText(/Experimental model signal:/)).not.toBeInTheDocument();
});
