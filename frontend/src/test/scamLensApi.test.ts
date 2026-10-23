import { afterEach, describe, expect, it, vi } from "vitest";
import { analyzeMessage } from "../services/scamLensApi";

const validResponse = {
  project: "ScamLens",
  version: "1.2.0",
  predicted_label: 1,
  category: "scam",
  model_scam_score: 0.8,
  model_scam_score_percent: 80,
  model_score_is_calibrated: false,
  rule_analysis: { flags: ["credential_request"], reasons: ["Requests an OTP"] },
  url_analysis: { urls: [{ url: "https://bit.ly/example", flags: ["url_shortener"], reasons: ["Shortened URL"] }] },
  overall_risk: "Suspicious",
  reasons: ["Requests an OTP"],
  warning: "Experimental screening. No strong indicators does not mean safe.",
};

afterEach(() => vi.unstubAllGlobals());

describe("analyzeMessage", () => {
  it("posts the message to /check and returns a valid response", async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify(validResponse), { status: 200 }));
    vi.stubGlobal("fetch", fetchMock);
    const result = await analyzeMessage("  hello  ");
    expect(fetchMock).toHaveBeenCalledWith(expect.stringMatching(/\/check$/), expect.objectContaining({
      method: "POST",
      body: JSON.stringify({ message: "hello" }),
    }));
    expect(result.overall_risk).toBe("Suspicious");
  });

  it("rejects blank messages before making a request", async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    await expect(analyzeMessage("  ")).rejects.toThrow("Enter a message");
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("rejects an unexpected response shape", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response(JSON.stringify({ overall_risk: "Suspicious" }), { status: 200 })));
    await expect(analyzeMessage("hello")).rejects.toThrow("unexpected response shape");
  });

  it("accepts a response from a server with no text model (null model fields)", async () => {
    const noModel = {
      ...validResponse,
      model_available: false,
      predicted_label: null,
      category: null,
      model_scam_score: null,
      model_scam_score_percent: null,
      advice: ["Verify through the official app."],
    };
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response(JSON.stringify(noModel), { status: 200 })));
    const result = await analyzeMessage("hello");
    expect(result.model_scam_score).toBeNull();
    expect(result.advice).toEqual(["Verify through the official app."]);
  });

  it("rejects a non-numeric model score", async () => {
    const bad = { ...validResponse, model_scam_score: "high" };
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response(JSON.stringify(bad), { status: 200 })));
    await expect(analyzeMessage("hello")).rejects.toThrow("unexpected response shape");
  });
});
