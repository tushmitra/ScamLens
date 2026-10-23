import { ScamLensApiError, type ScamLensResponse } from "../types/api";

const API_BASE_URL = (
  import.meta.env.VITE_SCAMLENS_API_URL || "http://127.0.0.1:8001"
).replace(/\/+$/, "");

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isNumberOrNull(value: unknown): value is number | null {
  return value === null || typeof value === "number";
}

function isStringArray(value: unknown): value is string[] {
  return Array.isArray(value) && value.every((item) => typeof item === "string");
}

function isScamLensResponse(value: unknown): value is ScamLensResponse {
  if (!isRecord(value)) return false;
  return (
    typeof value.project === "string" &&
    typeof value.version === "string" &&
    typeof value.overall_risk === "string" &&
    isStringArray(value.reasons) &&
    typeof value.warning === "string" &&
    isNumberOrNull(value.model_scam_score) &&
    isNumberOrNull(value.model_scam_score_percent) &&
    (value.advice === undefined || isStringArray(value.advice)) &&
    typeof value.model_score_is_calibrated === "boolean" &&
    isRecord(value.rule_analysis) &&
    isRecord(value.url_analysis)
  );
}

export async function analyzeMessage(
  message: string,
  signal?: AbortSignal,
): Promise<ScamLensResponse> {
  const cleanedMessage = message.trim();

  if (!cleanedMessage) {
    throw new ScamLensApiError("Enter a message before scanning.", "validation");
  }
  if (cleanedMessage.length > 10000) {
    throw new ScamLensApiError(
      "Messages must be 10,000 characters or fewer.",
      "validation",
    );
  }

  let response: Response;
  try {
    response = await fetch(`${API_BASE_URL}/check`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Accept: "application/json" },
      body: JSON.stringify({ message: cleanedMessage }),
      signal,
    });
  } catch (error) {
    if (error instanceof DOMException && error.name === "AbortError") throw error;
    throw new ScamLensApiError(
      `Could not connect to ScamLens at ${API_BASE_URL}. Start the backend and confirm VITE_SCAMLENS_API_URL points to the correct address (for example, http://127.0.0.1:8001).`,
      "network",
    );
  }

  if (!response.ok) {
    let message = response.status === 404
      ? `The API at ${API_BASE_URL} responded, but /check was not found. Confirm the backend route and API address.`
      : response.status === 422
        ? "The API rejected the request format (422). Confirm that the backend expects a JSON body with a 'message' field."
        : response.status >= 500
          ? `The ScamLens backend encountered an internal error (${response.status}). Check the backend terminal logs for the traceback.`
          : `ScamLens returned an error (${response.status}).`;
    try {
      const body: unknown = await response.json();
      if (isRecord(body) && typeof body.detail === "string") message = body.detail;
    } catch {
      // Retain the safe, generic HTTP error.
    }
    throw new ScamLensApiError(message, "http", response.status);
  }

  let data: unknown;
  try {
    data = await response.json();
  } catch {
    throw new ScamLensApiError("ScamLens returned invalid JSON.", "response");
  }

  if (!isScamLensResponse(data)) {
    throw new ScamLensApiError(
      "ScamLens returned an unexpected response shape. Check the API contract.",
      "response",
    );
  }

  return data;
}
