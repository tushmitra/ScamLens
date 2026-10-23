export type RuleAnalysis = {
  flags?: string[];
  reasons?: string[];
  flag_count?: number;
  disclaimer?: string;
  [key: string]: unknown;
};

export type UrlFinding = {
  url?: string;
  original_url?: string;
  flags?: string[];
  reasons?: string[];
  [key: string]: unknown;
};

export type UrlAnalysis = {
  urls?: UrlFinding[];
  [key: string]: unknown;
};

export type RiskDriver = {
  source: string; // "rule" | "url"
  id: string;
  strength: string; // "strong" | "supporting"
};

// Contract of POST /check (backend/app/schemas.py::CheckResponse).
// Model fields are null when the server has no text model loaded.
// Nested rule/URL fields stay defensive.
export type ScamLensResponse = {
  project: string;
  version: string;
  endpoint_version?: string;
  model_available?: boolean;
  predicted_label?: number | null;
  category?: string | null;
  model_scam_score: number | null;
  model_scam_score_percent: number | null;
  model_score_is_calibrated: boolean;
  rule_analysis: RuleAnalysis;
  url_analysis: UrlAnalysis;
  overall_risk: string;
  reasons: string[];
  drivers?: RiskDriver[];
  advice?: string[];
  warning: string;
};

export type ApiErrorCode = "validation" | "http" | "network" | "response";

export class ScamLensApiError extends Error {
  code: ApiErrorCode;
  status?: number;

  constructor(message: string, code: ApiErrorCode, status?: number) {
    super(message);
    this.name = "ScamLensApiError";
    this.code = code;
    this.status = status;
  }
}
