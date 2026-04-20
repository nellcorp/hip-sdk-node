/** Request sent by platforms to verify a human identity. */
export interface VerifyRequest {
  subject_id: string;
  request_id?: string;
  minimum_score?: number;
  purpose?: string;
  nonce?: string;
}

/** Request to exchange a signup code for a subject_id and verification. */
export interface ExchangeRequest {
  signup_code: string;
  request_id?: string;
  nonce?: string;
}

/** Provider's signed response. */
export interface VerifyResponse {
  request_id: string;
  subject_id: string;
  status: string;
  score: number;
  score_state: string;
  score_components: ScoreComponents;
  certificate_fingerprint: string;
  issued_at: string;
  expires_at: string;
  nonce: string;
  signature?: string;
}

export interface ScoreComponents {
  verification_age_days: number;
  recent_events: string[];
  active_flags: string[];
}

/** Resolves a provider's Ed25519 public key (raw 32-byte buffer). */
export interface KeyResolver {
  resolvePublicKey(providerID: string): Promise<Buffer>;
}

export interface HIPClientOptions {
  /** Custom fetch implementation (defaults to global fetch). */
  fetch?: typeof fetch;
  /** Key resolver for JWS signature verification. */
  keyResolver?: KeyResolver;
  /** Request timeout in milliseconds (default: 10000). */
  timeoutMs?: number;
  /** Override provider URL (for testing or non-standard deployments). Skips auto-discovery from subject_id. */
  providerURL?: string;
}
