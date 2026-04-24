/** Request sent by platforms to verify a human identity. */
export interface VerifyRequest {
  subject_id: string;
  minimum_score?: number;
  purpose?: string;
  nonce?: string;
}

/** Request to exchange a signup code for a subject_id and verification. */
export interface ExchangeRequest {
  signup_code: string;
  nonce?: string;
}

/** Provider's signed response. */
export interface VerifyResponse {
  subject_id: string;
  status: string;
  score: number;
  score_state: string;
  score_components: ScoreComponents;
  certificate_fingerprint: string;
  issued_at: string;
  expires_at: string;
  nonce: string;
}

/** Options for startOAuth. */
export interface OAuthStartOptions {
  /** Provider domain, e.g. "humanidentity.io". */
  provider_domain?: string;
  /** Platform's canonical_platform_id. */
  client_id: string;
  /** Redirect URI registered on the platform. */
  redirect_uri: string;
  /** Opaque CSRF value echoed on redirect. */
  state?: string;
}

/** Result of startOAuth — give verifier to session storage, redirect user to authorize_url. */
export interface OAuthFlow {
  authorize_url: string;
  verifier: string;
}

/** Options for completeOAuth. */
export interface CompleteOAuthOptions {
  provider_domain?: string;
  client_id: string;
}

/** Token endpoint response. */
export interface OAuthTokenResponse {
  subject_id: string;
  status: string;
  score: number;
  score_state: string;
  attestation: string;
  issued_at: string;
  expires_at: string;
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
