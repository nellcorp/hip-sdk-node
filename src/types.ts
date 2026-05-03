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

/** Resolves a provider's full HIP/1.1 registry entry. */
export interface ProviderResolver {
  resolveProvider(providerID: string): Promise<ProviderEntry>;
}

/** HIP/1.1 protocol surfaces (PROTOCOL.md §10.2). */
export interface ProviderEndpoints {
  verify: string;
  exchange: string;
  oauth_authorize: string;
  oauth_token: string;
}

/** End-user-facing surfaces. */
export interface ProviderApps {
  identity?: string;
  provider?: string;
}

/** Provider registry entry. HIP/1.1+ readers MUST resolve protocol endpoint
 * URLs from `endpoints` instead of string-concatenating against `id`. */
export interface ProviderEntry {
  id: string;
  display_name?: string;
  domain?: string;
  tier?: string;
  status?: string;
  public_key?: string;
  certificate_fingerprint?: string;
  endpoints: ProviderEndpoints;
  apps?: ProviderApps;
  peer_registries?: string[];
  /** @deprecated Removed in HIP/1.3. Use endpoints. */
  well_known_url?: string;
  entry_signature?: string;
}

export interface HIPClientOptions {
  /** Custom fetch implementation (defaults to global fetch). */
  fetch?: typeof fetch;
  /** Key resolver for JWS signature verification. If the resolver also
   * implements ProviderResolver, registry-driven service discovery is
   * enabled. */
  keyResolver?: KeyResolver;
  /** Request timeout in milliseconds (default: 10000). */
  timeoutMs?: number;
  /** Override provider URL (for testing or non-standard deployments).
   * Bypasses HIP/1.1 service discovery entirely. */
  providerURL?: string;
  /** Priority-ordered list of registry URLs (v2 federation hook). When unset
   * the SDK uses [DEFAULT_REGISTRY_URL]. Ignored when keyResolver is supplied. */
  registries?: string[];
}
