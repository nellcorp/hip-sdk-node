import { createHash, randomBytes } from "node:crypto";
import { verifyJWS } from "./jws.js";
import type {
  CompleteOAuthOptions,
  ExchangeRequest,
  HIPClientOptions,
  KeyResolver,
  OAuthFlow,
  OAuthStartOptions,
  OAuthTokenResponse,
  VerifyRequest,
  VerifyResponse,
} from "./types.js";

/**
 * HIP SDK client for verifying human identities from platforms.
 *
 * The provider URL is auto-discovered from the subject ID:
 * `xK7mN2pR9sT4vW6yB@id.humanidentity.io` → `https://humanidentity.io/.well-known/hip/verify`
 *
 * ```ts
 * const client = new HIPClient("hip_sk_...", {
 *   keyResolver: new RegistryKeyResolver("https://registry.hip.dev"),
 * });
 * const resp = await client.verify({
 *   subject_id: "xK7mN2pR9sT4vW6yB@id.humanidentity.io",
 * });
 * ```
 */
export class HIPClient {
  private readonly apiKey: string;
  private readonly fetchImpl: typeof fetch;
  private readonly keyResolver?: KeyResolver;
  private readonly timeoutMs: number;
  private readonly providerURL?: string;

  /**
   * @param apiKey The `hip_sk_…` secret issued by the provider for this
   * platform. Sent as a Bearer token on `/verify` and `/exchange`. Not used on
   * `/oauth/token` — PKCE + `client_id` are the platform auth there.
   */
  constructor(apiKey: string, options: HIPClientOptions = {}) {
    this.apiKey = apiKey;
    this.fetchImpl = options.fetch ?? globalThis.fetch;
    this.keyResolver = options.keyResolver;
    this.timeoutMs = options.timeoutMs ?? 10_000;
    this.providerURL = options.providerURL;
  }

  /**
   * Sends a verification request and verifies the response.
   * The provider URL is derived from the subject_id unless providerURL
   * was set in the constructor options. Auto-generates nonce if not provided.
   */
  async verify(req: VerifyRequest): Promise<VerifyResponse> {
    if (!req.subject_id) {
      throw new Error("hip: subject_id is required");
    }

    const providerID = extractProviderFromSubject(req.subject_id);
    const verifyURL = this.providerURL
      ? `${this.providerURL}/verify`
      : `https://${providerID}/.well-known/hip/verify`;

    const nonce = req.nonce ?? randomBytes(32).toString("base64url");
    const body: VerifyRequest = { ...req, nonce };

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.timeoutMs);

    try {
      const resp = await this.fetchImpl(verifyURL, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${this.apiKey}`,
        },
        body: JSON.stringify(body),
        signal: controller.signal,
      });

      if (!resp.ok) {
        const text = await resp.text();
        throw new Error(`hip: provider returned ${resp.status}: ${text}`);
      }

      // Response is a JWS compact serialization (Content-Type: application/jose).
      const jws = (await resp.text()).trim();
      const payload = await this.decodeAndVerifyJWS(jws, providerID);
      const verifyResp = JSON.parse(payload.toString("utf8")) as VerifyResponse;

      if (verifyResp.nonce !== nonce) {
        throw new Error(
          `hip: nonce mismatch: sent "${nonce}", got "${verifyResp.nonce}"`,
        );
      }
      return verifyResp;
    } finally {
      clearTimeout(timeout);
    }
  }

  /**
   * Exchanges a signup code for a subject_id and verification response.
   * Requires providerURL to be set in constructor options.
   * Auto-generates nonce if not provided.
   */
  async exchangeSignupCode(req: ExchangeRequest): Promise<VerifyResponse> {
    if (!req.signup_code) {
      throw new Error("hip: signup_code is required");
    }
    if (!this.providerURL) {
      throw new Error(
        "hip: providerURL must be set for signup code exchange",
      );
    }

    const exchangeURL = `${this.providerURL}/exchange`;
    const nonce = req.nonce ?? randomBytes(32).toString("base64url");
    const body: ExchangeRequest = { ...req, nonce };

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.timeoutMs);

    try {
      const resp = await this.fetchImpl(exchangeURL, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${this.apiKey}`,
        },
        body: JSON.stringify(body),
        signal: controller.signal,
      });

      if (!resp.ok) {
        const text = await resp.text();
        throw new Error(`hip: provider returned ${resp.status}: ${text}`);
      }

      const jws = (await resp.text()).trim();
      const providerID = extractProviderFromURL(this.providerURL);
      const payload = await this.decodeAndVerifyJWS(jws, providerID);
      const exchangeResp = JSON.parse(
        payload.toString("utf8"),
      ) as VerifyResponse;

      if (exchangeResp.nonce !== nonce) {
        throw new Error(
          `hip: nonce mismatch: sent "${nonce}", got "${exchangeResp.nonce}"`,
        );
      }
      return exchangeResp;
    } finally {
      clearTimeout(timeout);
    }
  }

  /**
   * Generates a PKCE verifier/challenge pair and returns the authorize URL.
   * Retain `flow.verifier` in the user's session until `completeOAuth`.
   *
   * ```ts
   * const flow = client.startOAuth({
   *   provider_domain: "humanidentity.io",
   *   client_id: "my-platform.example.com",
   *   redirect_uri: "https://my-platform.example.com/oauth/callback",
   *   state: "csrf-token",
   * });
   * // save flow.verifier in session
   * // redirect user to flow.authorize_url
   * ```
   */
  startOAuth(opts: OAuthStartOptions): OAuthFlow {
    if (!opts.client_id) {
      throw new Error("hip: client_id is required");
    }
    if (!opts.redirect_uri) {
      throw new Error("hip: redirect_uri is required");
    }
    const base = this.resolveOAuthBase(opts.provider_domain);

    const verifier = generateCodeVerifier();
    const challenge = codeChallenge(verifier);

    const params = new URLSearchParams({
      client_id: opts.client_id,
      redirect_uri: opts.redirect_uri,
      response_type: "code",
      code_challenge: challenge,
      code_challenge_method: "S256",
    });
    if (opts.state) params.set("state", opts.state);

    return {
      authorize_url: `${base}/oauth/authorize?${params.toString()}`,
      verifier,
    };
  }

  /**
   * Exchanges an authorization code + PKCE verifier for a verification
   * attestation. No Authorization header is sent — /oauth/token authenticates
   * the platform via client_id + code_verifier.
   */
  async completeOAuth(
    code: string,
    verifier: string,
    opts: CompleteOAuthOptions,
  ): Promise<OAuthTokenResponse> {
    if (!code) throw new Error("hip: code is required");
    if (!verifier) throw new Error("hip: verifier is required");
    if (!opts.client_id) throw new Error("hip: client_id is required");

    const base = this.resolveOAuthBase(opts.provider_domain);
    const url = `${base}/oauth/token`;

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.timeoutMs);

    try {
      const resp = await this.fetchImpl(url, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          // No Authorization header — PKCE + client_id are the auth.
        },
        body: JSON.stringify({
          grant_type: "authorization_code",
          code,
          client_id: opts.client_id,
          code_verifier: verifier,
        }),
        signal: controller.signal,
      });

      if (!resp.ok) {
        const text = await resp.text();
        throw new Error(`hip: provider returned ${resp.status}: ${text}`);
      }

      return (await resp.json()) as OAuthTokenResponse;
    } finally {
      clearTimeout(timeout);
    }
  }

  private resolveOAuthBase(providerDomain?: string): string {
    let base = this.providerURL ?? "";
    if (base) {
      base = base.replace(/\/+$/, "").replace(/\/\.well-known\/hip$/, "");
      return base;
    }
    if (!providerDomain) {
      throw new Error(
        "hip: provider_domain is required (or configure the client with providerURL)",
      );
    }
    return `https://${providerDomain}`;
  }

  private async decodeAndVerifyJWS(
    jws: string,
    providerID: string,
  ): Promise<Buffer> {
    const parts = jws.split(".");
    if (parts.length !== 3) {
      throw new Error(
        `hip: malformed JWS: expected 3 parts, got ${parts.length}`,
      );
    }
    if (this.keyResolver) {
      const pubKey = await this.keyResolver.resolvePublicKey(providerID);
      return verifyJWS(pubKey, jws);
    }
    return Buffer.from(parts[1]!, "base64url");
  }
}

/**
 * Generates a PKCE code_verifier: 96 random bytes → 128 base64url chars.
 */
export function generateCodeVerifier(): string {
  return randomBytes(96).toString("base64url");
}

/**
 * Computes the PKCE code_challenge for a given verifier:
 * base64url(SHA-256(verifier)).
 */
export function codeChallenge(verifier: string): string {
  return createHash("sha256").update(verifier).digest("base64url");
}

/**
 * Extracts the provider domain from a subject ID.
 * Expected format: {derived_id}@id.{provider_domain}
 * e.g. "xK7mN2pR9sT4vW6yB@id.humanidentity.io" → "humanidentity.io"
 * The "id." prefix is a namespace marker preventing collision with real emails.
 */
function extractProviderFromSubject(subjectID: string): string {
  const idx = subjectID.lastIndexOf("@");
  if (idx < 0 || idx === subjectID.length - 1) {
    throw new Error(`hip: invalid subject_id format: "${subjectID}"`);
  }
  const host = subjectID.slice(idx + 1);
  if (!host.startsWith("id.")) {
    throw new Error(`hip: missing id. prefix: "${subjectID}"`);
  }
  return host.slice(3);
}

/**
 * Extracts the provider domain from a provider URL.
 * e.g. "https://humanidentity.io/.well-known/hip" → "humanidentity.io"
 */
function extractProviderFromURL(providerURL: string): string {
  try {
    const url = new URL(providerURL);
    return url.hostname;
  } catch {
    throw new Error(`hip: invalid provider URL: "${providerURL}"`);
  }
}
