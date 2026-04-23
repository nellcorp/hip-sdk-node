import { randomBytes, randomUUID } from "node:crypto";
import { verifyJWS } from "./jws.js";
import type {
  ExchangeRequest,
  HIPClientOptions,
  KeyResolver,
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
   * platform. Sent as a Bearer token on every request; the provider derives
   * the platform from the key.
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
   * was set in the constructor options.
   * Auto-generates nonce and request_id if not provided.
   */
  async verify(req: VerifyRequest): Promise<VerifyResponse> {
    if (!req.subject_id) {
      throw new Error("hip: subject_id is required");
    }

    const providerID = extractProviderFromSubject(req.subject_id);
    const verifyURL = this.providerURL
      ? `${this.providerURL}/verify`
      : `https://${providerID}/.well-known/hip/verify`;

    // Auto-generate nonce and request ID.
    const nonce = req.nonce ?? randomBytes(32).toString("base64url");
    const requestID = req.request_id ?? randomUUID();

    const body: VerifyRequest = { ...req, nonce, request_id: requestID };

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

      const verifyResp = (await resp.json()) as VerifyResponse;

      // Verify nonce.
      if (verifyResp.nonce !== nonce) {
        throw new Error(
          `hip: nonce mismatch: sent "${nonce}", got "${verifyResp.nonce}"`,
        );
      }

      // Verify JWS signature if key resolver is configured.
      if (this.keyResolver && verifyResp.signature) {
        const pubKey = await this.keyResolver.resolvePublicKey(providerID);
        verifyJWS(pubKey, verifyResp.signature);
      }

      return verifyResp;
    } finally {
      clearTimeout(timeout);
    }
  }

  /**
   * Exchanges a signup code for a subject_id and verification response.
   * Requires providerURL to be set in constructor options.
   * Auto-generates nonce and request_id if not provided.
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

    // Auto-generate nonce and request ID.
    const nonce = req.nonce ?? randomBytes(32).toString("base64url");
    const requestID = req.request_id ?? randomUUID();

    const body: ExchangeRequest = { ...req, nonce, request_id: requestID };

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

      const exchangeResp = (await resp.json()) as VerifyResponse;

      // Verify nonce.
      if (exchangeResp.nonce !== nonce) {
        throw new Error(
          `hip: nonce mismatch: sent "${nonce}", got "${exchangeResp.nonce}"`,
        );
      }

      // Verify JWS signature if key resolver is configured.
      // For exchange, we need to extract provider from the providerURL.
      if (this.keyResolver && exchangeResp.signature) {
        const providerID = extractProviderFromURL(this.providerURL);
        const pubKey = await this.keyResolver.resolvePublicKey(providerID);
        verifyJWS(pubKey, exchangeResp.signature);
      }

      return exchangeResp;
    } finally {
      clearTimeout(timeout);
    }
  }
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
