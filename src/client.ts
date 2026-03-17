import { randomBytes, randomUUID } from "node:crypto";
import { verifyJWS } from "./jws.js";
import type {
  HIPClientOptions,
  KeyResolver,
  VerifyRequest,
  VerifyResponse,
} from "./types.js";

/**
 * HIP SDK client for verifying human identities from platforms.
 *
 * The provider URL is auto-discovered from the subject ID:
 * `abc123@provider.example.com` → `https://provider.example.com/.well-known/hip/verify`
 *
 * ```ts
 * const client = new HIPClient("api-key", "jwt-secret", {
 *   keyResolver: new RegistryKeyResolver("https://registry.hip.dev"),
 * });
 * const resp = await client.verify({
 *   subject_id: "abc123@provider.example.com",
 * });
 * ```
 */
export class HIPClient {
  private readonly apiKey: string;
  private readonly jwtSecret: string;
  private readonly fetchImpl: typeof fetch;
  private readonly keyResolver?: KeyResolver;
  private readonly timeoutMs: number;
  private readonly providerURL?: string;

  constructor(
    apiKey: string,
    jwtSecret: string,
    options: HIPClientOptions = {},
  ) {
    this.apiKey = apiKey;
    this.jwtSecret = jwtSecret;
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
          Authorization: `Bearer ${this.jwtSecret}`,
          "X-API-Key": this.apiKey,
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
}

/**
 * Extracts the provider domain from a subject ID.
 * e.g. "abc123@provider.example.com" → "provider.example.com"
 */
function extractProviderFromSubject(subjectID: string): string {
  const idx = subjectID.lastIndexOf("@");
  if (idx < 0 || idx === subjectID.length - 1) {
    throw new Error(
      `hip: invalid subject_id format, expected {id}@{provider}: "${subjectID}"`,
    );
  }
  return subjectID.slice(idx + 1);
}
