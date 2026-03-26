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
 * ```ts
 * const client = new HIPClient("api-key", "jwt-secret", {
 *   keyResolver: new RegistryKeyResolver("https://registry.hip.dev"),
 * });
 * const resp = await client.verify("https://provider.example.com/.well-known/identity", {
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
  }

  /**
   * Sends a verification request to the provider and verifies the response.
   * Auto-generates nonce and request_id if not provided.
   */
  async verify(
    providerURL: string,
    req: VerifyRequest,
  ): Promise<VerifyResponse> {
    if (!req.subject_id) {
      throw new Error("hip: subject_id is required");
    }

    // Auto-generate nonce and request ID.
    const nonce = req.nonce ?? randomBytes(32).toString("base64url");
    const requestID = req.request_id ?? randomUUID();

    const body: VerifyRequest = { ...req, nonce, request_id: requestID };

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.timeoutMs);

    try {
      const resp = await this.fetchImpl(`${providerURL}/verify`, {
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
        const providerID = extractProviderID(providerURL);
        const pubKey = await this.keyResolver.resolvePublicKey(providerID);
        verifyJWS(pubKey, verifyResp.signature);
      }

      return verifyResp;
    } finally {
      clearTimeout(timeout);
    }
  }
}

/** Extracts hostname from a provider URL. */
function extractProviderID(url: string): string {
  try {
    return new URL(url).hostname;
  } catch {
    // Fallback: strip scheme and path manually.
    let u = url;
    const schemeIdx = u.indexOf("://");
    if (schemeIdx >= 0) u = u.slice(schemeIdx + 3);
    const pathIdx = u.indexOf("/");
    if (pathIdx >= 0) u = u.slice(0, pathIdx);
    const portIdx = u.indexOf(":");
    if (portIdx >= 0) u = u.slice(0, portIdx);
    return u;
  }
}
