import type { KeyResolver, ProviderEntry, ProviderResolver } from "./types.js";

/** The canonical HIP registry URL. SDK consumers SHOULD NOT override this in
 * production; the URL is part of the protocol's bootstrap trust anchor
 * (PROTOCOL.md §10.8). Override only for development or staging. */
export const DEFAULT_REGISTRY_URL = "https://registry.humanidentity.io";

/** Default cache TTL for registry-fetched data. */
export const DEFAULT_REGISTRY_CACHE_TTL_MS = 24 * 60 * 60 * 1000;

interface CachedKey {
  key: Buffer;
  fetchedAt: number;
}

interface CachedProvider {
  entry: ProviderEntry;
  fetchedAt: number;
}

/**
 * Resolves provider Ed25519 public keys AND full HIP/1.1 provider entries
 * from the HIP registry with in-memory caching and last-known-good fallback.
 * Implements both KeyResolver and ProviderResolver.
 */
export class RegistryKeyResolver implements KeyResolver, ProviderResolver {
  private readonly registryURL: string;
  private readonly ttlMs: number;
  private readonly keyCache = new Map<string, CachedKey>();
  private readonly providerCache = new Map<string, CachedProvider>();
  private readonly fetchImpl: typeof fetch;

  constructor(
    registryURL: string = DEFAULT_REGISTRY_URL,
    ttlMs: number = DEFAULT_REGISTRY_CACHE_TTL_MS,
    fetchImpl?: typeof fetch,
  ) {
    this.registryURL = registryURL;
    this.ttlMs = ttlMs;
    this.fetchImpl = fetchImpl ?? globalThis.fetch;
  }

  async resolvePublicKey(providerID: string): Promise<Buffer> {
    const cached = this.keyCache.get(providerID);
    if (cached && Date.now() - cached.fetchedAt < this.ttlMs) {
      return cached.key;
    }

    try {
      const url = `${this.registryURL}/providers/${providerID}/certificate`;
      const resp = await this.fetchImpl(url, {
        headers: { Accept: "application/json" },
      });

      if (!resp.ok) {
        throw new Error(`registry returned ${resp.status}`);
      }

      const body = (await resp.json()) as { public_key: string };
      const key = parsePEMPublicKey(body.public_key);

      this.keyCache.set(providerID, { key, fetchedAt: Date.now() });
      return key;
    } catch (err) {
      // Last-known-good fallback.
      if (cached) {
        return cached.key;
      }
      throw err;
    }
  }

  async resolveProvider(providerID: string): Promise<ProviderEntry> {
    const cached = this.providerCache.get(providerID);
    if (cached && Date.now() - cached.fetchedAt < this.ttlMs) {
      return cached.entry;
    }

    try {
      const url = `${this.registryURL}/providers/${providerID}`;
      const resp = await this.fetchImpl(url, {
        headers: { Accept: "application/json" },
      });
      if (!resp.ok) {
        throw new Error(`registry returned ${resp.status}`);
      }
      const entry = (await resp.json()) as ProviderEntry;
      this.providerCache.set(providerID, { entry, fetchedAt: Date.now() });
      return entry;
    } catch (err) {
      if (cached) {
        return cached.entry;
      }
      throw err;
    }
  }
}

/** Returns the resolved verify endpoint URL for a HIP/1.1 entry, falling back
 * to the legacy well_known_url + "/verify" if endpoints are not populated. */
export function entryVerifyURL(entry: ProviderEntry): string {
  if (entry.endpoints?.verify) return entry.endpoints.verify;
  if (entry.well_known_url) {
    return entry.well_known_url.replace(/\/+$/, "") + "/verify";
  }
  return "";
}

/** Returns the resolved exchange endpoint URL with HIP/1.0 fallback. */
export function entryExchangeURL(entry: ProviderEntry): string {
  if (entry.endpoints?.exchange) return entry.endpoints.exchange;
  if (entry.well_known_url) {
    return entry.well_known_url.replace(/\/+$/, "") + "/exchange";
  }
  return "";
}

/** Returns the OAuth authorize URL (no HIP/1.0 fallback). */
export function entryOAuthAuthorizeURL(entry: ProviderEntry): string {
  return entry.endpoints?.oauth_authorize ?? "";
}

/** Returns the OAuth token URL (no HIP/1.0 fallback). */
export function entryOAuthTokenURL(entry: ProviderEntry): string {
  return entry.endpoints?.oauth_token ?? "";
}

/**
 * Parses a PEM-encoded Ed25519 public key and returns the raw DER bytes
 * (SPKI format, suitable for Node's crypto.createVerify).
 */
export function parsePEMPublicKey(pemData: string): Buffer {
  const lines = pemData
    .split("\n")
    .filter((l) => !l.startsWith("-----") && l.trim() !== "");
  const der = Buffer.from(lines.join(""), "base64");
  return der;
}
