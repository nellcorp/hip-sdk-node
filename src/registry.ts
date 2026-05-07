import { verifyJWS } from "./jws.js";
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
  private rootKeyDER?: Buffer;

  constructor(
    registryURL: string = DEFAULT_REGISTRY_URL,
    ttlMs: number = DEFAULT_REGISTRY_CACHE_TTL_MS,
    fetchImpl?: typeof fetch,
  ) {
    this.registryURL = registryURL;
    this.ttlMs = ttlMs;
    this.fetchImpl = fetchImpl ?? globalThis.fetch;
  }

  /** Pins the Ed25519 public key used to verify JWS-signed registry
   * responses. Accepts either a raw 32-byte key or a 44-byte SPKI-DER
   * encoding. When unset, the resolver accepts plain-JSON responses without
   * signature verification (intended for dev / local stubs). */
  setRegistryRootKey(key: Buffer): void {
    this.rootKeyDER = ed25519ToSPKI(key);
  }

  async resolvePublicKey(providerID: string): Promise<Buffer> {
    const cached = this.keyCache.get(providerID);
    if (cached && Date.now() - cached.fetchedAt < this.ttlMs) {
      return cached.key;
    }

    try {
      const url = `${this.registryURL}/providers/${providerID}/certificate`;
      const payload = await this.fetchAndUnwrap(url);
      const body = JSON.parse(payload.toString("utf-8")) as {
        public_key: string;
      };
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
      const payload = await this.fetchAndUnwrap(url);
      const entry = JSON.parse(payload.toString("utf-8")) as ProviderEntry;
      this.providerCache.set(providerID, { entry, fetchedAt: Date.now() });
      return entry;
    } catch (err) {
      if (cached) {
        return cached.entry;
      }
      throw err;
    }
  }

  /** Fetches the URL and returns the payload bytes ready for JSON.parse.
   * When the response Content-Type is application/jose AND a root key is
   * pinned, the JWS signature is verified before the payload is returned.
   * Otherwise the body is returned verbatim (legacy / dev path). */
  private async fetchAndUnwrap(url: string): Promise<Buffer> {
    const resp = await this.fetchImpl(url, {
      headers: { Accept: "application/jose, application/json;q=0.5" },
    });
    if (!resp.ok) {
      throw new Error(`registry returned ${resp.status}`);
    }
    const bodyBytes = Buffer.from(await resp.arrayBuffer());

    if (isJOSEContentType(resp.headers.get("content-type")) && this.rootKeyDER) {
      const token = bodyBytes.toString("utf-8").trim();
      try {
        return verifyJWS(this.rootKeyDER, token);
      } catch (err) {
        throw new Error(
          `registry JWS verify: ${err instanceof Error ? err.message : String(err)}`,
        );
      }
    }
    return bodyBytes;
  }
}

/** Reports whether the given Content-Type header indicates a JWS compact
 * serialization. Tolerates trailing parameters. */
function isJOSEContentType(ct: string | null): boolean {
  if (!ct) return false;
  const sep = ct.indexOf(";");
  const head = sep >= 0 ? ct.slice(0, sep) : ct;
  return head.trim().toLowerCase() === "application/jose";
}

/** SPKI DER prefix for Ed25519 public keys (RFC 8410). 12 bytes followed by
 * the 32-byte raw key. */
const ED25519_SPKI_PREFIX = Buffer.from([
  0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
]);

/** Converts a raw 32-byte Ed25519 public key into SPKI DER form (44 bytes).
 * Idempotent: a 44-byte SPKI input is returned verbatim. */
function ed25519ToSPKI(key: Buffer): Buffer {
  if (key.length === 32) {
    return Buffer.concat([ED25519_SPKI_PREFIX, key]);
  }
  if (key.length === 44) {
    return key;
  }
  throw new Error(
    `unexpected Ed25519 public key length ${key.length}; want 32 (raw) or 44 (SPKI)`,
  );
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
