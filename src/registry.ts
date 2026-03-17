import type { KeyResolver } from "./types.js";

interface CachedKey {
  key: Buffer;
  fetchedAt: number;
}

/**
 * Resolves provider Ed25519 public keys from the HIP registry with
 * in-memory caching and last-known-good fallback.
 */
export class RegistryKeyResolver implements KeyResolver {
  private readonly registryURL: string;
  private readonly ttlMs: number;
  private readonly cache = new Map<string, CachedKey>();
  private readonly fetchImpl: typeof fetch;

  constructor(
    registryURL: string,
    ttlMs: number = 24 * 60 * 60 * 1000,
    fetchImpl?: typeof fetch,
  ) {
    this.registryURL = registryURL;
    this.ttlMs = ttlMs;
    this.fetchImpl = fetchImpl ?? globalThis.fetch;
  }

  async resolvePublicKey(providerID: string): Promise<Buffer> {
    const cached = this.cache.get(providerID);
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

      this.cache.set(providerID, { key, fetchedAt: Date.now() });
      return key;
    } catch (err) {
      // Last-known-good fallback.
      if (cached) {
        return cached.key;
      }
      throw err;
    }
  }
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
