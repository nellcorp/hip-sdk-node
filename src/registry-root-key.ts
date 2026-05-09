import { createPublicKey } from "node:crypto";

/**
 * Canonical registry root public key per PROTOCOL.md §10.8. SDK releases
 * ship with this pinned; rotation will be announced 90 days in advance with
 * overlap windows so older SDK versions continue to verify against either
 * the old or new key.
 */
export const DEFAULT_REGISTRY_ROOT_KEY_PEM = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAjLot1q9kopqfW3KAZyPcErPNwnoDRp56VPslKSNHqnA=
-----END PUBLIC KEY-----
`;

/**
 * DefaultRegistryRootKey is the raw 32-byte Ed25519 public key for the
 * canonical registry, derived from {@link DEFAULT_REGISTRY_ROOT_KEY_PEM}.
 * HIPClient pins this on construction unless options.registryRootKey
 * overrides it (dev / federation testing per PROTOCOL.md §10.8).
 *
 * The SPKI DER encoding of an Ed25519 key is a fixed 12-byte AlgorithmIdentifier
 * prefix followed by the 32-byte raw public key. We slice off the prefix to
 * match the wire format expected by RegistryKeyResolver.setRegistryRootKey.
 */
export const DefaultRegistryRootKey: Buffer = createPublicKey(
  DEFAULT_REGISTRY_ROOT_KEY_PEM,
)
  .export({ type: "spki", format: "der" })
  .subarray(12);
