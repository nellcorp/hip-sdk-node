import { verify } from "node:crypto";

/**
 * Verifies a JWS Compact Serialization token with an Ed25519 public key.
 * Returns the decoded payload on success, throws on failure.
 *
 * @param publicKeyDER - SPKI-encoded Ed25519 public key (DER bytes)
 * @param token - JWS compact serialization (header.payload.signature)
 */
export function verifyJWS(publicKeyDER: Buffer, token: string): Buffer {
  const parts = token.split(".");
  if (parts.length !== 3) {
    throw new Error(`malformed JWS: expected 3 parts, got ${parts.length}`);
  }

  const signingInput = Buffer.from(`${parts[0]}.${parts[1]}`);
  const signature = Buffer.from(parts[2], "base64url");

  const isValid = verify(
    null, // Ed25519 doesn't use a digest algorithm
    signingInput,
    { key: publicKeyDER, format: "der", type: "spki" },
    signature,
  );

  if (!isValid) {
    throw new Error("invalid signature");
  }

  return Buffer.from(parts[1], "base64url");
}
