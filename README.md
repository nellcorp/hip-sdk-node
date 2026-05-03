# @nellcorp/hip-sdk

Node.js/TypeScript SDK for platforms integrating with the [Human Identity Protocol](https://github.com/nellcorp/hip).

## Install

```bash
npm install @nellcorp/hip-sdk
```

## Usage

```typescript
import { HIPClient, RegistryKeyResolver } from "@nellcorp/hip-sdk";

// Key resolver fetches provider public keys from the registry
// with 24h caching and last-known-good fallback.
const resolver = new RegistryKeyResolver("https://registry.humanidentity.io");

const client = new HIPClient("hip_sk_your_api_key", {
  keyResolver: resolver,
});

// The provider URL is auto-discovered from the subject ID
// (abc123@provider.example.com → provider.example.com).
const resp = await client.verify({
  subject_id: "abc123@provider.example.com",
  purpose: "account_creation",
  minimum_score: 60,
});

// purpose and minimum_score are optional.
// minimum_score is informational only; enforce your threshold using resp.score.

console.log(`Status: ${resp.status}, Score: ${resp.score}`);
```

## Features

- **TypeScript-first** — full type definitions included
- **Automatic JWS signature verification** using Ed25519 public keys from the registry
- **Nonce generation** — cryptographically random nonce auto-generated per request
- **Request ID generation** — UUID v4 auto-generated if not provided
- **Registry key resolver** with TTL-based caching and last-known-good fallback
- **Nonce verification** — ensures response nonce matches request
- **Auto-discovery** — provider URL derived from subject ID (`{id}@{provider}`)
- **Zero external dependencies** — uses only Node.js built-in `crypto` module

## Custom Key Resolver

Implement the `KeyResolver` interface:

```typescript
interface KeyResolver {
  resolvePublicKey(providerID: string): Promise<Buffer>;
}
```
