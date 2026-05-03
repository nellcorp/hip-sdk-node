import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { generateKeyPairSync, sign } from "node:crypto";
import {
  HIPClient,
  codeChallenge,
  generateCodeVerifier,
} from "./client.js";
import type { KeyResolver, VerifyRequest, VerifyResponse } from "./types.js";

function generateEd25519KeyPair() {
  return generateKeyPairSync("ed25519", {
    publicKeyEncoding: { type: "spki", format: "der" },
    privateKeyEncoding: { type: "pkcs8", format: "der" },
  });
}

// signJWSCompact returns the JWS compact serialization (header.payload.signature).
// This is what the HIP provider returns in the response body on /verify +
// /exchange (Content-Type: application/jose).
function signJWSCompact(privateDER: Buffer, payload: Buffer): string {
  const header = Buffer.from('{"alg":"EdDSA","kid":"test-key"}').toString("base64url");
  const encodedPayload = payload.toString("base64url");
  const signingInput = `${header}.${encodedPayload}`;
  const signature = sign(null, Buffer.from(signingInput), {
    key: privateDER,
    format: "der",
    type: "pkcs8",
  });
  return `${signingInput}.${signature.toString("base64url")}`;
}

class StaticKeyResolver implements KeyResolver {
  constructor(private key: Buffer) {}
  async resolvePublicKey(): Promise<Buffer> {
    return this.key;
  }
}

function startTestServer(
  handler: (req: IncomingMessage, res: ServerResponse) => void,
): Promise<{ url: string; close: () => void }> {
  return new Promise((resolve) => {
    const srv = createServer(handler);
    srv.listen(0, "127.0.0.1", () => {
      const addr = srv.address();
      if (typeof addr === "object" && addr) {
        resolve({
          url: `http://127.0.0.1:${addr.port}`,
          close: () => srv.close(),
        });
      }
    });
  });
}

function readBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolve) => {
    let data = "";
    req.on("data", (chunk: Buffer) => (data += chunk.toString()));
    req.on("end", () => resolve(data));
  });
}

describe("HIPClient.verify", () => {
  it("verify success (JWS response)", async () => {
    const { publicKey, privateKey } = generateEd25519KeyPair();

    const srv = await startTestServer(async (req, res) => {
      const body = JSON.parse(await readBody(req)) as VerifyRequest;
      const resp: VerifyResponse = {
        subject_id: body.subject_id,
        status: "active",
        score: 95,
        score_state: "stable",
        score_components: { verification_age_days: 30, recent_events: [], active_flags: [] },
        certificate_fingerprint: "sha256:abc",
        issued_at: new Date().toISOString(),
        expires_at: new Date(Date.now() + 86400000).toISOString(),
        nonce: body.nonce!,
      };
      const jws = signJWSCompact(
        privateKey as unknown as Buffer,
        Buffer.from(JSON.stringify(resp)),
      );
      res.writeHead(200, { "Content-Type": "application/jose" });
      res.end(jws);
    });

    try {
      const client = new HIPClient("key", {
        providerURL: srv.url,
        keyResolver: new StaticKeyResolver(publicKey as unknown as Buffer),
      });
      const resp = await client.verify({
        subject_id: "xK7mN2pR9sT4vW6yB@id.provider.example.com",
        purpose: "account_creation",
      });
      assert.equal(resp.status, "active");
      assert.equal(resp.score, 95);
    } finally {
      srv.close();
    }
  });

  it("rejects nonce mismatch", async () => {
    const { privateKey } = generateEd25519KeyPair();
    const srv = await startTestServer(async (_req, res) => {
      const resp = { status: "active", nonce: "wrong", subject_id: "x" };
      const jws = signJWSCompact(
        privateKey as unknown as Buffer,
        Buffer.from(JSON.stringify(resp)),
      );
      res.writeHead(200, { "Content-Type": "application/jose" });
      res.end(jws);
    });

    try {
      const client = new HIPClient("key", { providerURL: srv.url });
      await assert.rejects(
        () =>
          client.verify({
            subject_id: "xK7mN2pR9sT4vW6yB@id.provider.example.com",
            nonce: "my-nonce",
          }),
        /nonce mismatch/,
      );
    } finally {
      srv.close();
    }
  });

  it("rejects missing subject_id", async () => {
    const client = new HIPClient("key");
    await assert.rejects(
      () => client.verify({ subject_id: "" }),
      /subject_id is required/,
    );
  });

  it("rejects invalid subject_id format", async () => {
    const client = new HIPClient("key");
    await assert.rejects(
      () => client.verify({ subject_id: "no-at-sign" }),
      /invalid subject_id format/,
    );
  });

  it("rejects subject_id missing id. prefix", async () => {
    const client = new HIPClient("key");
    await assert.rejects(
      () => client.verify({ subject_id: "abc123@provider.example.com" }),
      /missing id\. prefix/,
    );
  });

  it("auto-generates nonce", async () => {
    let receivedBody: VerifyRequest | null = null;
    const { privateKey } = generateEd25519KeyPair();
    const srv = await startTestServer(async (req, res) => {
      receivedBody = JSON.parse(await readBody(req)) as VerifyRequest;
      const resp = {
        subject_id: receivedBody!.subject_id,
        status: "active",
        nonce: receivedBody!.nonce,
      };
      const jws = signJWSCompact(
        privateKey as unknown as Buffer,
        Buffer.from(JSON.stringify(resp)),
      );
      res.writeHead(200, { "Content-Type": "application/jose" });
      res.end(jws);
    });

    try {
      const client = new HIPClient("key", { providerURL: srv.url });
      await client.verify({
        subject_id: "xK7mN2pR9sT4vW6yB@id.provider.example.com",
      });
      assert.ok(receivedBody!.nonce, "expected auto-generated nonce");
      assert.equal(
        (receivedBody as unknown as { request_id?: string }).request_id,
        undefined,
        "request_id must NOT be sent",
      );
    } finally {
      srv.close();
    }
  });

  it("handles provider error", async () => {
    const srv = await startTestServer(async (_req, res) => {
      res.writeHead(500, { "Content-Type": "application/json" });
      res.end('{"error":"internal"}');
    });

    try {
      const client = new HIPClient("key", { providerURL: srv.url });
      await assert.rejects(
        () =>
          client.verify({
            subject_id: "xK7mN2pR9sT4vW6yB@id.provider.example.com",
          }),
        /500/,
      );
    } finally {
      srv.close();
    }
  });
});

describe("PKCE helpers", () => {
  it("generateCodeVerifier produces 128 base64url chars", () => {
    const v = generateCodeVerifier();
    assert.equal(v.length, 128);
    assert.match(v, /^[A-Za-z0-9_-]+$/);
  });

  it("codeChallenge matches RFC 7636 Appendix B test vector", () => {
    const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    const expected = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
    assert.equal(codeChallenge(verifier), expected);
  });
});

describe("HIPClient.startOAuth", () => {
  it("builds an authorize URL with PKCE", async () => {
    // registries: [] disables the auto-created RegistryKeyResolver so the test
    // does not try to hit the canonical registry over the network.
    const client = new HIPClient("key", { registries: [] });
    const flow = await client.startOAuth({
      provider_domain: "provider.example.com",
      client_id: "my-platform",
      redirect_uri: "https://my-platform.example.com/oauth/callback",
      state: "csrf123",
    });
    assert.equal(flow.verifier.length, 128);
    const url = new URL(flow.authorize_url);
    assert.equal(url.origin, "https://provider.example.com");
    assert.equal(url.pathname, "/oauth/authorize");
    assert.equal(url.searchParams.get("client_id"), "my-platform");
    assert.equal(url.searchParams.get("code_challenge_method"), "S256");
    assert.equal(url.searchParams.get("state"), "csrf123");
    assert.ok(url.searchParams.get("code_challenge"));
  });

  it("rejects missing client_id", async () => {
    const client = new HIPClient("key", { registries: [] });
    await assert.rejects(
      () =>
        client.startOAuth({
          redirect_uri: "https://x/cb",
        } as unknown as Parameters<typeof client.startOAuth>[0]),
      /client_id/,
    );
  });

  it("uses registry-discovered authorize URL when provided", async () => {
    const fakeResolver = {
      resolvePublicKey: async () => Buffer.alloc(32),
      resolveProvider: async () => ({
        id: "provider.example.com",
        endpoints: {
          verify: "https://api.example.com/.well-known/hip/verify",
          exchange: "https://api.example.com/.well-known/hip/exchange",
          oauth_authorize: "https://identity.example.com/oauth/authorize",
          oauth_token: "https://api.example.com/oauth/token",
        },
      }),
    };
    const client = new HIPClient("key", { keyResolver: fakeResolver });
    const flow = await client.startOAuth({
      provider_domain: "provider.example.com",
      client_id: "my-platform",
      redirect_uri: "https://my-platform.example.com/cb",
    });
    const url = new URL(flow.authorize_url);
    assert.equal(url.origin, "https://identity.example.com");
    assert.equal(url.pathname, "/oauth/authorize");
  });
});

describe("HIPClient.completeOAuth", () => {
  it("posts without Authorization header and returns token response", async () => {
    let gotAuth: string | undefined;
    let gotBody: Record<string, string> | undefined;
    const srv = await startTestServer(async (req, res) => {
      gotAuth = req.headers.authorization;
      gotBody = JSON.parse(await readBody(req));
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(
        JSON.stringify({
          subject_id: "sid",
          status: "active",
          score: 95,
          score_state: "stable",
          attestation: "a.b.c",
          issued_at: "2026-04-24T00:00:00Z",
          expires_at: "2026-04-24T00:05:00Z",
        }),
      );
    });

    try {
      const client = new HIPClient("shouldNotBeSent", { providerURL: srv.url });
      const verifier = "v".repeat(128);
      const resp = await client.completeOAuth("the-code", verifier, {
        client_id: "my-platform",
      });
      assert.equal(gotAuth, undefined, "Authorization header must NOT be sent");
      assert.equal(gotBody!["grant_type"], "authorization_code");
      assert.equal(gotBody!["code"], "the-code");
      assert.equal(gotBody!["client_id"], "my-platform");
      assert.equal(gotBody!["code_verifier"], verifier);
      assert.equal(resp.subject_id, "sid");
    } finally {
      srv.close();
    }
  });
});
