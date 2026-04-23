import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { generateKeyPairSync, sign } from "node:crypto";
import { HIPClient } from "./client.js";
import type { KeyResolver, VerifyRequest, VerifyResponse } from "./types.js";

function generateEd25519KeyPair() {
  return generateKeyPairSync("ed25519", {
    publicKeyEncoding: { type: "spki", format: "der" },
    privateKeyEncoding: { type: "pkcs8", format: "der" },
  });
}

function signJWS(privateDER: Buffer, payload: Buffer): string {
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

describe("HIPClient", () => {
  it("verify success with signature", async () => {
    const { publicKey, privateKey } = generateEd25519KeyPair();

    const srv = await startTestServer(async (req, res) => {
      const body = JSON.parse(await readBody(req)) as VerifyRequest;
      const resp: VerifyResponse = {
        request_id: body.request_id!,
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
      const payload = Buffer.from(JSON.stringify(resp));
      resp.signature = signJWS(privateKey as unknown as Buffer, payload);
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify(resp));
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
    const srv = await startTestServer(async (_req, res) => {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ status: "active", nonce: "wrong" }));
    });

    try {
      const client = new HIPClient("key", { providerURL: srv.url });
      await assert.rejects(
        () => client.verify({ subject_id: "xK7mN2pR9sT4vW6yB@id.provider.example.com", nonce: "my-nonce" }),
        /nonce mismatch/,
      );
    } finally {
      srv.close();
    }
  });

  it("rejects invalid signature", async () => {
    const { publicKey } = generateEd25519KeyPair();
    const { privateKey: otherPriv } = generateEd25519KeyPair();

    const srv = await startTestServer(async (req, res) => {
      const body = JSON.parse(await readBody(req)) as VerifyRequest;
      const resp: Partial<VerifyResponse> = { status: "active", nonce: body.nonce! };
      const payload = Buffer.from(JSON.stringify(resp));
      (resp as VerifyResponse).signature = signJWS(otherPriv as unknown as Buffer, payload);
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify(resp));
    });

    try {
      const client = new HIPClient("key", {
        providerURL: srv.url,
        keyResolver: new StaticKeyResolver(publicKey as unknown as Buffer),
      });
      await assert.rejects(
        () => client.verify({ subject_id: "xK7mN2pR9sT4vW6yB@id.provider.example.com" }),
        /invalid signature/,
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

  it("auto-generates nonce and request_id", async () => {
    let receivedBody: VerifyRequest | null = null;
    const srv = await startTestServer(async (req, res) => {
      receivedBody = JSON.parse(await readBody(req)) as VerifyRequest;
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({
        status: "active",
        nonce: receivedBody!.nonce,
        request_id: receivedBody!.request_id,
      }));
    });

    try {
      const client = new HIPClient("key", { providerURL: srv.url });
      await client.verify({ subject_id: "xK7mN2pR9sT4vW6yB@id.provider.example.com" });
      assert.ok(receivedBody!.nonce, "expected auto-generated nonce");
      assert.ok(receivedBody!.request_id, "expected auto-generated request_id");
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
        () => client.verify({ subject_id: "xK7mN2pR9sT4vW6yB@id.provider.example.com" }),
        /500/,
      );
    } finally {
      srv.close();
    }
  });
});
