import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import http from "node:http";

import { discover, exchangeCode, verifyIdToken } from "../src/oidc.js";
import { generateRsaKeyPair, signJwt } from "../src/crypto.js";

test("OIDC discovery, code exchange and ID token verification", async (t) => {
  const { privateKey, publicKey } = generateRsaKeyPair();
  const kid = "test-kid";
  const publicJwk = {
    ...publicKey.export({ format: "jwk" }),
    kid,
    use: "sig",
    alg: "RS256",
  };

  let base;
  const server = http.createServer((req, res) => {
    const send = (status, value) => {
      const body = Buffer.from(JSON.stringify(value));
      res.writeHead(status, {
        "content-type": "application/json",
        "content-length": body.length,
      });
      res.end(body);
    };

    if (req.method === "GET" && req.url === "/.well-known/openid-configuration") {
      return send(200, {
        issuer: base,
        authorization_endpoint: `${base}/authorize`,
        token_endpoint: `${base}/token`,
        jwks_uri: `${base}/jwks`,
        userinfo_endpoint: `${base}/userinfo`,
      });
    }
    if (req.method === "GET" && req.url === "/jwks") {
      return send(200, { keys: [publicJwk] });
    }
    if (req.method === "POST" && req.url === "/token") {
      let raw = "";
      req.on("data", (chunk) => (raw += chunk));
      req.on("end", () => {
        const body = new URLSearchParams(raw);
        if (body.get("code") !== "good-code") {
          return send(400, { error: "invalid_grant" });
        }
        if (body.get("code_verifier") !== "verifier-123") {
          return send(400, { error: "invalid_grant", detail: "pkce" });
        }
        if (body.get("client_secret") !== "client-secret") {
          return send(401, { error: "invalid_client" });
        }
        const idToken = signJwt(
          {
            iss: base,
            aud: "client-id",
            sub: "user-1",
            email: "user@example.com",
            nonce: "nonce-123",
            iat: Math.floor(Date.now() / 1000),
            exp: Math.floor(Date.now() / 1000) + 300,
          },
          privateKey,
          kid,
          "JWT",
        );
        return send(200, {
          access_token: "access-token",
          token_type: "Bearer",
          id_token: idToken,
        });
      });
      return;
    }
    return send(404, { error: "not_found" });
  });

  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => server.close());
  base = `http://127.0.0.1:${server.address().port}`;

  const cfg = {
    oidc: {
      issuer: base,
      clientId: "client-id",
      clientSecret: "client-secret",
      redirectUri: `${base}/callback`,
      scopes: "openid email profile",
      usePkce: true,
      tokenAuth: "post",
    },
  };

  const discovery = await discover(base);
  assert.equal(discovery.issuer, base);

  const tokens = await exchangeCode(discovery, cfg, {
    code: "good-code",
    codeVerifier: "verifier-123",
  });
  assert.equal(tokens.access_token, "access-token");

  const claims = await verifyIdToken(discovery, cfg, tokens.id_token, {
    nonce: "nonce-123",
  });
  assert.equal(claims.sub, "user-1");
  assert.equal(claims.email, "user@example.com");

  await assert.rejects(
    verifyIdToken(discovery, cfg, tokens.id_token, { nonce: "wrong" }),
    /nonce/,
  );

  const otherKey = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
  const tampered = signJwt(
    { iss: base, aud: "client-id", sub: "evil", exp: Math.floor(Date.now() / 1000) + 300 },
    otherKey.privateKey,
    kid,
    "JWT",
  );
  await assert.rejects(verifyIdToken(discovery, cfg, tampered), /signature/);
});
