import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import http from "node:http";
import net from "node:net";
import os from "node:os";
import path from "node:path";

import { createApp } from "../src/server.js";
import { generateRsaKeyPair, signJwt } from "../src/crypto.js";

async function freePort() {
  return await new Promise((resolve, reject) => {
    const s = net.createServer();
    s.on("error", reject);
    s.listen(0, "127.0.0.1", () => {
      const port = s.address().port;
      s.close(() => resolve(port));
    });
  });
}

function cookiesFrom(response) {
  const list =
    typeof response.headers.getSetCookie === "function"
      ? response.headers.getSetCookie()
      : [response.headers.get("set-cookie")].filter(Boolean);
  const jar = {};
  for (const cookie of list) {
    const [pair] = cookie.split(";");
    const i = pair.indexOf("=");
    if (i > 0) jar[pair.slice(0, i)] = pair.slice(i + 1);
  }
  return jar;
}

function cookieHeader(jar) {
  return Object.entries(jar)
    .map(([name, value]) => `${name}=${value}`)
    .join("; ");
}

test("OIDC login creates an account and a session", async (t) => {
  const shimPort = await freePort();
  const idpPort = await freePort();
  const shimBase = `http://127.0.0.1:${shimPort}`;
  const idpBase = `http://127.0.0.1:${idpPort}`;
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "fxa-shim-oidc-"));

  const { privateKey, publicKey } = generateRsaKeyPair();
  const kid = "idp-kid";
  const publicJwk = {
    ...publicKey.export({ format: "jwk" }),
    kid,
    use: "sig",
    alg: "RS256",
  };
  let expectedNonce = "";

  const idp = http.createServer((req, res) => {
    const send = (status, value) => {
      const body = Buffer.from(JSON.stringify(value));
      res.writeHead(status, {
        "content-type": "application/json",
        "content-length": body.length,
      });
      res.end(body);
    };

    if (req.url === "/.well-known/openid-configuration") {
      return send(200, {
        issuer: idpBase,
        authorization_endpoint: `${idpBase}/authorize`,
        token_endpoint: `${idpBase}/token`,
        jwks_uri: `${idpBase}/jwks`,
      });
    }
    if (req.url === "/jwks") return send(200, { keys: [publicJwk] });
    if (req.url === "/token" && req.method === "POST") {
      let raw = "";
      req.on("data", (chunk) => (raw += chunk));
      req.on("end", () => {
        const body = new URLSearchParams(raw);
        if (body.get("code") !== "good-code") {
          return send(400, { error: "invalid_grant" });
        }
        if (body.get("client_id") !== "shim-client") {
          return send(401, { error: "invalid_client" });
        }
        const idToken = signJwt(
          {
            iss: idpBase,
            aud: "shim-client",
            sub: "alice-sub",
            email: "alice@example.com",
            nonce: expectedNonce,
            iat: Math.floor(Date.now() / 1000),
            exp: Math.floor(Date.now() / 1000) + 300,
          },
          privateKey,
          kid,
          "JWT",
        );
        return send(200, {
          access_token: "idp-access",
          token_type: "Bearer",
          id_token: idToken,
        });
      });
      return;
    }
    return send(404, { error: "not_found" });
  });
  await new Promise((resolve) => idp.listen(idpPort, "127.0.0.1", resolve));

  const cfg = {
    host: "127.0.0.1",
    port: shimPort,
    publicBaseUrl: shimBase,
    syncBaseUrl: "http://127.0.0.1:1",
    dataFile: path.join(tmp, "state.json"),
    sessionSecret: "oidc-test-secret",
    secureCookies: false,
    devLogin: false,
    declinePasswords: true,
    accessTokenTtl: 3600,
    codeTtl: 300,
    sessionTtl: 3600,
    oidc: {
      issuer: idpBase,
      clientId: "shim-client",
      clientSecret: "shim-secret",
      redirectUri: `${shimBase}/auth/callback`,
      scopes: "openid email profile",
      usePkce: true,
      tokenAuth: "post",
    },
  };

  const { server } = createApp(cfg);
  await new Promise((resolve) => server.listen(shimPort, "127.0.0.1", resolve));
  t.after(() => {
    server.close();
    idp.close();
    fs.rmSync(tmp, { recursive: true, force: true });
  });

  const login = await fetch(`${shimBase}/auth/login?return_to=/`, {
    redirect: "manual",
  });
  assert.equal(login.status, 302);
  const loginCookies = cookiesFrom(login);
  assert.ok(loginCookies.fxa_flow);

  const location = new URL(login.headers.get("location"));
  assert.equal(location.origin, idpBase);
  assert.equal(location.searchParams.get("client_id"), "shim-client");
  assert.equal(location.searchParams.get("code_challenge_method"), "S256");
  expectedNonce = location.searchParams.get("nonce");
  const state = location.searchParams.get("state");
  assert.ok(state);

  const callback = await fetch(
    `${shimBase}/auth/callback?code=good-code&state=${encodeURIComponent(state)}`,
    { redirect: "manual", headers: { cookie: cookieHeader(loginCookies) } },
  );
  assert.equal(callback.status, 302);
  assert.equal(new URL(callback.headers.get("location")).pathname, "/");
  const sessionCookies = cookiesFrom(callback);
  assert.ok(sessionCookies.fxa_session);

  const session = await fetch(`${shimBase}/api/session`, {
    headers: { cookie: cookieHeader(sessionCookies) },
  }).then((response) => response.json());
  assert.equal(session.loggedIn, true);
  assert.equal(session.email, "alice@example.com");
  assert.equal(session.uid.length, 32);
});
