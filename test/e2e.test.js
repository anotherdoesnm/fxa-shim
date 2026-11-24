import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";

import { createApp } from "../src/server.js";
import {
  OLDSYNC,
  b64url,
  bytesToHex,
  deriveMaterial,
  makeKeysJwe,
  randomBytes,
  xor,
} from "../src/client-crypto.js";
import { decryptJwe, OLDSYNC_SCOPE } from "../src/crypto.js";

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

function cookies(response) {
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

function baseConfig(port, tmp, keyMode) {
  const base = `http://127.0.0.1:${port}`;
  return {
    host: "127.0.0.1",
    port,
    publicBaseUrl: base,
    syncBaseUrl: "http://127.0.0.1:1",
    dataFile: path.join(tmp, "state.json"),
    sessionSecret: "e2e-test-secret",
    secureCookies: false,
    devLogin: true,
    keyMode,
    declinePasswords: true,
    declineAddresses: true,
    declineCreditCards: true,
    accessTokenTtl: 3600,
    codeTtl: 300,
    sessionTtl: 3600,
    oidc: {
      issuer: "",
      clientId: "",
      clientSecret: "",
      redirectUri: `${base}/auth/callback`,
      scopes: "openid email profile",
      usePkce: true,
      requireNonce: true,
      tokenAuth: "post",
    },
  };
}

test("browser E2E crypto produces a keys_jwe Firefox can decrypt", async () => {
  const client = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const publicJwk = client.publicKey.export({ format: "jwk" });
  const kB = randomBytes(32);
  const material = await deriveMaterial("correct horse battery staple", "uid|a@example.com");
  assert.equal(material.unwrapBKey.length, 32);
  assert.equal(material.authHash.length, 32);

  const wrapkB = xor(kB, material.unwrapBKey);
  assert.equal(wrapkB.length, 32);

  const jwe = await makeKeysJwe(kB, b64url(JSON.stringify(publicJwk)));
  const decrypted = JSON.parse(
    decryptJwe(jwe, client.privateKey).toString("utf8"),
  );
  const scoped = decrypted[OLDSYNC];
  assert.equal(scoped.scope, OLDSYNC);
  assert.equal(scoped.kty, "oct");
  assert.equal(Buffer.from(scoped.k, "base64url").length, 64);
  assert.ok(scoped.kid.includes("-"));
});

test("E2E setup, unlock and authorize with client-side keys", async (t) => {
  const port = await freePort();
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "fxa-shim-e2e-"));
  const cfg = baseConfig(port, tmp, "e2e");
  const base = cfg.publicBaseUrl;
  const { server } = createApp(cfg);
  await new Promise((resolve) => server.listen(port, "127.0.0.1", resolve));
  t.after(() => {
    server.close();
    fs.rmSync(tmp, { recursive: true, force: true });
  });

  const login = await fetch(`${base}/auth/dev`, {
    method: "POST",
    redirect: "manual",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ email: "e2e@example.com", return_to: "/" }),
  });
  const jar = cookies(login);
  const cookie = cookieHeader(jar);

  const session = await fetch(`${base}/api/session`, { headers: { cookie } }).then((r) => r.json());
  assert.equal(session.loggedIn, true);
  assert.equal(session.keyMode, "e2e");
  assert.equal(session.mode, "e2e");
  assert.equal(session.needsSetup, true);

  const material = await deriveMaterial("a very long sync password", `${session.uid}|${session.email}`);
  const kB = randomBytes(32);
  const wrapkB = xor(kB, material.unwrapBKey);
  const setup = await fetch(`${base}/api/keys/setup`, {
    method: "POST",
    headers: { cookie, "content-type": "application/json" },
    body: JSON.stringify({
      wrapkB: bytesToHex(wrapkB),
      authHash: bytesToHex(material.authHash),
    }),
  });
  assert.equal(setup.status, 200);

  const status = await fetch(`${base}/api/keys/status`, { headers: { cookie } }).then((r) => r.json());
  assert.equal(status.hasKeys, true);
  assert.equal(status.needsSetup, false);

  const wrong = await fetch(`${base}/api/keys/unlock`, {
    method: "POST",
    headers: { cookie, "content-type": "application/json" },
    body: JSON.stringify({ authHash: "0".repeat(64) }),
  });
  assert.equal(wrong.status, 401);

  const unlocked = await fetch(`${base}/api/keys/unlock`, {
    method: "POST",
    headers: { cookie, "content-type": "application/json" },
    body: JSON.stringify({ authHash: bytesToHex(material.authHash) }),
  }).then((r) => r.json());
  assert.equal(unlocked.wrapkB, bytesToHex(wrapkB));

  const verifier = "e".repeat(43);
  const challenge = b64url(
    crypto.createHash("sha256").update(verifier).digest(),
  );
  const authorize = await fetch(`${base}/api/authorize`, {
    method: "POST",
    headers: { cookie, "content-type": "application/json" },
    body: JSON.stringify({
      client_id: "5882386c6d801776",
      scope: `${OLDSYNC_SCOPE} profile`,
      state: "s",
      code_challenge: challenge,
      code_challenge_method: "S256",
      keys_jwe: "a.b.c.d.e",
    }),
  });
  assert.equal(authorize.status, 200);
  const code = await authorize.json();

  const token = await fetch(`${base}/v1/oauth/token`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code: code.code,
      client_id: "5882386c6d801776",
      code_verifier: verifier,
    }),
  }).then((r) => r.json());
  assert.equal(token.keys_jwe, "a.b.c.d.e");
});

test("existing server-side account can migrate to E2E without losing kB", async (t) => {
  const port = await freePort();
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "fxa-shim-mig-"));
  const cfg = baseConfig(port, tmp, "server");
  const base = cfg.publicBaseUrl;

  const first = createApp(cfg);
  await new Promise((resolve) => first.server.listen(port, "127.0.0.1", resolve));
  const login = await fetch(`${base}/auth/dev`, {
    method: "POST",
    redirect: "manual",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ email: "migrate@example.com", return_to: "/" }),
  });
  const cookie = cookieHeader(cookies(login));
  const session = await fetch(`${base}/api/session`, { headers: { cookie } }).then((r) => r.json());
  assert.equal(session.mode, "server");
  assert.equal(session.hasKeys, true);
  await new Promise((resolve) => first.server.close(resolve));

  cfg.keyMode = "e2e";
  const port2 = await freePort();
  cfg.port = port2;
  cfg.publicBaseUrl = `http://127.0.0.1:${port2}`;
  cfg.oidc.redirectUri = `${cfg.publicBaseUrl}/auth/callback`;
  const second = createApp(cfg);
  await new Promise((resolve) => second.server.listen(port2, "127.0.0.1", resolve));
  const base2 = cfg.publicBaseUrl;
  t.after(() => {
    second.server.close();
    fs.rmSync(tmp, { recursive: true, force: true });
  });

  const status = await fetch(`${base2}/api/keys/status`, { headers: { cookie } }).then((r) => r.json());
  assert.equal(status.mode, "server");
  assert.equal(status.needsMigration, true);

  const migration = await fetch(`${base2}/api/keys/migration-kb`, { headers: { cookie } }).then((r) => r.json());
  assert.match(migration.kB, /^[0-9a-f]{64}$/);
  const kB = Buffer.from(migration.kB, "hex");

  const material = await deriveMaterial("migration password", `${session.uid}|${session.email}`);
  const wrapkB = xor(new Uint8Array(kB), material.unwrapBKey);
  const setup = await fetch(`${base2}/api/keys/setup`, {
    method: "POST",
    headers: { cookie, "content-type": "application/json" },
    body: JSON.stringify({
      wrapkB: bytesToHex(wrapkB),
      authHash: bytesToHex(material.authHash),
    }),
  });
  assert.equal(setup.status, 200);

  const after = await fetch(`${base2}/api/keys/status`, { headers: { cookie } }).then((r) => r.json());
  assert.equal(after.mode, "e2e");
  assert.equal(after.hasKeys, true);

  const state = JSON.parse(fs.readFileSync(cfg.dataFile, "utf8"));
  const account = Object.values(state.accounts)[0];
  assert.equal(account.kB, undefined);
  assert.match(account.wrapkB, /^[0-9a-f]{64}$/);
});
