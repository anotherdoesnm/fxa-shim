import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";

import { createApp } from "../src/server.js";
import {
  OLDSYNC_SCOPE,
  b64url,
  decryptJwe,
  hkdf,
  pkceChallenge,
  randomB64url,
  verifyJwt,
} from "../src/crypto.js";

async function freePort() {
  return await new Promise((resolve, reject) => {
    const server = net.createServer();
    server.on("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const port = server.address().port;
      server.close(() => resolve(port));
    });
  });
}

function responseCookies(response) {
  const setCookies =
    typeof response.headers.getSetCookie === "function"
      ? response.headers.getSetCookie()
      : [response.headers.get("set-cookie")].filter(Boolean);
  const jar = {};
  for (const cookie of setCookies) {
    const [pair] = cookie.split(";");
    const index = pair.indexOf("=");
    if (index > 0) jar[pair.slice(0, index)] = pair.slice(index + 1);
  }
  return jar;
}

test("dev login, authorize, token exchange and scoped keys", async (t) => {
  const port = await freePort();
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "fxa-shim-"));
  const base = `http://127.0.0.1:${port}`;

  const cfg = {
    host: "127.0.0.1",
    port,
    publicBaseUrl: base,
    syncBaseUrl: "http://127.0.0.1:1",
    dataFile: path.join(tmp, "state.json"),
    sessionSecret: "test-session-secret",
    secureCookies: false,
    devLogin: true,
    declinePasswords: true,
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
      tokenAuth: "post",
    },
  };

  const { server } = createApp(cfg);
  await new Promise((resolve) => server.listen(port, "127.0.0.1", resolve));
  t.after(() => {
    server.close();
    fs.rmSync(tmp, { recursive: true, force: true });
  });

  // 1. Dev sign-in creates a session.
  const login = await fetch(`${base}/auth/dev`, {
    method: "POST",
    redirect: "manual",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ email: "alice@example.com", return_to: "/" }),
  });
  assert.equal(login.status, 302);
  const jar = responseCookies(login);
  assert.ok(jar.fxa_session, "session cookie set");
  const cookieHeader = Object.entries(jar)
    .map(([name, value]) => `${name}=${value}`)
    .join("; ");

  // 2. Session endpoint sees the account.
  const sessionResponse = await fetch(`${base}/api/session`, {
    headers: { cookie: cookieHeader },
  });
  assert.equal(sessionResponse.status, 200);
  const session = await sessionResponse.json();
  assert.equal(session.loggedIn, true);
  assert.equal(session.email, "alice@example.com");
  assert.equal(session.uid.length, 32);
  assert.deepEqual([...session.declinedEngines].sort(), ["addresses", "creditcards", "passwords"]);

  // 3. Firefox-side OAuth parameters.
  const verifier = randomB64url(32);
  const challenge = pkceChallenge(verifier);
  const client = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const publicJwk = client.publicKey.export({ format: "jwk" });
  const keysJwk = b64url(JSON.stringify(publicJwk));
  const clientId = "5882386c6d801776";
  const scope = `${OLDSYNC_SCOPE} profile`;

  const authorize = await fetch(`${base}/api/authorize`, {
    method: "POST",
    headers: {
      cookie: cookieHeader,
      "content-type": "application/json",
    },
    body: JSON.stringify({
      client_id: clientId,
      scope,
      state: "firefox-state",
      code_challenge: challenge,
      code_challenge_method: "S256",
      keys_jwk: keysJwk,
    }),
  });
  assert.equal(authorize.status, 200);
  const authorization = await authorize.json();
  assert.equal(authorization.state, "firefox-state");
  assert.ok(authorization.code);

  // 4. Exchange the code, as Firefox does.
  const tokenResponse = await fetch(`${base}/v1/oauth/token`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      // Firefox sends a Hawk header derived from the sessionToken. The MVP
      // intentionally does not validate it; this checks that it does not get
      // in the way of the JSON body.
      authorization: 'Hawk id="test", ts="1", nonce="n", hash="h", mac="m"',
    },
    body: JSON.stringify({
      grant_type: "authorization_code",
      code: authorization.code,
      client_id: clientId,
      code_verifier: verifier,
    }),
  });
  assert.equal(tokenResponse.status, 200);
  const tokens = await tokenResponse.json();
  assert.ok(tokens.access_token);
  assert.ok(tokens.refresh_token);
  assert.ok(tokens.keys_jwe);
  assert.equal(tokens.scope, scope);

  // 5. Decrypt the keys exactly like Firefox does.
  const decrypted = JSON.parse(
    decryptJwe(tokens.keys_jwe, client.privateKey).toString("utf8"),
  );
  const scopedKey = decrypted[OLDSYNC_SCOPE];
  assert.equal(scopedKey.scope, OLDSYNC_SCOPE);
  assert.equal(scopedKey.kty, "oct");
  assert.ok(scopedKey.kid.includes("-"));
  assert.equal(Buffer.from(scopedKey.k, "base64url").length, 64);

  // 6. The access token verifies against the published JWKS.
  const jwksResponse = await fetch(`${base}/v1/jwks`);
  const jwks = await jwksResponse.json();
  assert.equal(jwks.keys.length, 1);
  const publicKey = crypto.createPublicKey({ key: jwks.keys[0], format: "jwk" });
  const verified = verifyJwt(tokens.access_token, publicKey).payload;
  assert.equal(verified.sub, session.uid);
  assert.ok(verified.scope.split(/[,\s]+/).includes(OLDSYNC_SCOPE));
  assert.equal(verified.iss, base);

  // 7. Profile endpoint.
  const profileResponse = await fetch(`${base}/v1/profile`, {
    headers: { authorization: `Bearer ${tokens.access_token}` },
  });
  assert.equal(profileResponse.status, 200);
  const profile = await profileResponse.json();
  assert.equal(profile.uid, session.uid);
  assert.equal(profile.email, "alice@example.com");

  // 8. Android's fxa-client also fetches the OpenID configuration.
  const openid = await fetch(`${base}/.well-known/openid-configuration`).then((r) => r.json());
  assert.equal(openid.issuer, base);
  assert.equal(openid.authorization_endpoint, `${base}/authorization`);
  assert.equal(openid.jwks_uri, `${base}/v1/jwks`);
  assert.equal(openid.userinfo_endpoint, `${base}/v1/profile`);
  assert.ok(openid.introspection_endpoint);
  const authorizationPage = await fetch(`${base}/authorization?client_id=x`);
  assert.equal(authorizationPage.status, 200);
  assert.match(await authorizationPage.text(), /WebChannelMessageToChrome/);

  // 9. Introspection is available for clients that use it.
  const introspect = await fetch(`${base}/v1/introspect`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ token: tokens.access_token }),
  }).then((r) => r.json());
  assert.equal(introspect.active, true);
  assert.equal(introspect.sub, session.uid);

  // 10. syncstorage's /v1/verify fallback sees the same token.
  const verifyResponse = await fetch(`${base}/v1/verify`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ token: tokens.access_token }),
  });
  assert.equal(verifyResponse.status, 200);
  const verifiedClaims = await verifyResponse.json();
  assert.equal(verifiedClaims.user, session.uid);
  assert.ok(verifiedClaims.scope.includes(OLDSYNC_SCOPE));

  // 11. app-services can mint a token from the session token (Hawk).
  const hawkId = hkdf(
    Buffer.from(session.sessionToken, "hex"),
    Buffer.alloc(32),
    "identity.mozilla.com/picl/v1/sessionToken",
    96,
  )
    .subarray(0, 32)
    .toString("hex");
  const credentialsToken = await fetch(`${base}/v1/oauth/token`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      authorization: `Hawk id="${hawkId}", ts="1", nonce="n", mac="m"`,
    },
    body: JSON.stringify({
      grant_type: "fxa-credentials",
      client_id: clientId,
      scope: OLDSYNC_SCOPE,
    }),
  });
  assert.equal(credentialsToken.status, 200);
  const credentialsBody = await credentialsToken.json();
  assert.ok(credentialsBody.access_token);

  // 12. Android revokes the access token and registers a device.
  const destroyAlt = await fetch(`${base}/v1/destroy`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ token: tokens.access_token }),
  });
  assert.equal(destroyAlt.status, 200);

  const device = await fetch(`${base}/v1/account/device`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ name: "Pixel", type: "mobile" }),
  }).then((r) => r.json());
  assert.match(device.id, /^[0-9a-f]{32}$/);
  assert.equal(device.name, "Pixel");

  // 13. Refreshing must keep the same refresh token (app-services reuses it).
  for (let i = 0; i < 2; i += 1) {
    const refreshed = await fetch(`${base}/v1/oauth/token`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "refresh_token",
        refresh_token: tokens.refresh_token,
        client_id: clientId,
      }),
    });
    assert.equal(refreshed.status, 200);
    const body = await refreshed.json();
    assert.equal(body.refresh_token, tokens.refresh_token);
    assert.ok(body.access_token);
  }

  // 14. Firefox revokes the refresh token immediately after login.
  const destroy = await fetch(`${base}/v1/oauth/destroy`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ client_id: clientId, token: tokens.refresh_token }),
  });
  assert.equal(destroy.status, 200);

  const refresh = await fetch(`${base}/v1/oauth/token`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "refresh_token",
      refresh_token: tokens.refresh_token,
      client_id: clientId,
    }),
  });
  assert.equal(refresh.status, 400);
});

test("PKCE mismatch is rejected and the code is single-use", async (t) => {
  const port = await freePort();
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "fxa-shim-"));
  const base = `http://127.0.0.1:${port}`;
  const cfg = {
    host: "127.0.0.1",
    port,
    publicBaseUrl: base,
    syncBaseUrl: "http://127.0.0.1:1",
    dataFile: path.join(tmp, "state.json"),
    sessionSecret: "test-session-secret",
    secureCookies: false,
    devLogin: true,
    declinePasswords: true,
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
      tokenAuth: "post",
    },
  };
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
    body: new URLSearchParams({ email: "bob@example.com", return_to: "/" }),
  });
  const jar = responseCookies(login);
  const cookieHeader = Object.entries(jar)
    .map(([name, value]) => `${name}=${value}`)
    .join("; ");

  const verifier = randomB64url(32);
  const authorize = await fetch(`${base}/api/authorize`, {
    method: "POST",
    headers: { cookie: cookieHeader, "content-type": "application/json" },
    body: JSON.stringify({
      client_id: "5882386c6d801776",
      scope: OLDSYNC_SCOPE,
      state: "s",
      code_challenge: pkceChallenge(verifier),
      code_challenge_method: "S256",
    }),
  });
  const { code } = await authorize.json();

  const bad = await fetch(`${base}/v1/oauth/token`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code,
      client_id: "5882386c6d801776",
      code_verifier: randomB64url(32),
    }),
  });
  assert.equal(bad.status, 400);

  const second = await fetch(`${base}/v1/oauth/token`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code,
      client_id: "5882386c6d801776",
      code_verifier: verifier,
    }),
  });
  assert.equal(second.status, 400);
});

test("state survives a process restart (kB is stored as hex)", async (t) => {
  const port = await freePort();
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "fxa-shim-"));
  const base = `http://127.0.0.1:${port}`;
  const cfg = {
    host: "127.0.0.1",
    port,
    publicBaseUrl: base,
    syncBaseUrl: "http://127.0.0.1:1",
    dataFile: path.join(tmp, "state.json"),
    sessionSecret: "test-session-secret",
    secureCookies: false,
    devLogin: true,
    declinePasswords: true,
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
      tokenAuth: "post",
    },
  };

  const first = createApp(cfg);
  await new Promise((resolve) => first.server.listen(port, "127.0.0.1", resolve));

  const login = await fetch(`${base}/auth/dev`, {
    method: "POST",
    redirect: "manual",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ email: "carol@example.com", return_to: "/" }),
  });
  const jar = responseCookies(login);
  const cookieHeader = Object.entries(jar)
    .map(([name, value]) => `${name}=${value}`)
    .join("; ");
  await new Promise((resolve) => first.server.close(resolve));

  const state = JSON.parse(fs.readFileSync(cfg.dataFile, "utf8"));
  const account = Object.values(state.accounts)[0];
  assert.equal(typeof account.kB, "string");
  assert.equal(account.kB.length, 64);

  const second = createApp(cfg);
  await new Promise((resolve) => second.server.listen(port, "127.0.0.1", resolve));
  t.after(() => {
    second.server.close();
    fs.rmSync(tmp, { recursive: true, force: true });
  });

  const sessionResponse = await fetch(`${base}/api/session`, {
    headers: { cookie: cookieHeader },
  });
  const session = await sessionResponse.json();
  assert.equal(session.loggedIn, true);

  const client = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const verifier = randomB64url(32);
  const authorize = await fetch(`${base}/api/authorize`, {
    method: "POST",
    headers: { cookie: cookieHeader, "content-type": "application/json" },
    body: JSON.stringify({
      client_id: "5882386c6d801776",
      scope: OLDSYNC_SCOPE,
      state: "s",
      code_challenge: pkceChallenge(verifier),
      code_challenge_method: "S256",
      keys_jwk: b64url(JSON.stringify(client.publicKey.export({ format: "jwk" }))),
    }),
  });
  assert.equal(authorize.status, 200);
});
