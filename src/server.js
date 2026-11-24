import http from "node:http";
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { fileURLToPath } from "node:url";

import { loadConfig } from "./config.js";
import { Store } from "./store.js";
import {
  OLDSYNC_SCOPE,
  b64url,
  b64urlDecode,
  encryptJwe,
  hkdf,
  makeScopedKeys,
  pkceChallenge,
  randomB64url,
  randomHex,
  rsaPublicJwk,
  sha256,
  signJwt,
  timingSafeEqualString,
  verifyJwt,
} from "./crypto.js";
import { buildAuthorizeUrl, discover, exchangeCode, fetchUserInfo, verifyIdToken } from "./oidc.js";
import { renderAccountPage, renderPage } from "./html.js";

const CLIENT_CRYPTO = fs.readFileSync(new URL("./client-crypto.js", import.meta.url), "utf8");

const OFFERED_ENGINES = ["addons", "bookmarks", "history", "passwords", "prefs", "tabs"];

function loadOrCreateKeys(cfg) {
  const dir = path.dirname(cfg.dataFile);
  fs.mkdirSync(dir, { recursive: true });

  let privateKey;
  if (process.env.RSA_KEY_PEM) {
    privateKey = crypto.createPrivateKey(process.env.RSA_KEY_PEM);
  } else {
    const keyFile = path.join(dir, "rsa-key.pem");
    if (fs.existsSync(keyFile)) {
      privateKey = crypto.createPrivateKey(fs.readFileSync(keyFile));
    } else {
      privateKey = crypto.generateKeyPairSync("rsa", {
        modulusLength: 2048,
      }).privateKey;
      fs.writeFileSync(
        keyFile,
        privateKey.export({ type: "pkcs8", format: "pem" }),
        { mode: 0o600 },
      );
    }
  }
  const publicKey = crypto.createPublicKey(privateKey);
  const kid = crypto
    .createHash("sha256")
    .update(publicKey.export({ type: "spki", format: "der" }))
    .digest("base64url")
    .slice(0, 16);
  return { privateKey, publicKey, kid, publicJwk: rsaPublicJwk(publicKey, kid) };
}

function parseCookies(req) {
  const header = req.headers.cookie || "";
  const out = {};
  for (const part of header.split(";")) {
    const index = part.indexOf("=");
    if (index < 0) continue;
    const name = part.slice(0, index).trim();
    const value = part.slice(index + 1).trim();
    if (name) out[name] = decodeURIComponent(value);
  }
  return out;
}

function signCookieValue(value, secret) {
  return crypto.createHmac("sha256", secret).update(value).digest("base64url");
}

function makeCookieValue(value, secret) {
  return `${value}.${signCookieValue(value, secret)}`;
}

function readSignedCookie(req, name, secret) {
  const raw = parseCookies(req)[name];
  if (!raw) return null;
  const index = raw.lastIndexOf(".");
  if (index < 0) return null;
  const value = raw.slice(0, index);
  const signature = raw.slice(index + 1);
  if (!timingSafeEqualString(signature, signCookieValue(value, secret))) {
    return null;
  }
  return value;
}

function cookie(name, value, options = {}) {
  const {
    maxAge,
    secure = false,
    httpOnly = true,
    sameSite = "Lax",
    path: cookiePath = "/",
  } = options;
  let out = `${name}=${encodeURIComponent(value)}; Path=${cookiePath}; SameSite=${sameSite}`;
  if (httpOnly) out += "; HttpOnly";
  if (secure) out += "; Secure";
  if (maxAge !== undefined) out += `; Max-Age=${Math.max(0, Math.floor(maxAge))}`;
  return out;
}

async function readBody(req, limit = 1_000_000) {
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > limit) throw new Error("request body too large");
    chunks.push(chunk);
  }
  return Buffer.concat(chunks);
}

function parseBody(req, buffer) {
  if (!buffer.length) return {};
  const contentType = String(req.headers["content-type"] || "")
    .split(";")[0]
    .trim()
    .toLowerCase();
  const text = buffer.toString("utf8");
  if (contentType === "application/json" || (!contentType && text.trim().startsWith("{"))) {
    return JSON.parse(text);
  }
  return Object.fromEntries(new URLSearchParams(text));
}

function json(res, status, value, extraHeaders = {}) {
  const body = Buffer.from(JSON.stringify(value));
  res.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "content-length": body.length,
    "cache-control": "no-store",
    ...extraHeaders,
  });
  res.end(body);
}

function text(res, status, value, contentType = "text/plain; charset=utf-8") {
  const body = Buffer.from(value);
  res.writeHead(status, {
    "content-type": contentType,
    "content-length": body.length,
    "cache-control": "no-store",
  });
  res.end(body);
}

function html(res, status, value) {
  const body = Buffer.from(value);
  res.writeHead(status, {
    "content-type": "text/html; charset=utf-8",
    "content-length": body.length,
    "cache-control": "no-store",
    "content-security-policy":
      "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
    "x-frame-options": "DENY",
    "referrer-policy": "no-referrer",
  });
  res.end(body);
}

function redirect(res, location, cookies = []) {
  const headers = { location, "cache-control": "no-store" };
  if (cookies.length) headers["set-cookie"] = cookies;
  res.writeHead(302, headers);
  res.end();
}

function safeReturnTo(value, publicBaseUrl) {
  try {
    const candidate = new URL(value || "/", publicBaseUrl);
    const base = new URL(publicBaseUrl);
    if (candidate.origin !== base.origin) return "/";
    return candidate.href;
  } catch {
    return "/";
  }
}

function accountForIdentity(store, cfg, issuer, sub, email) {
  let account = store.findAccount(issuer, sub);
  if (account) return account;

  const uid = sha256(`${issuer}\0${sub}`).toString("hex").slice(0, 32);
  const cleanSub = String(sub).replace(/[^a-zA-Z0-9._-]/g, "").slice(0, 64) || "user";
  const safeEmail =
    email && String(email).includes("@") ? String(email) : `${cleanSub}@oidc.local`;

  account = {
    uid,
    email: safeEmail,
    issuer,
    sub,
    keyMode: cfg.keyMode,
    sessionToken: randomHex(32),
    keyFetchToken: randomHex(32),
    unwrapBKey: randomHex(32),
    createdAt: Date.now(),
  };
  if (cfg.keyMode !== "e2e") {
    account.kB = crypto.randomBytes(32).toString("hex");
  }
  store.putAccount(account);
  return account;
}

function signAccessToken(cfg, keys, account, scope, clientId) {
  const now = Math.floor(Date.now() / 1000);
  // Firefox/app-services and the deployed syncstorage tokenserver both
  // expect OAuth scopes space-separated.
  const tokenScope = String(scope)
    .split(/[,\s]+/)
    .filter(Boolean)
    .join(" ");
  return signJwt(
    {
      sub: account.uid,
      scope: tokenScope,
      client_id: clientId,
      iss: cfg.tokenIssuer || cfg.publicBaseUrl,
      iat: now,
      exp: now + cfg.accessTokenTtl,
      "fxa-generation": 0,
    },
    keys.privateKey,
    keys.kid,
  );
}

function hawkIdForSessionToken(sessionTokenHex) {
  const material = hkdf(
    Buffer.from(sessionTokenHex, "hex"),
    Buffer.alloc(32),
    "identity.mozilla.com/picl/v1/sessionToken",
    96,
  );
  return material.subarray(0, 32).toString("hex");
}

function accountForHawk(req, store) {
  const header = String(req.headers.authorization || "");
  const match = header.match(/\bid="([^"]+)"/);
  const accounts = Object.values(store.state.accounts);
  if (match) {
    const found = accounts.find(
      (account) => hawkIdForSessionToken(account.sessionToken) === match[1],
    );
    if (found) return found;
  }
  // Single-user deployments: be forgiving if the client did not send Hawk.
  return accounts.length === 1 ? accounts[0] : null;
}

function bearerToken(req) {
  const header = String(req.headers.authorization || "");
  const match = header.match(/^Bearer\s+(.+)$/i);
  return match ? match[1].trim() : null;
}

function accountKeyMode(account) {
  return account.keyMode || "server";
}

function keyStatus(account) {
  const mode = accountKeyMode(account);
  if (mode === "e2e" && account.wrapkB) {
    return { mode, hasKeys: true, needsSetup: false, needsMigration: false };
  }
  if (mode === "e2e") {
    return { mode, hasKeys: false, needsSetup: true, needsMigration: false };
  }
  return {
    mode,
    hasKeys: Boolean(account.kB),
    needsSetup: false,
    needsMigration: Boolean(account.kB),
  };
}

function declinedEngines(cfg) {
  const declined = [];
  if (cfg.declinePasswords) declined.push("passwords");
  if (cfg.declineAddresses !== false) declined.push("addresses");
  if (cfg.declineCreditCards !== false) declined.push("creditcards");
  return declined;
}

export function createApp(cfg = loadConfig()) {
  const store = new Store(cfg.dataFile);
  const keys = loadOrCreateKeys(cfg);

  setInterval(() => store.cleanup(), 60_000).unref();

  function getSession(req) {
    const sid = readSignedCookie(req, "fxa_session", cfg.sessionSecret);
    return sid ? store.getSession(sid) : null;
  }

  function sessionCookie(sid) {
    return cookie("fxa_session", makeCookieValue(sid, cfg.sessionSecret), {
      maxAge: cfg.sessionTtl,
      secure: cfg.secureCookies,
      sameSite: "Lax",
    });
  }

  function clearSessionCookie() {
    return cookie("fxa_session", "", {
      maxAge: 0,
      secure: cfg.secureCookies,
      sameSite: "Lax",
    });
  }

  async function handle(req, res) {
    const url = new URL(req.url || "/", cfg.publicBaseUrl);
    const pathname = url.pathname;
    const method = req.method || "GET";

    if (method === "GET" && (pathname === "/" || pathname === "/signin" || pathname === "/oauth" || pathname === "/oauth/signin")) {
      return html(res, 200, renderPage());
    }

    if (method === "GET" && pathname === "/healthz") {
      return json(res, 200, { ok: true });
    }

    if (method === "GET" && pathname === "/client-crypto.js") {
      return text(res, 200, CLIENT_CRYPTO, "text/javascript; charset=utf-8");
    }

    if (method === "GET" && pathname === "/avatar.png") {
      // 1x1 transparent PNG. Fenix/Iceraven expects a real avatar URL; an
      // empty string can make the account menu's image loader unhappy.
      const png = Buffer.from(
        "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=",
        "base64",
      );
      res.writeHead(200, {
        "content-type": "image/png",
        "content-length": png.length,
        "cache-control": "public, max-age=3600",
      });
      res.end(png);
      return;
    }

    if (method === "GET" && pathname === "/.well-known/fxa-client-configuration") {
      return json(res, 200, {
        auth_server_base_url: cfg.publicBaseUrl,
        oauth_server_base_url: cfg.publicBaseUrl,
        profile_server_base_url: cfg.publicBaseUrl,
        sync_tokenserver_base_url: cfg.syncBaseUrl,
      });
    }

    // Android's application-services fxa-client fetches this in addition to
    // fxa-client-configuration when the content server is overridden.
    if (method === "GET" && pathname === "/.well-known/openid-configuration") {
      return json(res, 200, {
        issuer: cfg.publicBaseUrl,
        authorization_endpoint: `${cfg.publicBaseUrl}/authorization`,
        token_endpoint: `${cfg.publicBaseUrl}/v1/oauth/token`,
        userinfo_endpoint: `${cfg.publicBaseUrl}/v1/profile`,
        jwks_uri: `${cfg.publicBaseUrl}/v1/jwks`,
        introspection_endpoint: `${cfg.publicBaseUrl}/v1/introspect`,
        revocation_endpoint: `${cfg.publicBaseUrl}/v1/oauth/destroy`,
        verify_endpoint: `${cfg.publicBaseUrl}/v1/verify`,
        response_types_supported: ["code"],
        scopes_supported: ["openid", "profile", "email", OLDSYNC_SCOPE],
        subject_types_supported: ["public"],
        id_token_signing_alg_values_supported: ["RS256"],
        token_endpoint_auth_methods_supported: [
          "client_secret_post",
          "client_secret_basic",
        ],
        claims_supported: ["aud", "exp", "iat", "iss", "sub"],
      });
    }

    // Mozilla's OpenID configuration uses /authorization as the web-content
    // entry point for the OAuth flow; serve the same page there.
    if (method === "GET" && (pathname === "/authorization" || pathname === "/oauth/authorization")) {
      return html(res, 200, renderPage());
    }

    if (method === "GET" && (pathname === "/v1/jwks" || pathname === "/jwks")) {
      return json(res, 200, { keys: [keys.publicJwk] });
    }

    if (method === "POST" && pathname === "/v1/introspect") {
      const body = parseBody(req, await readBody(req));
      try {
        const payload = verifyJwt(String(body.token || ""), keys.publicKey).payload;
        return json(res, 200, {
          active: true,
          scope: payload.scope,
          client_id: payload.client_id,
          sub: payload.sub,
          exp: payload.exp,
          iss: payload.iss,
        });
      } catch {
        return json(res, 200, { active: false });
      }
    }

    if (method === "POST" && pathname === "/v1/verify") {
      const body = parseBody(req, await readBody(req));
      try {
        const payload = verifyJwt(String(body.token || ""), keys.publicKey).payload;
        return json(res, 200, {
          user: payload.sub,
          client_id: payload.client_id,
          scope: String(payload.scope || "")
            .split(/[,\s]+/)
            .filter(Boolean),
          generation: payload["fxa-generation"] ?? 0,
        });
      } catch {
        return json(res, 401, { error: "invalid_token" });
      }
    }

    if (method === "GET" && pathname === "/api/session") {
      const session = getSession(req);
      if (!session) return json(res, 200, { loggedIn: false });
      const account = store.getAccount(session.uid);
      if (!account) return json(res, 200, { loggedIn: false });
      return json(res, 200, {
        loggedIn: true,
        uid: account.uid,
        email: account.email,
        sessionToken: account.sessionToken,
        keyFetchToken: account.keyFetchToken,
        unwrapBKey: account.unwrapBKey,
        declinedEngines: declinedEngines(cfg),
        keyMode: cfg.keyMode,
        ...keyStatus(account),
      });
    }

    if (method === "GET" && pathname === "/api/keys/status") {
      const session = getSession(req);
      if (!session) return json(res, 401, { error: "not_signed_in" });
      const account = store.getAccount(session.uid);
      if (!account) return json(res, 401, { error: "unknown_account" });
      return json(res, 200, keyStatus(account));
    }

    if (method === "GET" && pathname === "/api/keys/migration-kb") {
      const session = getSession(req);
      if (!session) return json(res, 401, { error: "not_signed_in" });
      const account = store.getAccount(session.uid);
      if (!account) return json(res, 401, { error: "unknown_account" });
      if (accountKeyMode(account) !== "server" || !account.kB) {
        return json(res, 409, { error: "no_migration_material" });
      }
      return json(res, 200, { kB: account.kB });
    }

    if (method === "POST" && pathname === "/api/keys/setup") {
      const session = getSession(req);
      if (!session) return json(res, 401, { error: "not_signed_in" });
      const account = store.getAccount(session.uid);
      if (!account) return json(res, 401, { error: "unknown_account" });
      if (accountKeyMode(account) === "e2e" && account.wrapkB) {
        return json(res, 409, { error: "sync_password_already_set" });
      }
      const body = parseBody(req, await readBody(req));
      const wrapkB = String(body.wrapkB || "");
      const authHash = String(body.authHash || "");
      if (!/^[0-9a-f]{64}$/i.test(wrapkB) || !/^[0-9a-f]{64}$/i.test(authHash)) {
        return json(res, 400, { error: "invalid_key_material" });
      }
      account.keyMode = "e2e";
      account.wrapkB = wrapkB.toLowerCase();
      account.authHash = authHash.toLowerCase();
      delete account.kB;
      store.putAccount(account);
      return json(res, 200, { ok: true });
    }

    if (method === "POST" && pathname === "/api/keys/unlock") {
      const session = getSession(req);
      if (!session) return json(res, 401, { error: "not_signed_in" });
      const account = store.getAccount(session.uid);
      if (!account) return json(res, 401, { error: "unknown_account" });
      if (!account.wrapkB || !account.authHash) {
        return json(res, 409, { error: "sync_password_not_set" });
      }
      const body = parseBody(req, await readBody(req));
      const authHash = String(body.authHash || "").toLowerCase();
      if (!timingSafeEqualString(authHash, account.authHash)) {
        return json(res, 401, { error: "invalid_sync_password" });
      }
      return json(res, 200, { wrapkB: account.wrapkB });
    }

    if (method === "POST" && pathname === "/api/authorize") {
      const session = getSession(req);
      if (!session) return json(res, 401, { error: "not_signed_in" });
      const account = store.getAccount(session.uid);
      if (!account) return json(res, 401, { error: "unknown_account" });

      const body = parseBody(req, await readBody(req));
      const { client_id, scope, state, keys_jwk } = body;
      const codeChallenge = body.code_challenge;
      const codeChallengeMethod = body.code_challenge_method || "S256";

      if (!client_id || !scope || !state || !codeChallenge) {
        return json(res, 400, { error: "missing_parameters" });
      }
      if (!String(scope).split(/\s+/).includes(OLDSYNC_SCOPE)) {
        return json(res, 400, { error: "sync_scope_required" });
      }
      if (codeChallengeMethod !== "S256") {
        return json(res, 400, { error: "pkce_s256_required" });
      }

      const mode = accountKeyMode(account);
      let keysJwe;
      if (mode === "e2e") {
        if (!account.wrapkB) {
          return json(res, 409, { error: "sync_password_required" });
        }
        if (!body.keys_jwe || typeof body.keys_jwe !== "string") {
          return json(res, 400, { error: "missing_keys_jwe" });
        }
        if (body.keys_jwe.length > 16_384) {
          return json(res, 400, { error: "keys_jwe_too_large" });
        }
        keysJwe = body.keys_jwe;
      } else if (keys_jwk) {
        let jwk;
        try {
          jwk = JSON.parse(b64urlDecode(String(keys_jwk)).toString("utf8"));
        } catch {
          return json(res, 400, { error: "invalid_keys_jwk" });
        }
        if (jwk.kty !== "EC" || jwk.crv !== "P-256" || !jwk.x || !jwk.y) {
          return json(res, 400, { error: "unsupported_keys_jwk" });
        }
        const scoped = makeScopedKeys(Buffer.from(account.kB, "hex"), Date.now());
        keysJwe = encryptJwe(JSON.stringify(scoped), jwk, jwk.kid);
      }

      const code = randomHex(32);
      store.createCode({
        code,
        uid: account.uid,
        clientId: String(client_id),
        scope: String(scope),
        codeChallenge,
        codeChallengeMethod,
        keysJwe,
        createdAt: Date.now(),
        expiresAt: Date.now() + cfg.codeTtl * 1000,
      });
      return json(res, 200, { code, state });
    }

    if (method === "POST" && pathname === "/v1/oauth/token") {
      const body = parseBody(req, await readBody(req));
      const grantType = body.grant_type;

      if (grantType === "authorization_code") {
        const entry = store.consumeCode(body.code || "");
        if (!entry) return json(res, 400, { error: "unknown_code" });
        if (entry.expiresAt < Date.now()) return json(res, 400, { error: "expired_code" });
        if (body.client_id && body.client_id !== entry.clientId) {
          return json(res, 400, { error: "client_mismatch" });
        }
        if (entry.codeChallenge) {
          if (!body.code_verifier) return json(res, 400, { error: "missing_code_verifier" });
          const expected = pkceChallenge(body.code_verifier);
          if (!timingSafeEqualString(expected, entry.codeChallenge)) {
            return json(res, 400, { error: "invalid_code_verifier" });
          }
        }

        const account = store.getAccount(entry.uid);
        if (!account) return json(res, 400, { error: "unknown_account" });

        const accessToken = signAccessToken(cfg, keys, account, entry.scope, entry.clientId);
        const refreshToken = randomHex(32);
        store.createRefresh({
          token: refreshToken,
          uid: account.uid,
          clientId: entry.clientId,
          scope: entry.scope,
          createdAt: Date.now(),
          expiresAt: Date.now() + 30 * 24 * 3600 * 1000,
        });

        const response = {
          access_token: accessToken,
          token_type: "bearer",
          scope: entry.scope,
          expires_in: cfg.accessTokenTtl,
          refresh_token: refreshToken,
          auth_at: Math.floor(Date.now() / 1000),
        };
        if (entry.keysJwe) response.keys_jwe = entry.keysJwe;
        return json(res, 200, response);
      }

      if (grantType === "refresh_token") {
        const entry = store.getRefresh(body.refresh_token || "");
        if (!entry) return json(res, 400, { error: "unknown_refresh_token" });

        const account = store.getAccount(entry.uid);
        if (!account) return json(res, 400, { error: "unknown_account" });

        // Do not rotate the refresh token. FxA keeps it stable for normal
        // access-token refreshes; rotating it here makes app-services lose
        // the token (it keeps the old one) and profile/sync then fail.
        const accessToken = signAccessToken(cfg, keys, account, entry.scope, entry.clientId);

        return json(res, 200, {
          access_token: accessToken,
          token_type: "bearer",
          scope: entry.scope,
          expires_in: cfg.accessTokenTtl,
          refresh_token: entry.token,
          auth_at: Math.floor(Date.now() / 1000),
        });
      }

      // app-services uses this to mint a short-lived access token from the
      // session token (Hawk-authenticated) rather than from a refresh token.
      if (grantType === "fxa-credentials") {
        const account = accountForHawk(req, store);
        if (!account) return json(res, 401, { error: "invalid_credentials" });
        const scope = String(body.scope || "profile");
        const accessToken = signAccessToken(
          cfg,
          keys,
          account,
          scope,
          String(body.client_id || "5882386c6d801776"),
        );
        return json(res, 200, {
          access_token: accessToken,
          token_type: "bearer",
          scope,
          expires_in: cfg.accessTokenTtl,
          auth_at: Math.floor(Date.now() / 1000),
        });
      }

      return json(res, 400, { error: "unsupported_grant_type" });
    }

    if (method === "POST" && (pathname === "/v1/oauth/destroy" || pathname === "/v1/destroy")) {
      const body = parseBody(req, await readBody(req));
      if (body.token) store.deleteRefresh(String(body.token));
      return json(res, 200, {});
    }

    // Application-services registers the device after completing OAuth; a 404
    // here makes the whole sign-in fail even though the tokens were issued.
    if (method === "POST" && pathname === "/v1/account/device") {
      const body = parseBody(req, await readBody(req));
      const deviceId = body.id || randomHex(16);
      return json(res, 200, {
        id: deviceId,
        name: body.name || "Firefox",
        type: body.type || "mobile",
        createdAt: Date.now(),
        availableCommands: body.availableCommands || {},
        pushCallback: body.pushCallback || null,
        pushPublicKey: body.pushPublicKey || null,
        pushAuthKey: body.pushAuthKey || null,
        pushEndpointExpired: false,
        isCurrentDevice: true,
      });
    }

    if (method === "GET" && pathname === "/v1/profile") {
      const token = bearerToken(req);
      if (!token) return json(res, 401, { error: "missing_token" });
      let payload;
      try {
        payload = verifyJwt(token, keys.publicKey).payload;
      } catch {
        return json(res, 401, { error: "invalid_token" });
      }
      const account = store.getAccount(payload.sub);
      if (!account) return json(res, 404, { error: "unknown_account" });
      return json(res, 200, {
        uid: account.uid,
        email: account.email,
        displayName: account.email,
        avatar: `${cfg.publicBaseUrl}/avatar.png`,
        avatarDefault: true,
      });
    }

    if (method === "GET" && (pathname === "/settings" || pathname === "/settings/clients" || pathname === "/settings/avatar/change")) {
      const session = getSession(req);
      if (!session) {
        return redirect(res, `/auth/login?return_to=${encodeURIComponent(pathname)}`);
      }
      const account = store.getAccount(session.uid);
      if (!account) return redirect(res, "/");
      return html(res, 200, renderAccountPage(account));
    }

    if (method === "GET" && (pathname === "/v1/session/status" || pathname === "/v1/session/verify")) {
      return json(res, 200, { state: "verified" });
    }

    if (method === "POST" && pathname === "/v1/session/destroy") {
      return json(res, 200, {});
    }

    if (method === "GET" && pathname === "/v1/recovery_email/status") {
      return json(res, 200, { verified: true });
    }

    if (method === "GET" && pathname === "/v1/account/status") {
      return json(res, 200, { exists: true });
    }

    if (method === "GET" && (pathname === "/v1/account/devices" || pathname === "/v1/account/attached_clients")) {
      return json(res, 200, []);
    }

    if (method === "GET" && pathname === "/auth/login") {
      const returnTo = safeReturnTo(url.searchParams.get("return_to"), cfg.publicBaseUrl);
      if (cfg.devLogin) {
        return html(
          res,
          200,
          `<!doctype html><meta charset="utf-8"><title>Dev sign-in</title>
<body style="font:16px system-ui;max-width:32rem;margin:3rem auto">
<h1>Dev sign-in</h1>
<form method="post" action="/auth/dev">
  <input type="hidden" name="return_to" value="${escapeHtml(returnTo)}">
  <p><label>Email <input name="email" type="email" required value="dev@example.com"></label></p>
  <p><button type="submit">Sign in</button></p>
</form></body>`,
        );
      }

      const discovery = await discover(cfg.oidc.issuer);
      const state = randomHex(16);
      const nonce = randomB64url(16);
      const verifier = randomB64url(32);
      const challenge = pkceChallenge(verifier);
      store.createFlow({
        state,
        returnTo,
        nonce,
        verifier,
        createdAt: Date.now(),
        expiresAt: Date.now() + 10 * 60 * 1000,
      });
      const location = buildAuthorizeUrl(discovery, cfg, {
        state,
        nonce,
        codeChallenge: challenge,
      });
      return redirect(res, location, [
        cookie("fxa_flow", makeCookieValue(state, cfg.sessionSecret), {
          maxAge: 600,
          secure: cfg.secureCookies,
          sameSite: "Lax",
        }),
      ]);
    }

    if (method === "GET" && pathname === "/auth/callback") {
      const error = url.searchParams.get("error");
      if (error) {
        return text(res, 400, `OIDC error: ${error} ${url.searchParams.get("error_description") || ""}`);
      }
      const state = url.searchParams.get("state") || "";
      const code = url.searchParams.get("code") || "";
      const cookieState = readSignedCookie(req, "fxa_flow", cfg.sessionSecret);
      if (!state || !code || !cookieState || cookieState !== state) {
        return text(res, 400, "Invalid OIDC state");
      }
      const flow = store.getFlow(state);
      store.deleteFlow(state);
      if (!flow) return text(res, 400, "Expired OIDC flow");

      const discovery = await discover(cfg.oidc.issuer);
      const tokens = await exchangeCode(discovery, cfg, {
        code,
        codeVerifier: flow.verifier,
      });

      let claims;
      if (tokens.id_token) {
        claims = await verifyIdToken(discovery, cfg, tokens.id_token, {
          nonce: flow.nonce,
        });
        if (!claims.email && tokens.access_token) {
          const info = await fetchUserInfo(discovery, tokens.access_token).catch(() => null);
          if (info) claims = { ...claims, ...info };
        }
      } else {
        claims = await fetchUserInfo(discovery, tokens.access_token);
      }
      if (!claims || !claims.sub) return text(res, 400, "OIDC response had no subject");

      const account = accountForIdentity(
        store,
        cfg,
        cfg.oidc.issuer,
        claims.sub,
        claims.email || claims.preferred_username,
      );
      const session = store.createSession(account.uid, cfg.sessionTtl * 1000);

      return redirect(res, flow.returnTo, [
        sessionCookie(session.sid),
        cookie("fxa_flow", "", {
          maxAge: 0,
          secure: cfg.secureCookies,
          sameSite: "Lax",
        }),
      ]);
    }

    if (method === "POST" && pathname === "/auth/dev" && cfg.devLogin) {
      const body = parseBody(req, await readBody(req));
      const email = String(body.email || "").trim();
      if (!email.includes("@")) return text(res, 400, "email required");
      const account = accountForIdentity(store, cfg, "dev", email, email);
      const session = store.createSession(account.uid, cfg.sessionTtl * 1000);
      const returnTo = safeReturnTo(body.return_to, cfg.publicBaseUrl);
      return redirect(res, returnTo, [sessionCookie(session.sid)]);
    }

    if (method === "POST" && (pathname === "/auth/logout" || pathname === "/auth/signout")) {
      return logout(req, res);
    }
    if (method === "GET" && (pathname === "/auth/logout" || pathname === "/auth/signout")) {
      return logout(req, res);
    }

    return json(res, 404, { error: "not_found" });
  }

  function logout(req, res) {
    const sid = readSignedCookie(req, "fxa_session", cfg.sessionSecret);
    if (sid) store.deleteSession(sid);
    return redirect(res, "/", [clearSessionCookie()]);
  }

  const server = http.createServer((req, res) => {
    handle(req, res).catch((err) => {
      console.error("request failed", req.method, req.url, err);
      if (!res.headersSent) {
        json(res, 500, { error: "internal_error" });
      } else {
        res.end();
      }
    });
  });

  return { server, cfg, store, keys };
}

function escapeHtml(value) {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

const isMain =
  process.argv[1] &&
  path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);

if (isMain) {
  const cfg = loadConfig();
  const { server } = createApp(cfg);
  server.listen(cfg.port, cfg.host, () => {
    console.log(`fxa-shim listening on http://${cfg.host}:${cfg.port}`);
    console.log(`public: ${cfg.publicBaseUrl}`);
    console.log(`sync:   ${cfg.syncBaseUrl}`);
    console.log(`dev login: ${cfg.devLogin ? "on" : "off"}`);
  });
}
