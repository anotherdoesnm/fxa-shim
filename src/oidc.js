import crypto from "node:crypto";

const discoveryCache = new Map();
const jwksCache = new Map();
const CACHE_TTL_MS = 5 * 60 * 1000;

async function fetchJson(url, options = {}) {
  const response = await fetch(url, {
    ...options,
    signal: AbortSignal.timeout(10_000),
    headers: {
      accept: "application/json",
      ...(options.headers || {}),
    },
  });
  const text = await response.text();
  let body;
  try {
    body = text ? JSON.parse(text) : null;
  } catch {
    body = null;
  }
  if (!response.ok) {
    const detail = body ? JSON.stringify(body) : text.slice(0, 500);
    throw new Error(`OIDC request to ${url} failed: ${response.status} ${detail}`);
  }
  return body;
}

export async function discover(issuer) {
  const cached = discoveryCache.get(issuer);
  if (cached && cached.expiresAt > Date.now()) return cached.value;
  const value = await fetchJson(
    `${issuer.replace(/\/+$/, "")}/.well-known/openid-configuration`,
  );
  if (!value || !value.authorization_endpoint || !value.token_endpoint) {
    throw new Error("OIDC discovery document is missing required endpoints");
  }
  discoveryCache.set(issuer, { value, expiresAt: Date.now() + CACHE_TTL_MS });
  return value;
}

export function buildAuthorizeUrl(discovery, cfg, { state, nonce, codeChallenge }) {
  const url = new URL(discovery.authorization_endpoint);
  url.searchParams.set("client_id", cfg.oidc.clientId);
  url.searchParams.set("redirect_uri", cfg.oidc.redirectUri);
  url.searchParams.set("response_type", "code");
  url.searchParams.set("scope", cfg.oidc.scopes);
  url.searchParams.set("state", state);
  url.searchParams.set("nonce", nonce);
  if (cfg.oidc.usePkce) {
    url.searchParams.set("code_challenge_method", "S256");
    url.searchParams.set("code_challenge", codeChallenge);
  }
  return url.href;
}

export async function exchangeCode(discovery, cfg, { code, codeVerifier }) {
  const body = new URLSearchParams();
  body.set("grant_type", "authorization_code");
  body.set("code", code);
  body.set("redirect_uri", cfg.oidc.redirectUri);
  body.set("client_id", cfg.oidc.clientId);
  if (cfg.oidc.usePkce && codeVerifier) body.set("code_verifier", codeVerifier);

  const headers = {
    "content-type": "application/x-www-form-urlencoded",
    accept: "application/json",
  };
  if (cfg.oidc.tokenAuth === "basic" && cfg.oidc.clientSecret) {
    headers.authorization =
      "Basic " +
      Buffer.from(
        `${cfg.oidc.clientId}:${cfg.oidc.clientSecret}`,
        "utf8",
      ).toString("base64");
  } else if (cfg.oidc.clientSecret) {
    body.set("client_secret", cfg.oidc.clientSecret);
  }

  return fetchJson(discovery.token_endpoint, {
    method: "POST",
    headers,
    body,
  });
}

async function getJwks(jwksUri) {
  const cached = jwksCache.get(jwksUri);
  if (cached && cached.expiresAt > Date.now()) return cached.value;
  const value = await fetchJson(jwksUri);
  if (!value || !Array.isArray(value.keys)) {
    throw new Error("OIDC JWKS document has no keys");
  }
  jwksCache.set(jwksUri, { value, expiresAt: Date.now() + CACHE_TTL_MS });
  return value;
}

function verifySignature(alg, data, key, signature) {
  if (alg === "RS256") {
    return crypto.verify("sha256", data, key, signature);
  }
  if (alg === "ES256") {
    return crypto.verify(
      "sha256",
      data,
      { key, dsaEncoding: "ieee-p1363" },
      signature,
    );
  }
  throw new Error(`unsupported ID token alg: ${alg}`);
}

export async function verifyIdToken(discovery, cfg, idToken, { nonce } = {}) {
  const parts = String(idToken).split(".");
  if (parts.length !== 3) throw new Error("malformed ID token");
  const [headerB64, payloadB64, signatureB64] = parts;
  const header = JSON.parse(
    Buffer.from(headerB64, "base64url").toString("utf8"),
  );
  const payload = JSON.parse(
    Buffer.from(payloadB64, "base64url").toString("utf8"),
  );

  const jwks = await getJwks(discovery.jwks_uri);
  const candidates = header.kid
    ? jwks.keys.filter((candidate) => candidate.kid === header.kid)
    : jwks.keys;
  if (!candidates.length) throw new Error("ID token signing key not found");

  let verified = false;
  for (const jwk of candidates) {
    try {
      const key = crypto.createPublicKey({ key: jwk, format: "jwk" });
      if (
        verifySignature(
          header.alg,
          Buffer.from(`${headerB64}.${payloadB64}`),
          key,
          Buffer.from(signatureB64, "base64url"),
        )
      ) {
        verified = true;
        break;
      }
    } catch {
      // Try the next key.
    }
  }
  if (!verified) throw new Error("invalid ID token signature");

  const now = Math.floor(Date.now() / 1000);
  if (typeof payload.exp !== "number" || payload.exp + 60 < now) {
    throw new Error("ID token expired");
  }
  if (payload.iss !== discovery.issuer) {
    throw new Error("ID token issuer mismatch");
  }
  const audiences = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
  if (!audiences.includes(cfg.oidc.clientId)) {
    throw new Error("ID token audience mismatch");
  }
  if (nonce && cfg.oidc.requireNonce !== false && payload.nonce !== nonce) {
    throw new Error("ID token nonce mismatch");
  }
  return payload;
}

export async function fetchUserInfo(discovery, accessToken) {
  if (!discovery.userinfo_endpoint) return null;
  return fetchJson(discovery.userinfo_endpoint, {
    headers: { authorization: `Bearer ${accessToken}` },
  });
}
