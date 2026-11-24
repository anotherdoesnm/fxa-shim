import path from "node:path";
import process from "node:process";

function trimSlash(value) {
  return String(value).replace(/\/+$/, "");
}

function boolean(value, fallback) {
  if (value === undefined) return fallback;
  return value === "1" || value === "true" || value === "yes";
}

/**
 * Load configuration from environment variables.
 *
 * The public base URL is the single origin that serves both the content page
 * and the FxA API (`/v1/...`). The sync base URL points at syncstorage-rs,
 * which owns the tokenserver and the storage API.
 */
export function loadConfig(env = process.env) {
  const publicBaseUrl = trimSlash(env.PUBLIC_BASE_URL || "http://localhost:8000");
  const syncBaseUrl = trimSlash(env.SYNC_BASE_URL || "http://localhost:8001");

  const cfg = {
    host: env.HOST || "0.0.0.0",
    port: Number(env.PORT || 8000),
    publicBaseUrl,
    syncBaseUrl,
    // The issuer written into access tokens. In Docker it can be the internal
    // service URL that syncstorage uses to fetch /v1/jwks.
    tokenIssuer: trimSlash(env.TOKEN_ISSUER || publicBaseUrl),
    dataFile: env.DATA_FILE || path.resolve("data/state.json"),
    sessionSecret: env.SESSION_SECRET || "dev-insecure-session-secret-change-me",
    secureCookies: publicBaseUrl.startsWith("https://"),
    devLogin: boolean(env.DEV_LOGIN, false),
    keyMode: env.KEY_MODE === "e2e" ? "e2e" : "server",
    declinePasswords: boolean(env.DECLINE_PASSWORDS, true),
    declineAddresses: boolean(env.DECLINE_ADDRESSES, true),
    declineCreditCards: boolean(env.DECLINE_CREDITCARDS, true),
    accessTokenTtl: Number(env.ACCESS_TOKEN_TTL || 3600),
    codeTtl: Number(env.CODE_TTL || 300),
    sessionTtl: Number(env.SESSION_TTL || 60 * 60 * 24 * 30),
    oidc: {
      issuer: trimSlash(env.OIDC_ISSUER || ""),
      clientId: env.OIDC_CLIENT_ID || "",
      clientSecret: env.OIDC_CLIENT_SECRET || "",
      redirectUri: env.OIDC_REDIRECT_URI || `${publicBaseUrl}/auth/callback`,
      scopes: env.OIDC_SCOPES || "openid email profile",
      usePkce: boolean(env.OIDC_PKCE, true),
      requireNonce: boolean(env.OIDC_REQUIRE_NONCE, true),
      tokenAuth: env.OIDC_TOKEN_AUTH || "post", // "post" or "basic"
    },
  };

  if (!cfg.devLogin && (!cfg.oidc.issuer || !cfg.oidc.clientId)) {
    throw new Error(
      "OIDC_ISSUER and OIDC_CLIENT_ID are required unless DEV_LOGIN=1",
    );
  }
  if (
    !cfg.devLogin &&
    (cfg.sessionSecret === "dev-insecure-session-secret-change-me" ||
      cfg.sessionSecret.startsWith("change-me"))
  ) {
    throw new Error("SESSION_SECRET must be set to a random value in production");
  }
  return cfg;
}
