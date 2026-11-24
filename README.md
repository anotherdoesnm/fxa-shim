# fxa-shim

A small **FxA-compatible OIDC bridge** for Firefox Sync. It lets Firefox sign in
with your own OIDC provider (Dex, Kanidm, Authelia, Keycloak, …) and use a
self-hosted [syncstorage-rs](https://github.com/mozilla-services/syncstorage-rs)
without a Mozilla account and without running the full Firefox Accounts stack.

> **Status: MVP / experimental.** It implements the subset of FxA needed for
> Firefox's `oauth_webchannel_v1` Sync flow. It is not audited, has no rate
> limiting. It supports two key modes: `server` (simple, `kB` on the server) and
> `e2e` (a separate Sync password, `kB` never leaves the browser). Use it on a
> homelab or a small trusted deployment, not as a public service yet.

## Why

Firefox does not speak generic OIDC for Sync. It speaks Mozilla Accounts (FxA):
a content page talks to the browser over WebChannel, the browser exchanges an
OAuth code for tokens and a `keys_jwe` blob, and only then does Sync start.
Pointing `identity.fxaccounts.autoconfig.uri` at an OIDC provider does not work;
the provider has to *be* FxA-compatible.

This project is that compatibility layer. It is deliberately much smaller than
FxA: OIDC login, the OAuth endpoints Firefox calls, scoped keys, profile, JWKS.

## Architecture

```
Firefox (desktop / Android / iOS)
  │
  ├── content page + WebChannel ──► fxa-shim  (accounts.example.com)
  │                                   ├── OIDC login (Dex/Kanidm/...)
  │                                   ├── /v1/oauth/token  → JWT + keys_jwe
  │                                   ├── /v1/profile
  │                                   └── /v1/jwks        (public key)
  │
  └── token server + storage ─────► syncstorage-rs (sync.example.com)
                                      └── verifies the JWT via fxa-shim's JWKS
```

`fxa-shim` never stores Sync data. It only manages accounts, OAuth codes and the
root key `kB` used to derive the scoped Sync key. Storage, quotas and Hawk
credentials are handled by `syncstorage-rs`.

## Quick start (tests only, no Firefox)

Requires Node.js 20+ (no npm dependencies).

```sh
cd fxa-shim
npm test
```

The tests cover JWE/ECDH-ES (including decryption with WebCrypto the way
Firefox does it), the scoped-key shape Firefox validates, RS256 tokens, the
full dev-login → authorize → token flow, PKCE/single-use codes, state
persistence, and a complete OIDC login against a mock provider.

## Run with Docker (shim + syncstorage + Postgres)

```sh
cp .env.example .env
# edit .env: PUBLIC_BASE_URL, SYNC_BASE_URL, SESSION_SECRET, SYNC_MASTER_SECRET,
# and either OIDC_* or DEV_LOGIN=1
docker compose up -d --build
```

The published syncstorage images are `linux/amd64`; on ARM hosts Docker must
emulate them. For a local, no-OIDC smoke test set these in `.env`:

```ini
PUBLIC_BASE_URL=http://localhost:8000
SYNC_BASE_URL=http://localhost:8001
DEV_LOGIN=1
```

Then configure Firefox (desktop):

1. `about:config`
2. `identity.fxaccounts.autoconfig.uri` = `http://localhost:8000`
3. `identity.fxaccounts.allowHttp` = `true` (only for local HTTP; use HTTPS in
   production)
4. Restart Firefox, open **Settings → Sync**, sign in. The sign-in page is served
   by the shim; use the dev form.

Firefox reads the rest from `/.well-known/fxa-client-configuration`:

- auth/oauth/profile: `PUBLIC_BASE_URL` (+ `/v1`)
- token server: `SYNC_BASE_URL` (+ `/1.0/sync/1.5`)

On Android: **Settings → About Firefox**, tap the logo 5 times, then
**Sync Debug → Custom Mozilla account server** = your `PUBLIC_BASE_URL`. Leave
"Custom Sync server" empty: it is discovered from the account server. Android
builds generally require HTTPS with a trusted certificate; use a domain and a
reverse proxy, and make sure `PUBLIC_BASE_URL`, `SYNC_BASE_URL` and
`SYNC_NODE_URL` are reachable from the phone (a LAN IP works for `http://` only
where the browser allows it). On a phone, set `SYNC_NODE_URL` to the address the
phone can reach, not `localhost`.

On iOS: **Settings → About**, tap the version 5 times, then
**Advanced Sync Settings → Use Custom FxA Content Server** = your
`PUBLIC_BASE_URL`.

## OIDC provider setup

Register a confidential client with redirect URI:

```
${PUBLIC_BASE_URL}/auth/callback
```

Scopes: `openid email profile`. Then set:

```ini
OIDC_ISSUER=https://id.example.com
OIDC_CLIENT_ID=fxa-shim
OIDC_CLIENT_SECRET=...
```

Dex example:

```yaml
staticClients:
  - id: fxa-shim
    secret: <random>
    name: Firefox Sync bridge
    redirectURIs:
      - https://accounts.example.com/auth/callback
```

- Dex supports PKCE and `client_secret_post`; defaults work.
- Kanidm uses a per-client issuer URL (the `issuer` from its discovery
  document). Set `OIDC_ISSUER` to exactly that value. If your deployment
  rejects PKCE, set `OIDC_PKCE=0`; if it wants HTTP Basic at the token endpoint,
  set `OIDC_TOKEN_AUTH=basic`.
- The ID token must contain `sub` and preferably `email`. If there is no
  `id_token`, the shim falls back to the `userinfo` endpoint. The nonce is
  checked by default; set `OIDC_REQUIRE_NONCE=0` only for an IdP that does not
  echo it.

## syncstorage-rs configuration

The published image used by `docker-compose.yml` is
`ghcr.io/mozilla-services/syncstorage-rs/syncserver-postgres` (linux/amd64).
The important settings:

```ini
SYNC_MASTER_SECRET=<long random string>
SYNC_SYNCSTORAGE__DATABASE_URL=postgres://...
SYNC_TOKENSERVER__DATABASE_URL=postgres://...
SYNC_TOKENSERVER__ENABLED=true
SYNC_TOKENSERVER__RUN_MIGRATIONS=true
SYNC_TOKENSERVER__FXA_OAUTH_SERVER_URL=http://fxa-shim:8000
SYNC_TOKENSERVER__FXA_EMAIL_DOMAIN=accounts.example.com
SYNC_TOKENSERVER__INIT_NODE_URL=https://sync.example.com
```

`FXA_OAUTH_SERVER_URL` must be reachable *from the syncstorage container* and
must serve `/v1/jwks`. `TOKEN_ISSUER` in the shim must match it (the JWT `iss`
claim). `INIT_NODE_URL` is the public URL clients use for storage.

Firefox appends `/1.0/sync/1.5` to `SYNC_BASE_URL`; that is the tokenserver
endpoint. syncstorage then returns a node URL and Hawk credentials for
`/1.5/...` storage requests.

If you prefer a different database backend, use the `syncserver-mysql` image and
the matching `SYNC_*_DATABASE_URL`. The rest of the configuration is unchanged.

## What is implemented

- `GET /.well-known/fxa-client-configuration`
- `GET /.well-known/openid-configuration` (Android fxa-client fetches this too)
- `GET /authorization` (OAuth web-content entry point used by Android)
- WebChannel content page (`account_updates` channel) with
  `fxaccounts:fxa_status`, `fxaccounts:can_link_account`,
  `fxaccounts:login`, `fxaccounts:oauth_login`
- `POST /v1/oauth/token` (`authorization_code`, `refresh_token`) returning
  `access_token` (RS256 JWT), `refresh_token`, `keys_jwe`
- `POST /v1/oauth/destroy`
- `GET /v1/profile`
- `GET /v1/jwks`
- `POST /v1/verify` (fallback for syncstorage's remote token verification)
- `POST /v1/introspect`
- `GET /v1/session/status`, `/v1/session/verify`, `/v1/account/status`
- Scoped sync key: `HKDF(kB, "identity.mozilla.com/picl/v1/oldsync", 64)`,
  delivered as JWE `ECDH-ES` + `A256GCM` to Firefox's `keys_jwk`
- OIDC authorization-code login with PKCE and nonce, ID-token verification
  (RS256/ES256), userinfo fallback
- Dev passwordless login (`DEV_LOGIN=1`) for local testing

Not implemented: password change, account deletion, device management, pairing,
send-tab push, legacy BrowserID/onepw login, multi-account UI, Hawk signature
validation on the token endpoint, rate limiting, CSRF tokens, multi-instance
storage, migrations between `kB` values.

## Testing with a real Firefox

Use a throwaway profile so you do not touch your real Sync data:

```sh
firefox --no-remote --profile /tmp/fxa-test-profile
```

Set `identity.fxaccounts.autoconfig.uri` (and `identity.fxaccounts.allowHttp`
for local HTTP), restart, then sign in from **Settings → Sync**. After the
"Connect Firefox" button, watch:

- `about:sync-log` for Sync errors;
- the Browser Console (`Ctrl+Shift+J`) for WebChannel messages and any
  `fxaccounts:*` errors.

If Firefox keeps opening the sign-in page, check that the origin in
`identity.fxaccounts.remote.root` is exactly the URL you opened, that the page
is not behind a path prefix, and that the shim can reach
`PUBLIC_BASE_URL/.well-known/fxa-client-configuration`.

## Key modes

`KEY_MODE=server` (default) generates `kB` on the server. It is the simplest
mode, but the server can decrypt Synced data and a backup leak exposes it.

`KEY_MODE=e2e` requires a **separate Sync password** on the content page. The
browser derives `unwrapBKey`/`authHash` with PBKDF2, stores only
`wrapkB = kB XOR unwrapBKey` and the verifier on the server, and computes
`keys_jwe` itself. The Sync password is never sent to the server and is not the
Dex/YunoHost password.

- New accounts: the browser generates `kB`, the server never sees it.
- Existing `server` accounts: the page offers a one-time migration, re-wraps the
  existing `kB`, and the server deletes `kB` afterwards.
- Losing the Sync password means losing the Sync data. There is no recovery.
- Old backups that predate the migration may still contain `kB`; remove them
  after migrating (or keep them only if you accept that risk).

## Security

This MVP is intentionally simple, and that has consequences:

- **`KEY_MODE=server` stores `kB` on the server.** The shim can derive the Sync
  key and therefore decrypt Synced data. Use `KEY_MODE=e2e` for the
  zero-knowledge model; then only `wrapkB` and a password verifier are stored.
- **Passwords are declined by default.** `DECLINE_PASSWORDS=1` tells Firefox not
  to sync the `passwords` engine. Given the previous point, this is the sane
  default. Use Vaultwarden/Bitwarden for passwords. Setting
  `DECLINE_PASSWORDS=0` means your server can decrypt them.
- **Hawk is not validated on `/v1/oauth/token`.** The endpoint relies on the
  single-use authorization code and PKCE. Keep it behind TLS and a reverse proxy
  with rate limits; do not expose it to untrusted networks.
- **State is a JSON file.** `data/state.json` contains accounts, `kB`, sessions
  and codes; `data/rsa-key.pem` signs access tokens. Back both up with mode
  `0600`. Losing `state.json` means losing `kB` and therefore the Synced data.
  Losing only `rsa-key.pem` invalidates access tokens until restart/re-login.
- **No rate limiting or CSRF middleware.** SameSite=Lax cookies and the OIDC
  state check are the current protections. Add a reverse proxy (Caddy/Nginx)
  with request limits before exposing it.
- **Use HTTPS.** For local development only, Firefox's
  `identity.fxaccounts.allowHttp` allows plain HTTP. Mobile builds generally
  require a trusted HTTPS certificate.

## Development

```sh
DEV_LOGIN=1 DATA_FILE=./data/dev.json SESSION_SECRET=dev npm start
# http://localhost:8000/
```

Useful checks:

```sh
node --check src/*.js
npm test
curl -s http://localhost:8000/.well-known/fxa-client-configuration | jq
```

The RSA key is generated on first start and persisted next to the data file.

## Roadmap

1. SQLite/Postgres store and a proper migration path.
2. Hawk validation for `/v1/oauth/token` (derive Hawk creds from `sessionToken`).
3. ~~E2E mode~~ — implemented (`KEY_MODE=e2e`).
4. Web import/export page (client-side decryption), so mobile users can migrate
   passwords and bookmarks without a desktop.
5. Yunohost/SelfPrivacy packaging, reverse-proxy examples, rate limits.
6. Compatibility tests against real Firefox releases (desktop + Android).

## Deployment recipes

- [YunoHost (nexus/doesnmlab recipe)](deploy/YUNOHOST.md) — Dex, `syncserver-rs`, systemd, reverse proxy, Traefik.
- [`deploy/fxa-shim.service`](deploy/fxa-shim.service), [`deploy/fxa-shim.env.example`](deploy/fxa-shim.env.example), [`deploy/traefik-fxa.yml`](deploy/traefik-fxa.yml).

## License

MIT. See [LICENSE](LICENSE).
