# Deploying fxa-shim on YunoHost

This is the recipe used for `accounts.doesnmlab.xyz` (fxa-shim) and
`sync.doesnmlab.xyz` (syncstorage-rs) on the YunoHost container `nexus`
(YunoHost 12.1, Debian bookworm). Adjust names.

The setup assumes:

- YunoHost + a working `dex` app (LDAP connector) for OIDC;
- public DNS for `accounts.` and `sync.`;
- a reverse proxy in front of YunoHost that terminates TLS (Traefik here).

## 1. Add the domains

```sh
yunohost domain add accounts.example.com
yunohost domain add sync.example.com
```

If the reverse proxy terminates TLS (as Traefik does here), YunoHost's own
self-signed certificate is enough for the internal hop. If YunoHost must serve
TLS directly, install a Let's Encrypt certificate afterwards:

```sh
yunohost domain cert install accounts.example.com sync.example.com
```

## 2. Install syncstorage-rs

```sh
yunohost app install syncserver-rs -a "domain=sync.example.com" -f
```

This installs PostgreSQL, a venv and the `syncserver` binary, and creates the
`syncserver-rs` systemd service. Then point its tokenserver at the shim:

```sh
sed -i 's|^tokenserver.fxa_email_domain = .*|tokenserver.fxa_email_domain = "accounts.example.com"|' /var/www/syncserver-rs/config.toml
sed -i 's|^tokenserver.fxa_oauth_server_url = .*|tokenserver.fxa_oauth_server_url = "http://127.0.0.1:8000"|' /var/www/syncserver-rs/config.toml
systemctl restart syncserver-rs
```

`fxa_oauth_server_url` must be reachable *from the syncserver process* and
serve `/v1/jwks`. The shim's `TOKEN_ISSUER` must be the same URL, because the
tokenserver matches JWTs against it.

> On `yunohost app upgrade syncserver-rs`, these two lines may be reset. Re-apply
> them (or keep a patched template) after upgrading.

Check:

```sh
curl -s http://127.0.0.1:11864/__heartbeat__   # port from /etc/yunohost/apps/syncserver-rs/settings.yml
```

## 3. Install Node.js and fxa-shim

No `apt install nodejs` is required; use the official static build:

```sh
NODE_VERSION=22.23.4
mkdir -p /opt/fxa-shim/node
cd /tmp
curl -fsSLO "https://nodejs.org/dist/v${NODE_VERSION}/node-v${NODE_VERSION}-linux-x64.tar.xz"
curl -fsSLO "https://nodejs.org/dist/v${NODE_VERSION}/SHASUMS256.txt"
grep " node-v${NODE_VERSION}-linux-x64.tar.xz$" SHASUMS256.txt | sha256sum -c -
tar -xJf "node-v${NODE_VERSION}-linux-x64.tar.xz" -C /opt/fxa-shim/node --strip-components=1
```

Create the service user and copy the app:

```sh
id fxa-shim >/dev/null 2>&1 || useradd --system --home /var/lib/fxa-shim --shell /usr/sbin/nologin fxa-shim
mkdir -p /opt/fxa-shim/app /var/lib/fxa-shim /etc/fxa-shim
tar -xzf fxa-shim.tar.gz -C /opt/fxa-shim/app --strip-components=1
chown -R fxa-shim:fxa-shim /opt/fxa-shim/app /var/lib/fxa-shim
```

Create `/etc/fxa-shim/env` from
[`fxa-shim.env.example`](fxa-shim.env.example), then install the unit:

```sh
cp deploy/fxa-shim.service /etc/systemd/system/fxa-shim.service
systemctl daemon-reload
systemctl enable --now fxa-shim
curl -s http://127.0.0.1:8000/healthz
```

The important values are:

```ini
PUBLIC_BASE_URL=https://accounts.example.com
SYNC_BASE_URL=https://sync.example.com
TOKEN_ISSUER=http://127.0.0.1:8000
KEY_MODE=e2e
OIDC_ISSUER=https://nexus.example.com/dex
OIDC_CLIENT_ID=fxa-shim
OIDC_CLIENT_SECRET=<random>
OIDC_REDIRECT_URI=https://accounts.example.com/auth/callback
```

## 4. Register the Dex client

YunoHost's Dex app stores additional clients in `/var/www/dex/config.yaml.d/`.
Use its helper (the callback is passed without `https://`):

```sh
SECRET=$(openssl rand -hex 32)
/var/www/dex/add_config.sh fxa-shim fxa-shim accounts.example.com/auth/callback "$SECRET"
systemctl restart dex
```

Put the same `$SECRET` into `OIDC_CLIENT_SECRET` in `/etc/fxa-shim/env`, then
`systemctl restart fxa-shim`.

Verify:

```sh
grep -A5 'id: fxa-shim' /var/www/dex/config.yaml
curl -s https://nexus.example.com/dex/.well-known/openid-configuration | head
```

## 5. Publish the accounts domain

YunoHost's `reverseproxy` catalog app puts nginx in front of the local shim:

```sh
yunohost app install reverseproxy \
  -a "domain=accounts.example.com&path=/&proxy_path=http://127.0.0.1:8000&init_main_permission=visitors" \
  -f
```

## 6. Traefik (if used)

If a Traefik instance on another host terminates TLS, add explicit routers for
the two names; the wildcard fallback alone does not get per-name certificates.
See [`traefik-fxa.yml`](traefik-fxa.yml). Copy it to Traefik's file provider
directory (e.g. `/root/traefik/fxa.yml`). The certificates are requested on
demand by the configured resolver.

## 7. Verify

```sh
# public config (replace the --resolve with normal DNS if needed)
curl -s https://accounts.example.com/.well-known/fxa-client-configuration

# page
curl -s https://accounts.example.com/ | grep -o 'account_updates'

# syncstorage
curl -s https://sync.example.com/__heartbeat__

# OIDC redirect
curl -sI 'https://accounts.example.com/auth/login?return_to=/' | grep -i '^location:'
```

The final redirect should point at your Dex `/auth` endpoint with
`client_id=fxa-shim` and `redirect_uri=https://accounts.example.com/auth/callback`.

## 8. Firefox

Desktop:

```
identity.fxaccounts.autoconfig.uri = https://accounts.example.com
```

Android: **Settings → About Firefox**, tap the logo 5 times, **Sync Debug →
Custom Mozilla account server** = `https://accounts.example.com`. Leave
"Custom Sync server" empty; it is discovered from the account server.

iOS: **Settings → About**, tap the version 5 times, **Advanced Sync Settings →
Use Custom FxA Content Server** = `https://accounts.example.com`.

For local HTTP testing, desktop also needs `identity.fxaccounts.allowHttp=true`;
Android generally requires HTTPS.

## 9. Backups

The shim's `state.json` contains each account's `kB`; losing it means losing the
ability to decrypt Sync data. Back it up outside the container:

```sh
mkdir -p /var/backups/fxa-shim
cat >/usr/local/sbin/fxa-shim-backup.sh <<'EOF'
#!/bin/sh
set -eu
umask 077
mkdir -p /var/backups/fxa-shim
tar -czf /var/backups/fxa-shim/fxa-shim-$(date +%F).tgz -C /var/lib/fxa-shim .
find /var/backups/fxa-shim -type f -mtime +30 -delete
EOF
chmod 700 /usr/local/sbin/fxa-shim-backup.sh
echo '0 4 * * * root /usr/local/sbin/fxa-shim-backup.sh' > /etc/cron.d/fxa-shim-backup
/usr/local/sbin/fxa-shim-backup.sh
```

Also back up the syncstorage app/DB:

```sh
yunohost backup create --apps syncserver-rs
```

## 10. Caveats

- This is an MVP. With `KEY_MODE=server`, `kB` is stored server-side and the
  server can decrypt Sync data. With `KEY_MODE=e2e`, only `wrapkB` and an
  `authHash` are stored; the Sync password is entered in the browser. Existing
  accounts are migrated on the next Connect. `DECLINE_PASSWORDS=1` keeps the
  passwords engine out of Sync.
- The shim does not validate Hawk on `/v1/oauth/token`; the single-use code and
  PKCE are the gate. Keep it behind TLS and rate limits.
- State is a single JSON file and a single service process; no HA/multi-instance.
- The `syncserver-rs` app upgrade may overwrite `config.toml`; re-apply the two
  `tokenserver.fxa_*` lines.
- Keep `fxa-shim`, `syncserver-rs` and `dex` running; `systemctl status` and
  `journalctl -u fxa-shim` are the first places to look.
