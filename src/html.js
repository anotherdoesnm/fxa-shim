export function renderPage() {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Firefox Sync bridge</title>
<style>
  :root { color-scheme: light dark; }
  body { font: 16px/1.5 system-ui, -apple-system, Segoe UI, sans-serif; max-width: 44rem; margin: 3rem auto; padding: 0 1.2rem; }
  h1 { font-size: 1.4rem; margin-bottom: .25rem; }
  p.lead { margin-top: 0; opacity: .75; }
  button, .button { display: inline-block; font: inherit; padding: .6rem 1rem; border-radius: .5rem; border: 1px solid #8888; background: #4b6cf4; color: #fff; cursor: pointer; text-decoration: none; }
  button:disabled { opacity: .55; cursor: default; }
  .secondary { background: transparent; color: inherit; }
  .card { border: 1px solid #8884; border-radius: .75rem; padding: 1rem 1.2rem; margin: 1rem 0; }
  code, pre { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: .85rem; }
  pre { white-space: pre-wrap; word-break: break-word; background: #8881; padding: .75rem; border-radius: .5rem; }
  .muted { opacity: .7; font-size: .9rem; }
  .row { display: flex; gap: .75rem; flex-wrap: wrap; align-items: center; }
  [hidden] { display: none !important; }
</style>
</head>
<body>
  <h1>Firefox Sync bridge</h1>
  <p class="lead">Sign in with your identity provider, then connect Firefox.</p>

  <div id="status" class="card">Loading…</div>

  <div id="login" class="card" hidden>
    <p>You are not signed in yet.</p>
    <a id="login-link" class="button" href="/auth/login">Sign in</a>
  </div>

  <div id="account" class="card" hidden>
    <p>Signed in as <strong id="account-email"></strong>.</p>
    <div class="row">
      <button id="connect" hidden>Connect Firefox</button>
      <a class="button secondary" href="/auth/logout">Sign out</a>
    </div>
    <p id="flow-hint" class="muted" hidden></p>
  </div>

  <div id="key-card" class="card" hidden>
    <h2 id="key-title" style="font-size:1.1rem;margin-top:0">Sync password</h2>
    <p id="key-hint" class="muted"></p>
    <p><input id="sync-password" type="password" placeholder="Sync password" autocomplete="new-password"
      style="width:100%;padding:.6rem;border-radius:.4rem;border:1px solid #8886;background:transparent;color:inherit"></p>
    <p id="confirm-row"><input id="sync-password2" type="password" placeholder="Repeat sync password" autocomplete="new-password"
      style="width:100%;padding:.6rem;border-radius:.4rem;border:1px solid #8886;background:transparent;color:inherit"></p>
    <div class="row"><button id="key-submit">Set password</button></div>
  </div>

  <details class="card" id="details" hidden>
    <summary>Protocol details</summary>
    <pre id="details-body"></pre>
  </details>

<script type="module">
import {
  deriveMaterial,
  makeKeysJwe,
  hexToBytes,
  bytesToHex,
  randomBytes,
  xor
} from '/client-crypto.js';

(function () {
  'use strict';

  var params = new URLSearchParams(window.location.search);
  var flow = {
    client_id: params.get('client_id'),
    scope: params.get('scope'),
    state: params.get('state'),
    code_challenge: params.get('code_challenge'),
    code_challenge_method: params.get('code_challenge_method') || 'S256',
    keys_jwk: params.get('keys_jwk'),
    service: params.get('service') || 'sync',
    context: params.get('context') || ''
  };
  var hasFlow = !!(flow.client_id && flow.state && flow.code_challenge);
  var channelId = 'account_updates';
  var pending = new Map();
  var session = null;
  var kB = null;
  var keyReady = false;

  var statusEl = document.getElementById('status');
  var loginEl = document.getElementById('login');
  var loginLink = document.getElementById('login-link');
  var accountEl = document.getElementById('account');
  var accountEmail = document.getElementById('account-email');
  var connectEl = document.getElementById('connect');
  var flowHint = document.getElementById('flow-hint');
  var detailsEl = document.getElementById('details');
  var detailsBody = document.getElementById('details-body');
  var keyCard = document.getElementById('key-card');
  var keyTitle = document.getElementById('key-title');
  var keyHint = document.getElementById('key-hint');
  var keySubmit = document.getElementById('key-submit');
  var passwordEl = document.getElementById('sync-password');
  var password2El = document.getElementById('sync-password2');
  var confirmRow = document.getElementById('confirm-row');

  function setStatus(text) { statusEl.textContent = text; }

  function b64urlId(bytes) {
    var binary = '';
    for (var i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
    return btoa(binary).replace(/\\+/g, '-').replace(/\\//g, '_').replace(/=+$/, '');
  }

  function randomId() {
    var bytes = new Uint8Array(9);
    crypto.getRandomValues(bytes);
    return b64urlId(bytes);
  }

  function send(command, data, messageId) {
    var detail = { id: channelId, message: { command: command, data: data, messageId: messageId } };
    var isIOS = /fxios/i.test(navigator.userAgent);
    window.dispatchEvent(new CustomEvent('WebChannelMessageToChrome', {
      detail: isIOS ? detail : JSON.stringify(detail)
    }));
  }

  function request(command, data, timeoutMs) {
    return new Promise(function (resolve, reject) {
      var id = randomId();
      var timer = setTimeout(function () {
        if (pending.delete(id)) reject(new Error('timeout waiting for ' + command));
      }, timeoutMs || 5000);
      pending.set(id, function (value) { clearTimeout(timer); resolve(value); });
      send(command, data, id);
    });
  }

  window.addEventListener('WebChannelMessageToContent', function (event) {
    var raw = event.detail;
    var parsed;
    try { parsed = typeof raw === 'string' ? JSON.parse(raw) : raw; } catch (e) { return; }
    var msg = parsed && parsed.message ? parsed.message : parsed;
    if (!msg || !msg.messageId) return;
    var cb = pending.get(msg.messageId);
    if (cb) { pending.delete(msg.messageId); cb(msg.data || {}); }
  });

  function salt() {
    return String(session.uid || '') + '|' + String(session.email || '');
  }

  function needKeySetup() {
    return !!(session && session.loggedIn && session.keyMode === 'e2e' && !keyReady);
  }

  function render() {
    if (!session || !session.loggedIn) {
      loginEl.hidden = false;
      accountEl.hidden = true;
      keyCard.hidden = true;
      loginLink.href = '/auth/login?return_to=' + encodeURIComponent(window.location.href);
      setStatus(hasFlow ? 'Sign in to connect Firefox.' : 'Sign in to manage your Sync account.');
      return;
    }

    loginEl.hidden = true;
    accountEl.hidden = false;
    accountEmail.textContent = session.email || session.uid;
    detailsEl.hidden = false;
    detailsBody.textContent = JSON.stringify({
      uid: session.uid,
      email: session.email,
      service: flow.service,
      scope: flow.scope,
      keys: !!flow.keys_jwk,
      keyMode: session.keyMode,
      accountKeyMode: session.mode,
      declinedEngines: session.declinedEngines || []
    }, null, 2);

    var needsKeys = needKeySetup();
    keyCard.hidden = !needsKeys;
    connectEl.hidden = !hasFlow || needsKeys;
    flowHint.hidden = !hasFlow;

    if (needsKeys) {
      var accountE2E = session.mode === 'e2e';
      if (accountE2E && session.hasKeys) {
        keyTitle.textContent = 'Enter your Sync password';
        keyHint.textContent = 'This password decrypts your Sync keys in the browser. It is not sent to the server.';
        confirmRow.hidden = true;
        keySubmit.textContent = 'Unlock';
        passwordEl.autocomplete = 'current-password';
      } else {
        keyTitle.textContent = 'Set a Sync password';
        keyHint.textContent = (session.mode === 'server')
          ? 'Existing Sync data will be re-wrapped with this password. It is not re-uploaded; the server stops holding the key.'
          : 'This password encrypts your Sync keys. It is not sent to the server. Store it safely: there is no recovery.';
        confirmRow.hidden = false;
        keySubmit.textContent = 'Set password';
        passwordEl.autocomplete = 'new-password';
      }
      setStatus('Sync password required before connecting Firefox.');
      return;
    }

    if (session.keyMode === 'e2e') {
      flowHint.textContent = 'Firefox is requesting Sync access with browser-held keys.';
    } else {
      flowHint.textContent = 'Firefox is requesting Sync access with server-held keys.';
    }
    setStatus(hasFlow ? 'Ready to connect Firefox.' : 'Signed in.');
  }

  keySubmit.addEventListener('click', async function () {
    if (!session || !session.loggedIn) return;
    var password = passwordEl.value || '';
    var accountE2E = session.mode === 'e2e';
    var unlocking = accountE2E && session.hasKeys;

    if (!password) { setStatus('Enter the Sync password.'); return; }
    if (!unlocking && password.length < 8) {
      setStatus('Use at least 8 characters for the Sync password.');
      return;
    }
    if (!unlocking && password !== (password2El.value || '')) {
      setStatus('The Sync passwords do not match.');
      return;
    }

    keySubmit.disabled = true;
    setStatus(unlocking ? 'Deriving key…' : 'Setting the Sync password…');
    try {
      var material = await deriveMaterial(password, salt());
      if (unlocking) {
        var unlockResponse = await fetch('/api/keys/unlock', {
          method: 'POST',
          credentials: 'same-origin',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ authHash: bytesToHex(material.authHash) })
        });
        var unlockText = await unlockResponse.text();
        if (!unlockResponse.ok) throw new Error(unlockText || ('HTTP ' + unlockResponse.status));
        var unlocked = JSON.parse(unlockText);
        kB = xor(hexToBytes(unlocked.wrapkB), material.unwrapBKey);
      } else {
        var keyBytes;
        if (session.mode === 'server' && session.hasKeys) {
          var migrationResponse = await fetch('/api/keys/migration-kb', { credentials: 'same-origin' });
          var migrationText = await migrationResponse.text();
          if (!migrationResponse.ok) throw new Error(migrationText || ('HTTP ' + migrationResponse.status));
          keyBytes = hexToBytes(JSON.parse(migrationText).kB);
        } else {
          keyBytes = randomBytes(32);
        }
        var wrapkB = xor(keyBytes, material.unwrapBKey);
        var setupResponse = await fetch('/api/keys/setup', {
          method: 'POST',
          credentials: 'same-origin',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({
            wrapkB: bytesToHex(wrapkB),
            authHash: bytesToHex(material.authHash)
          })
        });
        var setupText = await setupResponse.text();
        if (!setupResponse.ok) throw new Error(setupText || ('HTTP ' + setupResponse.status));
        kB = keyBytes;
        session.mode = 'e2e';
        session.hasKeys = true;
        session.needsMigration = false;
        session.needsSetup = false;
      }
      keyReady = true;
      passwordEl.value = '';
      password2El.value = '';
      render();
      setStatus(unlocking ? 'Unlocked. Ready to connect Firefox.' : 'Sync password set. Ready to connect Firefox.');
    } catch (e) {
      setStatus('Error: ' + (e && e.message ? e.message : String(e)));
      keySubmit.disabled = false;
    }
  });

  connectEl.addEventListener('click', async function () {
    if (!hasFlow || !session || !session.loggedIn) return;
    connectEl.disabled = true;
    setStatus('Authorizing Firefox…');
    try {
      try {
        var link = await request('fxaccounts:can_link_account', { email: session.email }, 10000);
        if (link && link.ok === false) throw new Error('account linking was cancelled');
      } catch (e) {
        if (e && e.message === 'account linking was cancelled') throw e;
      }

      var keysJwe = null;
      if (session.mode === 'e2e') {
        if (!kB) throw new Error('Sync password is not unlocked');
        if (!flow.keys_jwk) throw new Error('Firefox did not send a keys_jwk');
        keysJwe = await makeKeysJwe(kB, flow.keys_jwk);
      }

      var response = await fetch('/api/authorize', {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          client_id: flow.client_id,
          scope: flow.scope,
          state: flow.state,
          code_challenge: flow.code_challenge,
          code_challenge_method: flow.code_challenge_method,
          keys_jwk: flow.keys_jwk,
          keys_jwe: keysJwe
        })
      });
      var text = await response.text();
      if (!response.ok) throw new Error(text || ('HTTP ' + response.status));
      var result = JSON.parse(text);

      var declined = session.declinedEngines || [];
      var offered = ['addons', 'bookmarks', 'history', 'passwords', 'prefs', 'tabs', 'addresses', 'creditcards'];

      send('fxaccounts:login', {
        email: session.email,
        uid: session.uid,
        sessionToken: session.sessionToken,
        verified: true,
        services: { sync: { offeredEngines: offered, declinedEngines: declined } }
      });

      await new Promise(function (resolve) { setTimeout(resolve, 250); });

      send('fxaccounts:oauth_login', {
        code: result.code,
        state: result.state,
        redirect: 'urn:ietf:wg:oauth:2.0:oob',
        action: 'signin',
        declinedSyncEngines: declined,
        offeredSyncEngines: offered
      });

      setStatus('Connected. Firefox should start syncing; you can close this tab.');
      flowHint.textContent = 'If Firefox does not start syncing, sign out and sign in again.';
    } catch (e) {
      setStatus('Error: ' + (e && e.message ? e.message : String(e)));
      connectEl.disabled = false;
    }
  });

  fetch('/api/session', { credentials: 'same-origin' })
    .then(function (response) { return response.json(); })
    .then(function (data) {
      session = data;
      render();
      if (hasFlow) {
        request('fxaccounts:fxa_status', { service: flow.service, context: flow.context }, 3000)
          .catch(function () {});
      }
    })
    .catch(function (e) {
      setStatus('Failed to load session: ' + e.message);
    });
})();
</script>
</body>
</html>`;
}

export function renderAccountPage(account) {
  const email = String(account.email || "").replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  })[c]);
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Account</title>
<style>body{font:16px/1.5 system-ui,sans-serif;max-width:40rem;margin:3rem auto;padding:0 1.2rem}a.button{display:inline-block;padding:.6rem 1rem;border-radius:.5rem;background:#4b6cf4;color:#fff;text-decoration:none}</style>
</head><body>
<h1>Account</h1>
<p>Signed in as <strong>${email}</strong>.</p>
<p class="muted">Account password changes, data deletion and device management are not implemented in this shim yet.</p>
<p><a class="button" href="/">Back</a> <a class="button" href="/auth/logout">Sign out</a></p>
</body></html>`;
}
