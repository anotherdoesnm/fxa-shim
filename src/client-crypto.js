// Browser-side Sync key derivation. Used by the content page; no password is
// ever sent to the server in E2E mode.
const enc = new TextEncoder();
const dec = new TextDecoder();

export const OLDSYNC = "https://identity.mozilla.com/apps/oldsync";

export function b64url(input) {
  const bytes = typeof input === "string"
    ? enc.encode(input)
    : input instanceof Uint8Array
      ? input
      : new Uint8Array(input);
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function b64urlDecode(value) {
  const padded = String(value).replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(padded + "=".repeat((4 - (padded.length % 4)) % 4));
  return Uint8Array.from(binary, (c) => c.charCodeAt(0));
}

export function hexToBytes(value) {
  const out = new Uint8Array(value.length / 2);
  for (let i = 0; i < out.length; i += 1) {
    out[i] = parseInt(value.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

export function bytesToHex(bytes) {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

export function randomBytes(length) {
  return crypto.getRandomValues(new Uint8Array(length));
}

export function xor(a, b) {
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i += 1) out[i] = a[i] ^ b[i];
  return out;
}

function concat(...arrays) {
  const length = arrays.reduce((sum, a) => sum + a.length, 0);
  const out = new Uint8Array(length);
  let offset = 0;
  for (const a of arrays) {
    out.set(a, offset);
    offset += a.length;
  }
  return out;
}

async function hkdf(ikm, info, length) {
  const key = await crypto.subtle.importKey("raw", ikm, "HKDF", false, ["deriveBits"]);
  return new Uint8Array(
    await crypto.subtle.deriveBits(
      {
        name: "HKDF",
        hash: "SHA-256",
        salt: new Uint8Array(32),
        info: enc.encode(info),
      },
      key,
      length * 8,
    ),
  );
}

/**
 * Derive the two values that never leave the browser:
 *   - unwrapBKey: XORed with wrapkB to obtain kB
 *   - authHash:   sent to the server as a password verifier
 */
export async function deriveMaterial(password, salt) {
  const baseKey = await crypto.subtle.importKey(
    "raw",
    enc.encode(password),
    "PBKDF2",
    false,
    ["deriveBits"],
  );
  const stretched = new Uint8Array(
    await crypto.subtle.deriveBits(
      {
        name: "PBKDF2",
        salt: enc.encode(salt),
        iterations: 200000,
        hash: "SHA-256",
      },
      baseKey,
      256,
    ),
  );
  return {
    unwrapBKey: await hkdf(stretched, "fxa-shim/unwrapBKey", 32),
    authHash: await hkdf(stretched, "fxa-shim/authHash", 32),
  };
}

export async function deriveScopedKeys(kB, nowMs = Date.now()) {
  const k = await hkdf(kB, "identity.mozilla.com/picl/v1/oldsync", 64);
  const fingerprint = new Uint8Array(
    (await crypto.subtle.digest("SHA-256", kB)).slice(0, 16),
  );
  return {
    [OLDSYNC]: {
      scope: OLDSYNC,
      kid: `${nowMs}-${b64url(fingerprint)}`,
      k: b64url(k),
      kty: "oct",
    },
  };
}

/** JWE compact, alg=ECDH-ES, enc=A256GCM, direct key agreement. */
export async function makeKeysJwe(kB, keysJwkB64) {
  const recipient = JSON.parse(dec.decode(b64urlDecode(keysJwkB64)));
  const peer = await crypto.subtle.importKey(
    "jwk",
    { kty: "EC", crv: "P-256", x: recipient.x, y: recipient.y },
    { name: "ECDH", namedCurve: "P-256" },
    false,
    [],
  );
  const ephemeral = await crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    true,
    ["deriveBits"],
  );
  const exported = await crypto.subtle.exportKey("jwk", ephemeral.publicKey);
  const epk = { kty: "EC", crv: "P-256", x: exported.x, y: exported.y };

  const shared = new Uint8Array(
    await crypto.subtle.deriveBits(
      { name: "ECDH", public: peer },
      ephemeral.privateKey,
      256,
    ),
  );
  const algorithm = enc.encode("A256GCM");
  const info = concat(
    Uint8Array.from([0, 0, 0, algorithm.length]),
    algorithm,
    Uint8Array.from([0, 0, 0, 0]),
    Uint8Array.from([0, 0, 0, 0]),
    Uint8Array.from([0, 0, 1, 0]),
  );
  const contentKey = new Uint8Array(
    await crypto.subtle.digest(
      "SHA-256",
      concat(Uint8Array.from([0, 0, 0, 1]), shared, info),
    ),
  );

  const header = { alg: "ECDH-ES", enc: "A256GCM", epk };
  if (recipient.kid) header.kid = recipient.kid;
  const headerB64 = b64url(enc.encode(JSON.stringify(header)));
  const iv = randomBytes(12);
  const aes = await crypto.subtle.importKey(
    "raw",
    contentKey,
    { name: "AES-GCM" },
    false,
    ["encrypt"],
  );
  const plaintext = enc.encode(JSON.stringify(await deriveScopedKeys(kB)));
  const sealed = new Uint8Array(
    await crypto.subtle.encrypt(
      {
        name: "AES-GCM",
        iv,
        additionalData: enc.encode(headerB64),
        tagLength: 128,
      },
      aes,
      plaintext,
    ),
  );
  const ciphertext = sealed.slice(0, sealed.length - 16);
  const tag = sealed.slice(sealed.length - 16);
  return `${headerB64}..${b64url(iv)}.${b64url(ciphertext)}.${b64url(tag)}`;
}
