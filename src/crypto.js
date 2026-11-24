import crypto from "node:crypto";

export const OLDSYNC_SCOPE = "https://identity.mozilla.com/apps/oldsync";
const OLDSYNC_INFO = "identity.mozilla.com/picl/v1/oldsync";

export function b64url(input) {
  return Buffer.from(input).toString("base64url");
}

export function b64urlDecode(input) {
  return Buffer.from(input, "base64url");
}

export function sha256(input) {
  return crypto.createHash("sha256").update(input).digest();
}

export function randomHex(bytes = 32) {
  return crypto.randomBytes(bytes).toString("hex");
}

export function randomB64url(bytes = 32) {
  return crypto.randomBytes(bytes).toString("base64url");
}

export function hkdf(ikm, salt, info, length) {
  return Buffer.from(
    crypto.hkdfSync("sha256", ikm, salt, Buffer.from(info), length),
  );
}

/**
 * The legacy Sync key derivation used by Firefox for the oldsync scope.
 * 64 bytes = 32-byte encryption key + 32-byte HMAC key.
 */
export function deriveSyncKey(kB) {
  return hkdf(kB, Buffer.alloc(32), OLDSYNC_INFO, 64);
}

export function keyFingerprint(kB) {
  return b64url(sha256(kB).subarray(0, 16));
}

export function makeScopedKeys(kB, nowMs = Date.now()) {
  const scope = OLDSYNC_SCOPE;
  return {
    [scope]: {
      scope,
      kid: `${nowMs}-${keyFingerprint(kB)}`,
      k: b64url(deriveSyncKey(kB)),
      kty: "oct",
    },
  };
}

export function generateRsaKeyPair() {
  return crypto.generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicExponent: 0x10001,
  });
}

export function rsaPublicJwk(publicKey, kid) {
  const jwk = publicKey.export({ format: "jwk" });
  return {
    kty: "RSA",
    n: jwk.n,
    e: jwk.e,
    kid,
    use: "sig",
    alg: "RS256",
  };
}

export function signJwt(payload, privateKey, kid, typ = "application/at+jwt") {
  const header = { alg: "RS256", typ, kid };
  const signingInput =
    b64url(JSON.stringify(header)) + "." + b64url(JSON.stringify(payload));
  const signature = crypto.sign("sha256", Buffer.from(signingInput), privateKey);
  return signingInput + "." + b64url(signature);
}

export function verifyJwt(token, publicKey, { clockTolerance = 60 } = {}) {
  const parts = String(token).split(".");
  if (parts.length !== 3) throw new Error("malformed JWT");
  const [headerB64, payloadB64, signatureB64] = parts;
  const header = JSON.parse(b64urlDecode(headerB64).toString("utf8"));
  if (header.alg !== "RS256") throw new Error("unsupported JWT alg");
  const ok = crypto.verify(
    "sha256",
    Buffer.from(`${headerB64}.${payloadB64}`),
    publicKey,
    b64urlDecode(signatureB64),
  );
  if (!ok) throw new Error("invalid JWT signature");
  const payload = JSON.parse(b64urlDecode(payloadB64).toString("utf8"));
  const now = Math.floor(Date.now() / 1000);
  if (typeof payload.exp === "number" && payload.exp + clockTolerance < now) {
    throw new Error("expired JWT");
  }
  return { header, payload };
}

/**
 * NIST Concat KDF specialised for ECDH-ES + A256GCM, matching Firefox's
 * services/crypto/modules/jwcrypto.sys.mjs.
 */
function concatKdf(sharedSecret) {
  const algorithm = Buffer.from("A256GCM", "ascii");
  const info = Buffer.concat([
    Buffer.from([0, 0, 0, algorithm.length]),
    algorithm,
    Buffer.from([0, 0, 0, 0]), // empty PartyUInfo
    Buffer.from([0, 0, 0, 0]), // empty PartyVInfo
    Buffer.from([0, 0, 1, 0]), // 256-bit key
  ]);
  return sha256(
    Buffer.concat([Buffer.from([0, 0, 0, 1]), sharedSecret, info]),
  );
}

function cleanEcJwk(jwk) {
  return {
    kty: "EC",
    crv: jwk.crv,
    x: jwk.x,
    y: jwk.y,
  };
}

/**
 * Encrypt a payload with JWE compact serialization, alg=ECDH-ES,
 * enc=A256GCM, direct key agreement (no encrypted key).
 *
 * @param {Buffer|string} plaintext
 * @param {object} recipientJwk EC P-256 public JWK from Firefox's keys_jwk
 * @param {string} [kid]
 */
export function encryptJwe(plaintext, recipientJwk, kid) {
  const eph = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const epkJwk = cleanEcJwk(eph.publicKey.export({ format: "jwk" }));

  const header = { alg: "ECDH-ES", enc: "A256GCM", epk: epkJwk };
  if (kid) header.kid = kid;

  const peerPublicKey = crypto.createPublicKey({
    key: cleanEcJwk(recipientJwk),
    format: "jwk",
  });
  const sharedSecret = crypto.diffieHellman({
    privateKey: eph.privateKey,
    publicKey: peerPublicKey,
  });
  const contentKey = concatKdf(sharedSecret);

  const headerB64 = b64url(JSON.stringify(header));
  const aad = Buffer.from(headerB64, "utf8");
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", contentKey, iv);
  cipher.setAAD(aad);
  const ciphertext = Buffer.concat([
    cipher.update(Buffer.from(plaintext)),
    cipher.final(),
  ]);
  const tag = cipher.getAuthTag();

  return `${headerB64}..${b64url(iv)}.${b64url(ciphertext)}.${b64url(tag)}`;
}

/**
 * Inverse of encryptJwe. Used by tests and by the optional export tooling.
 */
export function decryptJwe(jwe, recipientPrivateKey) {
  const parts = String(jwe).split(".");
  if (parts.length !== 5 || parts[1] !== "") {
    throw new Error("unsupported JWE");
  }
  const [headerB64, , ivB64, ciphertextB64, tagB64] = parts;
  const header = JSON.parse(b64urlDecode(headerB64).toString("utf8"));
  if (header.alg !== "ECDH-ES" || header.enc !== "A256GCM") {
    throw new Error("unsupported JWE algorithms");
  }
  if (header.apu || header.apv) {
    throw new Error("apu/apv are not supported");
  }
  const epk = crypto.createPublicKey({
    key: cleanEcJwk(header.epk),
    format: "jwk",
  });
  const sharedSecret = crypto.diffieHellman({
    privateKey: recipientPrivateKey,
    publicKey: epk,
  });
  const contentKey = concatKdf(sharedSecret);

  const decipher = crypto.createDecipheriv(
    "aes-256-gcm",
    contentKey,
    b64urlDecode(ivB64),
  );
  decipher.setAAD(Buffer.from(headerB64, "utf8"));
  decipher.setAuthTag(b64urlDecode(tagB64));
  return Buffer.concat([
    decipher.update(b64urlDecode(ciphertextB64)),
    decipher.final(),
  ]);
}

export function pkceChallenge(verifier) {
  return b64url(sha256(Buffer.from(verifier, "utf8")));
}

export function timingSafeEqualString(a, b) {
  const left = Buffer.from(String(a));
  const right = Buffer.from(String(b));
  if (left.length !== right.length) return false;
  return crypto.timingSafeEqual(left, right);
}
