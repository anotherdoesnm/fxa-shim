import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";

import {
  OLDSYNC_SCOPE,
  decryptJwe,
  deriveSyncKey,
  encryptJwe,
  generateRsaKeyPair,
  makeScopedKeys,
  signJwt,
  verifyJwt,
} from "../src/crypto.js";

test("legacy sync key is 64 bytes", () => {
  const kB = crypto.randomBytes(32);
  assert.equal(deriveSyncKey(kB).length, 64);
});

test("scoped key has the shape Firefox validates", () => {
  const kB = crypto.randomBytes(32);
  const scoped = makeScopedKeys(kB, 1700000000000);
  const key = scoped[OLDSYNC_SCOPE];
  assert.equal(key.scope, OLDSYNC_SCOPE);
  assert.equal(key.kty, "oct");
  assert.match(key.kid, /^1700000000000-.+/);
  assert.equal(Buffer.from(key.k, "base64url").length, 64);
});

test("ECDH-ES/A256GCM JWE round-trips with a P-256 recipient key", () => {
  const client = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const publicJwk = client.publicKey.export({ format: "jwk" });
  const kB = crypto.randomBytes(32);
  const plaintext = JSON.stringify(makeScopedKeys(kB, 1700000000000));

  const jwe = encryptJwe(plaintext, publicJwk, publicJwk.kid);
  assert.equal(jwe.split(".").length, 5);
  assert.equal(jwe.split(".")[1], "");

  const decrypted = decryptJwe(jwe, client.privateKey).toString("utf8");
  assert.deepEqual(JSON.parse(decrypted), JSON.parse(plaintext));
});

test("RS256 access token signs and verifies", () => {
  const { privateKey, publicKey } = generateRsaKeyPair();
  const token = signJwt(
    { sub: "a".repeat(32), scope: OLDSYNC_SCOPE, exp: Math.floor(Date.now() / 1000) + 60 },
    privateKey,
    "test-kid",
  );
  const { header, payload } = verifyJwt(token, publicKey);
  assert.equal(header.alg, "RS256");
  assert.equal(payload.sub, "a".repeat(32));
});

test("verifyJwt rejects a tampered payload", () => {
  const { privateKey, publicKey } = generateRsaKeyPair();
  const token = signJwt({ sub: "abc" }, privateKey, "test-kid");
  const [header, , signature] = token.split(".");
  const tampered = `${header}.${Buffer.from('{"sub":"evil"}').toString("base64url")}.${signature}`;
  assert.throws(() => verifyJwt(tampered, publicKey));
});

test("JWE decrypts with WebCrypto the way Firefox does", async () => {
  const client = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const publicJwk = client.publicKey.export({ format: "jwk" });
  const privateJwk = client.privateKey.export({ format: "jwk" });
  const kB = crypto.randomBytes(32);
  const plaintext = JSON.stringify(makeScopedKeys(kB, 1700000000000));
  const jwe = encryptJwe(plaintext, publicJwk, publicJwk.kid);

  const [headerB64, , ivB64, ciphertextB64, tagB64] = jwe.split(".");
  const header = JSON.parse(Buffer.from(headerB64, "base64url").toString("utf8"));
  const subtle = crypto.webcrypto.subtle;

  const privateKey = await subtle.importKey(
    "jwk",
    privateJwk,
    { name: "ECDH", namedCurve: "P-256" },
    false,
    ["deriveKey"],
  );
  const ephemeralKey = await subtle.importKey(
    "jwk",
    header.epk,
    { name: "ECDH", namedCurve: "P-256" },
    false,
    [],
  );
  const shared = await subtle.deriveKey(
    { name: "ECDH", public: ephemeralKey },
    privateKey,
    { name: "AES-GCM", length: 256 },
    true,
    ["decrypt"],
  );
  const sharedBytes = Buffer.from(await subtle.exportKey("raw", shared));
  // Firefox's jwcrypto applies the NIST Concat KDF itself after WebCrypto
  // returns the raw ECDH secret.
  const algorithm = Buffer.from("A256GCM", "ascii");
  const info = Buffer.concat([
    Buffer.from([0, 0, 0, algorithm.length]),
    algorithm,
    Buffer.from([0, 0, 0, 0]),
    Buffer.from([0, 0, 0, 0]),
    Buffer.from([0, 0, 1, 0]),
  ]);
  const keyBytes = crypto
    .createHash("sha256")
    .update(Buffer.concat([Buffer.from([0, 0, 0, 1]), sharedBytes, info]))
    .digest();
  const contentKey = await subtle.importKey(
    "raw",
    keyBytes,
    { name: "AES-GCM" },
    false,
    ["decrypt"],
  );
  const bundle = Buffer.concat([
    Buffer.from(ciphertextB64, "base64url"),
    Buffer.from(tagB64, "base64url"),
  ]);
  const decrypted = await subtle.decrypt(
    {
      name: "AES-GCM",
      iv: Buffer.from(ivB64, "base64url"),
      additionalData: Buffer.from(headerB64, "utf8"),
      tagLength: 128,
    },
    contentKey,
    bundle,
  );
  assert.equal(Buffer.from(decrypted).toString("utf8"), plaintext);
});
