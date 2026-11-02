// Independent reference implementation, written from SPEC.md only.
// Dev-only, never shipped. Uses node:crypto; XChaCha20 is built from HChaCha20
// (draft-irtf-cfrg-xchacha-03 §2.2) plus node's IETF ChaCha20-Poly1305.
import crypto from "node:crypto";

export const enc = (s) => Buffer.from(s, "utf8");
export const cat = (...xs) => Buffer.concat(xs.map((x) => Buffer.from(x)));
export const b64u = (b) => Buffer.from(b).toString("base64url");
export const unb64u = (s) => {
  const b = Buffer.from(s, "base64url");
  if (b64u(b) !== s) throw new Error("non-canonical base64url");
  return b;
};
export const u16 = (x) => Buffer.from([(x >>> 8) & 255, x & 255]);
export const u32 = (x) => {
  const b = Buffer.alloc(4);
  b.writeUInt32BE(x);
  return b;
};
export const u64 = (x) => {
  const b = Buffer.alloc(8);
  b.writeBigUInt64BE(BigInt(x));
  return b;
};
export const lp = (x) => cat(u16(x.length), x);
export const sha256 = (...xs) =>
  crypto
    .createHash("sha256")
    .update(cat(...xs))
    .digest();
export const sha512 = (...xs) =>
  crypto
    .createHash("sha512")
    .update(cat(...xs))
    .digest();
export const hmac = (k, m) => crypto.createHmac("sha256", k).update(m).digest();
export const hkdf = (salt, ikm, info, len) =>
  Buffer.from(crypto.hkdfSync("sha256", ikm, salt, info, len));

// ── Keys (RFC 7748 / RFC 8032 through DER wrappers) ─────────────────────────
const PKCS8 = {
  x25519: "302e020100300506032b656e04220420",
  ed25519: "302e020100300506032b657004220420",
};
const SPKI = {
  x25519: "302a300506032b656e032100",
  ed25519: "302a300506032b6570032100",
};
const priv = (kind, sk) =>
  crypto.createPrivateKey({
    key: cat(Buffer.from(PKCS8[kind], "hex"), sk),
    format: "der",
    type: "pkcs8",
  });
const pub = (kind, pk) =>
  crypto.createPublicKey({
    key: cat(Buffer.from(SPKI[kind], "hex"), pk),
    format: "der",
    type: "spki",
  });
const rawPub = (k) =>
  crypto
    .createPublicKey(k)
    .export({ format: "der", type: "spki" })
    .subarray(-32);

export const xPub = (sk) => rawPub(priv("x25519", sk));
export function xDh(sk, pk) {
  const out = crypto.diffieHellman({
    privateKey: priv("x25519", sk),
    publicKey: pub("x25519", pk),
  });
  if (out.every((b) => b === 0)) throw new Error("all-zero X25519");
  return out;
}
export const edPub = (seed) => rawPub(priv("ed25519", seed));
export const edSign = (seed, m) => crypto.sign(null, m, priv("ed25519", seed));
export const edVerify = (pk, m, sig) => {
  try {
    return crypto.verify(null, m, pub("ed25519", pk), sig);
  } catch {
    return false;
  }
};

// ── XChaCha20-Poly1305 ───────────────────────────────────────────────────────
const rotl = (v, c) => ((v << c) | (v >>> (32 - c))) >>> 0;
export function hchacha20(key, nonce16) {
  const s = new Uint32Array(16);
  s.set([0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]);
  for (let i = 0; i < 8; i++) s[4 + i] = key.readUInt32LE(4 * i);
  for (let i = 0; i < 4; i++) s[12 + i] = nonce16.readUInt32LE(4 * i);
  const qr = (a, b, c, d) => {
    s[a] = (s[a] + s[b]) >>> 0;
    s[d] = rotl(s[d] ^ s[a], 16);
    s[c] = (s[c] + s[d]) >>> 0;
    s[b] = rotl(s[b] ^ s[c], 12);
    s[a] = (s[a] + s[b]) >>> 0;
    s[d] = rotl(s[d] ^ s[a], 8);
    s[c] = (s[c] + s[d]) >>> 0;
    s[b] = rotl(s[b] ^ s[c], 7);
  };
  for (let i = 0; i < 10; i++) {
    qr(0, 4, 8, 12);
    qr(1, 5, 9, 13);
    qr(2, 6, 10, 14);
    qr(3, 7, 11, 15);
    qr(0, 5, 10, 15);
    qr(1, 6, 11, 12);
    qr(2, 7, 8, 13);
    qr(3, 4, 9, 14);
  }
  const out = Buffer.alloc(32);
  [0, 1, 2, 3, 12, 13, 14, 15].forEach((w, i) =>
    out.writeUInt32LE(s[w], 4 * i),
  );
  return out;
}
const subkey = (key, nonce) => [
  hchacha20(Buffer.from(key), Buffer.from(nonce).subarray(0, 16)),
  cat(Buffer.alloc(4), Buffer.from(nonce).subarray(16, 24)),
];
export function xSeal(key, nonce, pt, aad) {
  const [k, n] = subkey(key, nonce);
  const c = crypto.createCipheriv("chacha20-poly1305", k, n, {
    authTagLength: 16,
  });
  c.setAAD(aad, { plaintextLength: pt.length });
  return cat(c.update(pt), c.final(), c.getAuthTag());
}
export function xOpen(key, nonce, ct, aad) {
  try {
    const [k, n] = subkey(key, nonce);
    const d = crypto.createDecipheriv("chacha20-poly1305", k, n, {
      authTagLength: 16,
    });
    d.setAAD(aad, { plaintextLength: ct.length - 16 });
    d.setAuthTag(ct.subarray(ct.length - 16));
    return cat(d.update(ct.subarray(0, ct.length - 16)), d.final());
  } catch {
    return null;
  }
}

// ── JCS subset (SPEC §4.6) ───────────────────────────────────────────────────
export function jcsText(v) {
  if (typeof v === "string") return JSON.stringify(v);
  if (typeof v === "number") {
    if (!Number.isInteger(v) || v < 0 || v > 2 ** 31 - 1 || Object.is(v, -0))
      throw new Error("jcs number");
    return String(v);
  }
  if (Array.isArray(v)) return `[${v.map(jcsText).join(",")}]`;
  if (v && typeof v === "object") {
    const ks = Object.keys(v).filter((k) => v[k] !== undefined);
    ks.sort((a, b) => {
      for (let i = 0; i < Math.min(a.length, b.length); i++)
        if (a.charCodeAt(i) !== b.charCodeAt(i))
          return a.charCodeAt(i) - b.charCodeAt(i);
      return a.length - b.length;
    });
    return `{${ks.map((k) => `${JSON.stringify(k)}:${jcsText(v[k])}`).join(",")}}`;
  }
  throw new Error("jcs value");
}
export const jcs = (v) => enc(jcsText(v));

// ── HMAC-DRBG tape replay (SPEC §15) ─────────────────────────────────────────
export function drbg(seedHex) {
  let K = Buffer.alloc(32);
  let V = Buffer.alloc(32, 1);
  const update = (p) => {
    K = hmac(K, cat(V, [0], p));
    V = hmac(K, V);
    if (p.length) {
      K = hmac(K, cat(V, [1], p));
      V = hmac(K, V);
    }
  };
  update(cat(Buffer.from(seedHex, "hex"), enc("e2ee/v2/test")));
  return (n) => {
    const out = [];
    let len = 0;
    while (len < n) {
      V = hmac(K, V);
      out.push(V);
      len += 32;
    }
    update(Buffer.alloc(0));
    return cat(...out).subarray(0, n);
  };
}

/** Replays a recorded tape, checking each draw against the DRBG and the expected purpose. */
export function tape(seedHex, entries) {
  const gen = drbg(seedHex);
  let i = 0;
  const draw = (n, purpose) => {
    const e = entries[i++];
    if (!e || e.purpose !== purpose)
      throw new Error(
        `tape: draw ${i - 1} wanted ${purpose}, have ${e?.purpose}`,
      );
    const b = gen(n);
    if (b.toString("hex") !== e.bytes)
      throw new Error(`tape: draw ${i - 1} bytes differ from the DRBG`);
    return b;
  };
  draw.done = () => i === entries.length;
  draw.at = () => i;
  return draw;
}

// ── Protocol pieces (SPEC §5-§7, §12, §13) ───────────────────────────────────
const L = (s) => enc(`e2ee/v2/${s}`);
const L2 = (s) => enc(`e2ee/s2/${s}`);
export const SUITE_V1 = "x25519-xchacha20poly1305-sha256-v1";
export const SUITE_V2 = "x25519-xchacha20poly1305-sha256-v2";
/** Newest first (SPEC §5.4). */
export const SUITES = [SUITE_V2, SUITE_V1];
const label = (suite, s) => (suite === SUITE_V2 ? L2(s) : L(s));
export const ms = (iso) => Date.parse(iso);

export const boxPkPayload = (deviceId, boxPk) =>
  cat(L("boxpk"), lp(enc(deviceId)), boxPk);
export const spkPayload = (deviceId, spkId, spkPk, createdAt, suites) =>
  cat(
    L("spk"),
    lp(enc(deviceId)),
    u32(spkId),
    spkPk,
    u64(ms(createdAt)),
    lp(jcs(suites)),
  );
export const hsDigest = (h) => b64u(sha256(L("hs-digest"), jcs(h)));
export const sidOf = (h) => b64u(sha256(L("sid"), jcs(h)).subarray(0, 8));
/** id(X) = lp(UTF-8(deviceId)) ‖ signPk ‖ boxPk (SPEC §6.2); keys are raw bytes. */
const idBytes = (x) => cat(lp(enc(x.deviceId)), x.signPk, x.boxPk);
export const x3dhInfo = (suite, a, b) =>
  suite === SUITE_V2 ? cat(L2("x3dh"), idBytes(a), idBytes(b)) : L("x3dh");
export const x3dhSk = (dhs, info) =>
  hkdf(Buffer.alloc(32), cat(Buffer.alloc(32, 0xff), ...dhs), info, 32);
export const kdfRk = (rk, dh, suite) => {
  const o = hkdf(rk, dh, label(suite, "rk"), 64);
  return [o.subarray(0, 32), o.subarray(32)];
};
export const kdfCk = (ck) => [
  hmac(ck, Buffer.from([2])),
  hmac(ck, Buffer.from([1])),
];
/** keys: IK_A, IK_B (v1), then ED_A, ED_B (v2), raw bytes. */
export const mkPrime = (mk, ad, keys) =>
  hkdf(
    Buffer.alloc(32),
    mk,
    cat(label(ad.suite, "mk"), sha256(jcs(ad), ...keys)),
    32,
  );
export const aadOf = (m) =>
  jcs({
    v: m.v,
    suite: m.suite,
    ad: m.ad,
    header: m.header,
    handshake: m.handshake,
  });

export const BUCKETS = [64, 128, 256, 512, 1024, 2048, 4096, 8196];
export function pad(p) {
  if (p.length > 8192) throw new Error("too large");
  const B = BUCKETS.find((b) => b >= 4 + p.length);
  return cat(u32(p.length), p, Buffer.alloc(B - 4 - p.length));
}
export function unpad(b) {
  if (b.length < 4) return null;
  const len = b.readUInt32BE(0);
  if (len > b.length - 4 || BUCKETS.find((x) => x >= 4 + len) !== b.length)
    return null;
  if (b.subarray(4 + len).some((x) => x !== 0)) return null;
  return b.subarray(4, 4 + len);
}

export function fingerprintChain(key, stableId, iterations = 5200) {
  let h = sha512(u16(0), key, enc(stableId), key);
  for (let i = 1; i < iterations; i++) h = sha512(h, key);
  return h;
}
export function digits30(fp) {
  let s = "";
  for (let i = 0; i < 6; i++) {
    let c = 0;
    for (let k = 0; k < 5; k++) c = c * 256 + fp[5 * i + k];
    s += String(c % 100000).padStart(5, "0");
  }
  return s;
}

export const linkTranscript = (t) =>
  sha256(
    L("link-transcript"),
    lp(enc(t.requestId)),
    lp(enc(t.accountId)),
    lp(enc(t.newDeviceId)),
    unb64u(t.newDeviceSignPk),
    unb64u(t.newDeviceBoxPk),
    lp(jcs(t.suites)),
  );
export const linkCommit = (T, ephNew) => sha256(L("link-commit"), T, ephNew);
export const linkCode = (T, ephNew, ephOld) =>
  String(
    hkdf(T, cat(ephNew, ephOld), L("link-code"), 4).readUInt32BE(0) % 1_000_000,
  ).padStart(6, "0");
export const linkSealKey = (T, sk, pk) =>
  hkdf(T, xDh(sk, pk), L("link-seal"), 32);
