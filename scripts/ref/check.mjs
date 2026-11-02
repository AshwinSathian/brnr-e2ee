// Asserts that the independent reference (scripts/ref/ref.mjs) agrees with the library on every vector input.
//   node scripts/ref/check.mjs
import { readFileSync } from "node:fs";
import * as R from "./ref.mjs";

const { b64u, unb64u, cat, enc, jcsText } = R;
const read = (name) =>
  JSON.parse(
    readFileSync(new URL(`../../vectors/${name}`, import.meta.url), "utf8"),
  );
let checks = 0;
function eq(a, b, what) {
  checks++;
  const [x, y] = [
    typeof a === "string" ? a : JSON.stringify(a),
    typeof b === "string" ? b : JSON.stringify(b),
  ];
  if (x !== y)
    throw new Error(
      `ref mismatch: ${what}\n  ref: ${x.slice(0, 200)}\n  lib: ${y.slice(0, 200)}`,
    );
}

// ── Primitive self-checks against draft-irtf-cfrg-xchacha-03 ────────────────
{
  const kat = JSON.parse(
    readFileSync(new URL("../../test/data/kat.json", import.meta.url), "utf8"),
  ).xchacha_draft03;
  const h = Buffer.from;
  eq(
    R.hchacha20(
      h(kat.hchacha20.key, "hex"),
      h(kat.hchacha20.nonce, "hex"),
    ).toString("hex"),
    kat.hchacha20.subkey,
    "HChaCha20 §2.2.1",
  );
  const a = kat.aead;
  eq(
    R.xSeal(
      h(a.key, "hex"),
      h(a.nonce, "hex"),
      h(a.plaintext, "hex"),
      h(a.aad, "hex"),
    ).toString("hex"),
    a.ciphertext + a.tag,
    "XChaCha20-Poly1305 §A.3.1",
  );
}

// ── Conversation engine (SPEC §6-§8, one device per party) ───────────────────
class Party {
  constructor(p, startTime) {
    this.name = p.name;
    this.deviceId = p.deviceId;
    this.suites = p.suites ?? [R.SUITE_V1]; // absent: an SPK offering suite v1 only
    this.startTime = startTime;
    this.draw = R.tape(p.seed, p.tape);
    this.draw(32, "health");
    this.draw(32, "health");
    this.signSk = this.draw(32, "seed");
    this.signPk = R.edPub(this.signSk);
    this.boxSk = this.draw(32, "seed");
    this.boxPk = R.xPub(this.boxSk);
    this.spks = new Map();
    this.rotate(this.suites);
    this.otps = new Map();
    this.nextOtp = 1;
    this.peers = new Map(); // peer name -> state
  }
  /** A new SPK with the next id (SPEC §5.2: one seed draw). */
  rotate(suites) {
    const sk = this.draw(32, "seed");
    this.spk = {
      spkId: this.spks.size + 1,
      sk,
      pk: R.xPub(sk),
      createdAt: this.startTime,
      suites,
    };
    this.spks.set(this.spk.spkId, this.spk);
  }
  bundle(otp) {
    const b = {
      deviceId: this.deviceId,
      signPk: this.signPk,
      ik: this.boxPk,
      spkId: this.spk.spkId,
      spk: this.spk.pk,
      suites: this.spk.suites,
    };
    if (otp) {
      const id = this.nextOtp++;
      const sk = this.draw(32, "seed");
      this.otps.set(id, sk);
      b.otp = { otpId: id, pk: R.xPub(sk) };
    }
    return b;
  }
  peer(name) {
    if (!this.peers.has(name))
      this.peers.set(name, {
        sessions: new Map(),
        active: null,
        suite: null,
        retired: new Set(), // SPEC §8.1; the 48 h expiry never elapses in these flows
      });
    return this.peers.get(name);
  }
}

/** SPEC §7.4: suite v2 AD also names the recipient. */
const adOf = (conv, suite, sender, recipient) =>
  suite === R.SUITE_V2
    ? {
        conversationId: conv,
        senderDeviceId: sender,
        recipientDeviceId: recipient,
        suite,
        v: 2,
      }
    : { conversationId: conv, senderDeviceId: sender, suite, v: 2 };
/** A session's suite follows its founding handshake's shape (SPEC §9.1). */
const suiteOf = (h) => ("initiatorSignPk" in h ? R.SUITE_V2 : R.SUITE_V1);
/** SUITES is newest first; a state never moves to an older suite. */
const older = (a, b) => R.SUITES.indexOf(a) > R.SUITES.indexOf(b);
/** IK_A ‖ IK_B, then ED_A ‖ ED_B for a v2 session (SPEC §7.4). */
function keysOf(S, self, st) {
  const me = [self.boxPk, self.signPk];
  const them = [st.peerBoxPk, st.peerSignPk];
  const [a, b] = S.role === "initiator" ? [me, them] : [them, me];
  return suiteOf(S.founding) === R.SUITE_V2
    ? [a[0], b[0], a[1], b[1]]
    : [a[0], b[0]];
}
const clone = (s) => ({
  ...s,
  prevRemoteDh: [...s.prevRemoteDh],
  skipped: new Map(s.skipped),
});

let order = 0; // session creation order, standing in for createdAt (SPEC §8.1)

function initiate(a, b, otp, forged) {
  const bun = b.bundle(otp);
  if (forged) {
    // The unknown-key-share bundle: another party's deviceId and signing key over b's keys.
    bun.deviceId = forged.deviceId;
    bun.signPk = forged.signer.signPk;
  }
  const suite = bun.suites.find((x) => R.SUITES.includes(x));
  const st = a.peer(b.name);
  if (st.suite && older(suite, st.suite)) throw new Error("suite downgrade");
  if (st.peerSignPk && !Buffer.from(st.peerSignPk).equals(bun.signPk))
    throw new Error("existing sign key");
  const ek = a.draw(32, "ek");
  const dhsSk = a.draw(32, "dhs");
  const dh = [R.xDh(a.boxSk, bun.spk), R.xDh(ek, bun.ik), R.xDh(ek, bun.spk)];
  if (bun.otp) dh.push(R.xDh(ek, Buffer.from(bun.otp.pk)));
  const sk = R.x3dhSk(
    dh,
    R.x3dhInfo(
      suite,
      { deviceId: a.deviceId, signPk: a.signPk, boxPk: a.boxPk },
      { deviceId: bun.deviceId, signPk: bun.signPk, boxPk: bun.ik },
    ),
  );
  const h = {
    v: 2,
    initiatorBoxPk: b64u(a.boxPk),
    initiatorEphPk: b64u(R.xPub(ek)),
    spkId: bun.spkId,
  };
  if (suite === R.SUITE_V2) {
    h.initiatorSignPk = b64u(a.signPk);
    h.responderDeviceId = bun.deviceId;
    h.responderSignPk = b64u(bun.signPk);
  }
  if (bun.otp) h.otpId = bun.otp.otpId;
  const [rk, cks] = R.kdfRk(sk, R.xDh(dhsSk, bun.spk), suite);
  const sid = R.sidOf(h);
  const S = {
    sid,
    role: "initiator",
    founding: h,
    pending: true,
    rk,
    dhsSk,
    dhsPk: R.xPub(dhsSk),
    dhr: b64u(bun.spk),
    cks,
    ckr: null,
    ns: 0,
    nr: 0,
    pn: 0,
    prevRemoteDh: [],
    skipped: new Map(),
    order: order++,
  };
  st.sessions.set(sid, S);
  st.active = sid;
  st.suite = suite;
  st.peerBoxPk = b.boxPk;
  if (suite === R.SUITE_V2) st.peerSignPk = bun.signPk;
  st.peerDeviceId = bun.deviceId;
}

function encrypt(a, b, conv, text) {
  const st = a.peer(b.name);
  const S = st.sessions.get(st.active);
  const [cks, mk] = R.kdfCk(S.cks);
  S.cks = cks;
  const header = { sid: S.sid, dh: b64u(S.dhsPk), pn: S.pn, n: S.ns };
  S.ns += 1;
  const nonce = a.draw(24, "nonce");
  const ad = adOf(conv, st.suite, a.deviceId, st.peerDeviceId);
  const m = { v: 2, suite: st.suite, header, nonce: b64u(nonce), ad };
  if (S.pending) m.handshake = { ...S.founding };
  m.ciphertext = b64u(
    R.xSeal(
      R.mkPrime(mk, ad, keysOf(S, a, st)),
      nonce,
      R.pad(enc(text)),
      R.aadOf(m),
    ),
  );
  return m;
}

/**
 * Returns { plaintext, messageKey } or throws. Commits only on success. `pinSign` is the signing key
 * the receiver pins for the sender (SPEC §6.4); the box-key pin is always the sender's.
 */
function decrypt(b, a, conv, m, pinSign = a.signPk) {
  if (!R.SUITES.includes(m.suite)) throw new Error("suite");
  if (jcsText(m.ad) !== jcsText(adOf(conv, m.suite, a.deviceId, b.deviceId)))
    throw new Error("ad");
  const h = m.handshake;
  if (h) {
    if (h.initiatorBoxPk === b64u(b.boxPk)) throw new Error("reflection");
    if (R.sidOf(h) !== m.header.sid) throw new Error("sid");
  }
  const st0 = b.peer(a.name);
  let S = st0.sessions.get(m.header.sid);
  const st = { ...st0 }; // identity fields committed on success only
  let candidate = false;
  if (!S) {
    if (!h) throw new Error("handshake required");
    if (h.initiatorBoxPk !== b64u(a.boxPk)) throw new Error("pin");
    const v2 = m.suite === R.SUITE_V2;
    if (v2) {
      if (h.initiatorSignPk !== b64u(pinSign)) throw new Error("sign pin");
      if (
        h.responderDeviceId !== b.deviceId ||
        h.responderSignPk !== b64u(b.signPk)
      )
        throw new Error("handshake targets another device");
    }
    if (st.suite && older(m.suite, st.suite))
      throw new Error("suite downgrade");
    if (st.peerSignPk && !Buffer.from(st.peerSignPk).equals(pinSign))
      throw new Error("existing sign key");
    const spk = b.spks.get(h.spkId);
    if (!spk || !spk.suites.includes(m.suite)) throw new Error("spk");
    let otpSk;
    if (h.otpId !== undefined) {
      otpSk = b.otps.get(h.otpId);
      if (!otpSk) throw new Error("otp");
    }
    const ikA = unb64u(h.initiatorBoxPk);
    const ekA = unb64u(h.initiatorEphPk);
    const dh = [R.xDh(spk.sk, ikA), R.xDh(b.boxSk, ekA), R.xDh(spk.sk, ekA)];
    if (otpSk) dh.push(R.xDh(otpSk, ekA));
    const info = R.x3dhInfo(
      m.suite,
      {
        deviceId: m.ad.senderDeviceId,
        signPk: v2 ? unb64u(h.initiatorSignPk) : null,
        boxPk: ikA,
      },
      { deviceId: b.deviceId, signPk: b.signPk, boxPk: b.boxPk },
    );
    S = {
      sid: m.header.sid,
      role: "responder",
      founding: h,
      pending: false,
      rk: R.x3dhSk(dh, info),
      dhsSk: spk.sk,
      dhsPk: spk.pk,
      dhr: null,
      cks: null,
      ckr: null,
      ns: 0,
      nr: 0,
      pn: 0,
      prevRemoteDh: [],
      skipped: new Map(),
      order: order++,
    };
    candidate = true;
    st.peerBoxPk = ikA;
    st.peerDeviceId = m.ad.senderDeviceId;
    if (v2) st.peerSignPk = pinSign;
    st.suite ??= m.suite;
  } else if (h && jcsText(h) !== jcsText(S.founding))
    throw new Error("not founding");
  if (m.suite !== suiteOf(S.founding) || (st.suite && older(m.suite, st.suite)))
    throw new Error("session suite");
  const suite = m.suite;
  S = clone(S);
  const { dh, n, pn } = m.header;
  if (dh === S.dhr && !S.ckr) throw new Error("no receiving chain");
  const key = `${dh}/${n}`;
  let mk;
  let advanced = true;
  let confirmed = false;
  if (S.skipped.has(key)) {
    mk = S.skipped.get(key);
    S.skipped.delete(key);
    advanced = false;
  } else {
    if (dh === S.dhr && n < S.nr) throw new Error("duplicate");
    if (
      S.prevRemoteDh.includes(dh) ||
      (dh !== S.dhr &&
        [...S.skipped.keys()].some((k) => k.startsWith(`${dh}/`)))
    )
      throw new Error("duplicate dh");
    const skip = (until) => {
      if (until - S.nr > 1000) throw new Error("skip too large");
      if (!S.ckr) return;
      while (S.nr < until) {
        const [ck, k] = R.kdfCk(S.ckr);
        S.skipped.set(`${S.dhr}/${S.nr}`, k);
        S.ckr = ck;
        S.nr += 1;
      }
    };
    if (dh !== S.dhr) {
      confirmed = S.dhr !== null;
      skip(pn);
      if (S.dhr) S.prevRemoteDh = [...S.prevRemoteDh, S.dhr].slice(-64);
      S.pn = S.ns;
      S.ns = 0;
      S.nr = 0;
      S.dhr = dh;
      [S.rk, S.ckr] = R.kdfRk(S.rk, R.xDh(S.dhsSk, unb64u(dh)), suite);
      S.dhsSk = b.draw(32, "dhs");
      S.dhsPk = R.xPub(S.dhsSk);
      [S.rk, S.cks] = R.kdfRk(S.rk, R.xDh(S.dhsSk, unb64u(dh)), suite);
    }
    skip(n);
    const [ck, k] = R.kdfCk(S.ckr);
    S.ckr = ck;
    S.nr += 1;
    mk = k;
  }
  const mkp = R.mkPrime(mk, m.ad, keysOf(S, b, st));
  const padded = R.xOpen(
    mkp,
    unb64u(m.nonce),
    unb64u(m.ciphertext),
    R.aadOf(m),
  );
  if (!padded) throw new Error("aead");
  const pt = R.unpad(padded);
  if (!pt) throw new Error("padding");
  S.pending = false;
  Object.assign(st0, st);
  st0.sessions.set(S.sid, S);
  // SPEC §8.1: a confirmed decrypt on the already-active session retires the sessions not newer
  // than it (creation order here; the flows never create two sessions in the same millisecond).
  if (confirmed && st0.active === S.sid) {
    for (const [sid, y] of st0.sessions)
      if (sid !== S.sid && y.order <= S.order) st0.retired.add(sid);
  }
  // A decrypt activates its session unless it is retired.
  if (advanced && !st0.retired.has(S.sid)) {
    st0.active = S.sid;
    st0.suite = suite;
  }
  if (candidate && h.otpId !== undefined) b.otps.delete(h.otpId);
  return { plaintext: pt.toString("utf8"), messageKey: b64u(mkp) };
}

/** Tamper functions by vector name; `P` maps party names to parties. */
const withSid = (x, handshake) => ({
  ...x,
  handshake,
  header: { ...x.header, sid: R.sidOf(handshake) },
});
const TAMPER = {
  "header.n": (x) => ({ ...x, header: { ...x.header, n: x.header.n + 1 } }),
  "header.pn": (x) => ({ ...x, header: { ...x.header, pn: x.header.pn + 1 } }),
  "header.dh": (x) => ({
    ...x,
    header: { ...x.header, dh: b64u(Buffer.alloc(32, 7)) },
  }),
  "header.sid": (x) => ({ ...x, header: { ...x.header, sid: "AAAAAAAAAAA" } }),
  "handshake.initiatorEphPk": (x) => ({
    ...x,
    handshake: { ...x.handshake, initiatorEphPk: b64u(Buffer.alloc(32, 7)) },
  }),
  "ad.senderDeviceId": (x) => ({
    ...x,
    ad: { ...x.ad, senderDeviceId: "mallory-dev" },
  }),
  "ad.recipientDeviceId": (x) => ({
    ...x,
    ad: { ...x.ad, recipientDeviceId: "mallory-dev" },
  }),
  nonce: (x) => ({ ...x, nonce: b64u(Buffer.alloc(24)) }),
  "header.pn (same chain)": (x) => ({
    ...x,
    header: { ...x.header, pn: x.header.pn + 1 },
  }),
  "retarget to bob": (x, P) => ({
    ...withSid(x, {
      ...x.handshake,
      responderDeviceId: P.get("bob").deviceId,
      responderSignPk: b64u(P.get("bob").signPk),
    }),
    ad: { ...x.ad, recipientDeviceId: P.get("bob").deviceId },
  }),
  "initiatorSignPk = eve": (x, P) =>
    withSid(x, { ...x.handshake, initiatorSignPk: b64u(P.get("eve").signPk) }),
};

function replay(v, label) {
  const parties = new Map(
    v.parties.map((p) => [p.name, new Party(p, v.startTime)]),
  );
  const msgs = [];
  for (const [i, ev] of v.events.entries()) {
    const where = `${label} event ${i}`;
    if (ev.type === "advance") continue;
    if (ev.type === "rotate") parties.get(ev.by).rotate(ev.suites);
    else if (ev.type === "initiate") {
      if (ev.reset) parties.get(ev.by).peers.delete(ev.to);
      initiate(
        parties.get(ev.by),
        parties.get(ev.to),
        ev.otp,
        ev.forgedBy && {
          signer: parties.get(ev.forgedBy),
          deviceId: ev.deviceId,
        },
      );
    } else if (ev.type === "send") {
      const by = parties.get(ev.by);
      const to = ev.to
        ? parties.get(ev.to)
        : [...parties.values()].find((p) => p !== by);
      const m = encrypt(by, to, v.conversationId, ev.plaintext);
      msgs.push(m);
      if (!ev.drop) eq(jcsText(m), ev.message, `${where}: message bytes`);
    } else if (ev.type === "recv") {
      let m = structuredClone(msgs[ev.message]);
      if (ev.tamper) m = TAMPER[ev.tamper](m, parties);
      let r;
      try {
        r = decrypt(
          parties.get(ev.by),
          parties.get(ev.from),
          v.conversationId,
          m,
          ev.pinSignOf ? parties.get(ev.pinSignOf).signPk : undefined,
        );
      } catch (e) {
        r = { error: e.message };
      }
      if (ev.error) {
        if (!r.error)
          throw new Error(
            `${where}: library failed with ${ev.error}, reference decrypted`,
          );
        checks++;
      } else {
        if (r.error)
          throw new Error(
            `${where}: reference failed (${r.error}), library decrypted`,
          );
        eq(r.plaintext, ev.plaintext, `${where}: plaintext`);
        eq(r.messageKey, ev.messageKey, `${where}: messageKey`);
      }
    }
  }
  for (const p of parties.values())
    if (!p.draw.done())
      throw new Error(
        `${label}: ${p.name}'s tape not fully consumed (${p.draw.at()}/${v.parties.find((x) => x.name === p.name).tape.length})`,
      );
  return parties;
}

for (const f of ["x3dh.json", "x3dh-v2.json"])
  for (const [i, c] of read(f).cases.entries()) {
    const P = replay(c, `${f}[${i}]`);
    eq(R.hsDigest(c.handshake), c.hsDigest, `${f} hsDigest`);
    eq(R.sidOf(c.handshake), c.sid, `${f} sid`);
    if (c.info !== undefined) {
      const id = (p) => ({
        deviceId: p.deviceId,
        signPk: p.signPk,
        boxPk: p.boxPk,
      });
      eq(
        R.x3dhInfo(R.SUITE_V2, id(P.get("alice")), id(P.get("bob"))).toString(
          "hex",
        ),
        c.info,
        `${f} info`,
      );
    }
  }
for (const f of [
  "ratchet-linear.json",
  "ratchet-interleaved.json",
  "handshake-resend.json",
  "aead-ad.json",
  "aead-ad-v2.json",
  "suite-upgrade.json",
])
  replay(read(f), f);
for (const f of ["ratchet-skip.json", "session-conflict.json", "uks-v2.json"])
  read(f).cases.forEach((c, i) => replay(c, `${f}[${i}]`));

// ── report.json (SPEC §14) ───────────────────────────────────────────────────
{
  const v = read("report.json");
  replay(v, "report.json");
  const verify = (item) => {
    const m = item.message;
    const pt = R.xOpen(
      unb64u(item.messageKey),
      unb64u(m.nonce),
      unb64u(m.ciphertext),
      R.aadOf(m),
    );
    const u = pt && R.unpad(pt);
    return !!u && u.equals(enc(item.plaintext));
  };
  for (const c of v.cases)
    eq(verify(c.item), c.verifies, `report case: ${c.name}`);
  eq(
    v.cases.find((c) => c.name === "valid").verifies,
    true,
    "report valid case verifies",
  );
  for (const p of v.payloads)
    eq(
      jcsText(JSON.parse(p.payload)) === p.payload,
      p.accepted,
      `report payload: ${p.name}`,
    );
}

// ── padding.json ─────────────────────────────────────────────────────────────
{
  const v = read("padding.json");
  for (const c of v.valid) {
    eq(
      R.pad(Buffer.from(c.plaintext, "hex")).toString("hex"),
      c.padded,
      `pad ${c.plaintextLength}`,
    );
    eq(
      R.unpad(Buffer.from(c.padded, "hex")).toString("hex"),
      c.plaintext,
      `unpad ${c.plaintextLength}`,
    );
  }
  for (const c of v.invalid)
    eq(R.unpad(Buffer.from(c.padded, "hex")), null, `unpad rejects: ${c.why}`);
  let threw = false;
  try {
    R.pad(Buffer.alloc(8193));
  } catch {
    threw = true;
  }
  eq(threw, true, "pad 8193");
}

// ── bundle.json ──────────────────────────────────────────────────────────────
{
  const v = read("bundle.json");
  const p = new Party(v.parties[0], v.startTime);
  p.bundle(true);
  const b = v.bundle;
  eq(b64u(R.edPub(p.signSk)), b.deviceSignPk, "bundle deviceSignPk");
  eq(b64u(p.boxPk), b.deviceBoxPk, "bundle deviceBoxPk");
  eq(
    b64u(R.edSign(p.signSk, R.boxPkPayload(p.deviceId, p.boxPk))),
    b.deviceBoxPkSig,
    "deviceBoxPkSig",
  );
  eq(
    b64u(
      R.edSign(
        p.signSk,
        R.spkPayload(p.deviceId, 1, p.spk.pk, b.createdAt, b.suites),
      ),
    ),
    b.spkSig,
    "spkSig",
  );
  const verify = (x) =>
    R.edVerify(
      unb64u(x.deviceSignPk),
      R.boxPkPayload(x.deviceId, unb64u(x.deviceBoxPk)),
      unb64u(x.deviceBoxPkSig),
    ) &&
    R.edVerify(
      unb64u(x.deviceSignPk),
      R.spkPayload(x.deviceId, x.spkId, unb64u(x.spkPk), x.createdAt, x.suites),
      unb64u(x.spkSig),
    );
  eq(verify(b), true, "bundle verifies");
  for (const n of v.negatives)
    if (n.result === "E2EE_BUNDLE_SIGNATURE_INVALID")
      eq(verify(n.bundle), false, `bundle negative: ${n.name}`);
  eq(p.draw.done(), true, "bundle tape consumed");
}

// ── device-list.json ─────────────────────────────────────────────────────────
{
  const v = read("device-list.json");
  const draw = R.tape(v.seed, v.tape);
  draw(32, "health");
  draw(32, "health");
  const account = draw(32, "seed");
  const { sig, ...body } = v.list;
  const bytes = cat(enc("e2ee/v2/device-list"), [0], R.jcs(body));
  eq(b64u(R.edPub(account)), v.list.accountSignPk, "device list account key");
  eq(b64u(R.edSign(account, bytes)), sig, "device list signature");
  eq(b64u(R.sha256(bytes)), v.digest, "device list digest");
  for (const c of v.cases) {
    const { sig: s, ...b } = c.list;
    const ok =
      R.edVerify(
        unb64u(c.list.accountSignPk),
        cat(enc("e2ee/v2/device-list"), [0], R.jcs(b)),
        unb64u(s),
      ) && !(c.opts.minEpoch > c.list.epoch);
    eq(
      ok ? "ok" : "E2EE_DEVICE_LIST_INVALID",
      c.result,
      `device list case: ${c.name}`,
    );
  }
  for (const c of v.bundles) {
    const m = v.list.devices.some(
      (d) =>
        !d.revokedAt &&
        d.deviceId === c.bundle.deviceId &&
        d.deviceSignPk === c.bundle.deviceSignPk &&
        d.deviceBoxPk === c.bundle.deviceBoxPk,
    );
    eq(m, c.matches, `bundle match: ${c.name}`);
  }
}

// ── link.json ────────────────────────────────────────────────────────────────
{
  const v = read("link.json");
  const nd = R.tape(v.new.seed, v.new.tape);
  const od = R.tape(v.old.seed, v.old.tape);
  for (const d of [nd, od]) {
    d(32, "health");
    d(32, "health");
  }
  const accountSeed = od(32, "seed");
  const ephOldSk = od(32, "seed");
  nd(32, "seed");
  nd(32, "seed");
  const requestId = b64u(nd(16, "link-request"));
  const ephNewSk = nd(32, "seed");
  eq(requestId, v.transcriptInput.requestId, "link requestId");
  eq(b64u(R.edPub(accountSeed)), v.account.signPk, "link account key");
  const T = R.linkTranscript(v.transcriptInput);
  eq(b64u(T), v.transcript, "link transcript");
  const ephNew = R.xPub(ephNewSk);
  const ephOld = R.xPub(ephOldSk);
  eq(b64u(ephNew), v.ephNew.pk, "link ephNew");
  eq(b64u(R.linkCommit(T, ephNew)), v.commitment, "link commitment");
  eq(R.linkCode(T, ephNew, ephOld), v.code, "link code");
  const nonce = od(24, "nonce");
  const key = R.linkSealKey(T, ephOldSk, ephNew);
  const sealed = cat(
    nonce,
    R.xSeal(key, nonce, R.jcs(v.account), cat(T, ephOld, ephNew)),
  );
  eq(b64u(sealed), v.sealed, "link sealed");
  const opened = R.xOpen(
    R.linkSealKey(T, ephNewSk, ephOld),
    sealed.subarray(0, 24),
    sealed.subarray(24),
    cat(T, ephOld, ephNew),
  );
  eq(opened.toString("utf8"), jcsText(v.opened), "link opened");
  eq(nd.done() && od.done(), true, "link tapes consumed");
}

// ── wire-size.json, wire-size-v2.json ──────────────────────────────────────
for (const f of ["wire-size.json", "wire-size-v2.json"]) {
  const v = read(f);
  const m = JSON.parse(v.message);
  eq(jcsText(m), v.message, `${f} message is canonical`);
  eq(enc(v.message).length, v.bytes, `${f} byte count`);
  eq(v.bytes <= 12288, true, `${f} within MAX_WIRE_BYTES`);
  eq(R.sidOf(m.handshake), m.header.sid, `${f} sid`);
  eq(unb64u(m.ciphertext).length, 8196 + 16, `${f} ciphertext bucket`);
  eq(suiteOf(m.handshake), m.suite, `${f} handshake shape matches the suite`);
}

// ── fingerprint.json ─────────────────────────────────────────────────────────
{
  const v = read("fingerprint.json");
  const l = v.libsignal;
  const fa = R.fingerprintChain(
    Buffer.from(l.aliceIdentity, "hex"),
    l.aliceStableId,
  ).subarray(0, 32);
  const fb = R.fingerprintChain(
    Buffer.from(l.bobIdentity, "hex"),
    l.bobStableId,
  ).subarray(0, 32);
  eq(fa.toString("hex"), l.aliceFp32, "libsignal alice fp");
  eq(fb.toString("hex"), l.bobFp32, "libsignal bob fp");
  const [x, y] = [R.digits30(fa), R.digits30(fb)];
  eq(x < y ? x + y : y + x, l.displayable, "libsignal displayable");
  const lf = R.fingerprintChain(
    unb64u(v.api.local.accountSignPk),
    v.api.local.stableId,
  ).subarray(0, 32);
  const rf = R.fingerprintChain(
    unb64u(v.api.remote.accountSignPk),
    v.api.remote.stableId,
  ).subarray(0, 32);
  const [p, q] = [R.digits30(lf), R.digits30(rf)];
  eq(p < q ? p + q : q + p, v.api.digits, "safety number digits");
  eq(
    cat(R.u16(1), lf, rf).toString("hex"),
    v.api.qrPayload,
    "safety number QR payload",
  );
}

// ── jcs.json ─────────────────────────────────────────────────────────────────
{
  const v = read("jcs.json");
  for (const c of v.cases)
    eq(jcsText(c.input), c.output, `jcs ${c.output.slice(0, 30)}`);
  const cmp =
    Buffer.compare(unb64u(v.rawOrder.a), unb64u(v.rawOrder.b)) < 0
      ? "a < b"
      : "b < a";
  eq(cmp, v.rawOrder.rawBytesOrder, "raw byte order");
}

console.log(`ref: library and independent reference agree (${checks} checks)`);
