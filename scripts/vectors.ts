// Builds vectors/*.json from fixed seeds and the SPEC §15 DRBG tape. CLI: scripts/gen-vectors.ts.

import {
  createE2ee,
  E2eeError,
  type SuiteId,
  type AssociatedData,
  type DeviceBundleV2,
  type DeviceIdentityKeyPair,
  type E2ee,
  type MessageV2,
  type OneTimePrekeyPair,
  type SessionState,
  type SignedPrekeyPair,
} from "../src/index.js";
import {
  drbgRng,
  fingerprintChain,
  digits30,
  type TapeEntry,
} from "../src/testing.js";
import { b64uDecode, b64uEncode } from "../src/codec.js";
import { pad, unpad } from "../src/ratchet.js";
import { canonicalJson } from "../src/jcs.js";
import { boxPkSigPayload, spkSigPayload } from "../src/keys.js";
import { ed25519Sign } from "../src/primitives.js";
import { sidOf, x3dhInfo } from "../src/x3dh.js";

const V1 = "x25519-xchacha20poly1305-sha256-v1" as const;
const V2 = "x25519-xchacha20poly1305-sha256-v2" as const;

const T0 = Date.UTC(2026, 9, 22, 12, 0, 0);
const CONV = "conv-vectors";
const hex = (b: Uint8Array): string => Buffer.from(b).toString("hex");
const fromHex = (h: string): Uint8Array =>
  Uint8Array.from(Buffer.from(h, "hex"));
const enc = new TextEncoder();
const dec = new TextDecoder();

/** Seed = SHA-256-free, fixed and readable: the label's UTF-8, zero-padded to 32 bytes. */
function seedFor(label: string): Uint8Array {
  const s = new Uint8Array(32);
  s.set(enc.encode(label).subarray(0, 32));
  return s;
}

const tapeJson = (t: TapeEntry[]) =>
  t.map((x) => ({ purpose: x.purpose, bytes: hex(x.bytes) }));

class Party {
  readonly e: E2ee;
  readonly tape: TapeEntry[];
  readonly device: DeviceIdentityKeyPair;
  readonly spks = new Map<number, SignedPrekeyPair>();
  spk: SignedPrekeyPair;
  readonly otps = new Map<number, OneTimePrekeyPair>();
  readonly replay = new Set<string>();
  state: SessionState | null = null;
  private nextOtp = 1;

  readonly name: string;
  readonly clock: { ms: number };

  readonly suites: SuiteId[];

  constructor(name: string, clock: { ms: number }, suites: SuiteId[] = [V1]) {
    this.name = name;
    this.clock = clock;
    this.suites = suites;
    const { rng, tape } = drbgRng(seedFor(`vector/${name}`));
    this.tape = tape;
    this.e = createE2ee({
      rng,
      now: () => new Date(clock.ms),
      dangerouslyAllowTestRng: true,
    });
    this.device = this.e.generateDeviceIdentity(`${name}-dev`);
    this.spk = this.e.generateSignedPrekey(this.device, 1, suites);
    this.spks.set(1, this.spk);
  }

  /** A new SPK with the next id, offering `suites` (an upgrade). */
  rotate(suites: SuiteId[]): void {
    const id = this.spk.spkId + 1;
    this.spk = this.e.generateSignedPrekey(this.device, id, suites);
    this.spks.set(id, this.spk);
  }

  bundle(otp: boolean): DeviceBundleV2 {
    const b: DeviceBundleV2 = this.e.buildDeviceBundle({
      device: this.device,
      spk: this.spk,
    });
    if (!otp) return b;
    const [o] = this.e.generateOneTimePrekeys(this.nextOtp++, 1) as [
      OneTimePrekeyPair,
    ];
    this.otps.set(o.otpId, o);
    return { ...b, otp: { otpId: o.otpId, pk: o.pk } };
  }

  /** The AD encrypt expects: the active session's suite, sender and (v2) recipient (SPEC §7.4). */
  ad(): AssociatedData {
    const st = JSON.parse(this.e.serializeState(this.state!)) as {
      suite: SuiteId;
      peerDeviceId: string;
    };
    return adOf(st.suite, this.device.deviceId, st.peerDeviceId);
  }

  json() {
    return {
      name: this.name,
      seed: hex(seedFor(`vector/${this.name}`)),
      deviceId: this.device.deviceId,
      // Absent means the SPK offers suite v1 only, as in every vector written before suite v2.
      ...(this.suites.length === 1 && this.suites[0] === V1
        ? {}
        : { suites: this.suites }),
      tape: tapeJson(this.tape),
    };
  }
}

const adOf = (
  suite: SuiteId,
  sender: string,
  recipient: string,
): AssociatedData =>
  suite === V2
    ? {
        conversationId: CONV,
        senderDeviceId: sender,
        recipientDeviceId: recipient,
        suite: V2,
        v: 2,
      }
    : { conversationId: CONV, senderDeviceId: sender, suite: V1, v: 2 };

/**
 * The unknown-key-share bundle (SPEC §6.5): `signer` signs, under her own device key and `deviceId`,
 * a bundle that carries the victim's box key and SPK. Every signature in it verifies.
 */
function forge(
  b: DeviceBundleV2,
  signer: Party,
  deviceId: string,
): DeviceBundleV2 {
  const sk = b64uDecode(signer.device.signSk)!;
  const sign = (m: Uint8Array) => b64uEncode(ed25519Sign(sk, m));
  return {
    ...b,
    deviceId,
    deviceSignPk: signer.device.signPk,
    deviceBoxPkSig: sign(boxPkSigPayload(deviceId, b.deviceBoxPk)),
    spkSig: sign(
      spkSigPayload(deviceId, b.spkId, b.spkPk, b.createdAt, b.suites),
    ),
  };
}

type Event =
  | {
      type: "initiate";
      by: string;
      to: string;
      otp: boolean;
      reset?: boolean;
      /** UKS vectors: the bundle is re-signed by this party under `deviceId`, keeping `to`'s keys. */
      forgedBy?: string;
      deviceId?: string;
    }
  | { type: "rotate"; by: string; suites: SuiteId[] }
  | {
      type: "send";
      by: string;
      /** Only in vectors with more than two parties. */
      to?: string;
      plaintext: string;
      message?: string;
      drop?: boolean;
    }
  | {
      type: "recv";
      by: string;
      from: string;
      message: number;
      tamper?: string;
      /** UKS vectors: the receiver pins this party's signing key instead of `from`'s. */
      pinSignOf?: string;
      plaintext?: string;
      messageKey?: string;
      error?: string;
      reason?: string;
    }
  | { type: "advance"; ms: number };

/** Runs a scripted conversation through the public API and records everything. */
class Script {
  readonly clock = { ms: T0 };
  readonly parties = new Map<string, Party>();
  readonly events: Event[] = [];
  readonly messages: MessageV2[] = [];

  constructor(names: string[], suites: Record<string, SuiteId[]> = {}) {
    for (const n of names)
      this.parties.set(n, new Party(n, this.clock, suites[n]));
  }

  p(n: string): Party {
    return this.parties.get(n)!;
  }

  initiate(
    by: string,
    to: string,
    otp = true,
    reset = false,
    forged?: { by: string; deviceId: string },
  ): void {
    const a = this.p(by);
    if (reset) a.state = null;
    let peerBundle = this.p(to).bundle(otp);
    if (forged)
      peerBundle = forge(peerBundle, this.p(forged.by), forged.deviceId);
    a.state = a.e.initiateSession({
      conversationId: CONV,
      self: a.device,
      peerBundle,
      ...(a.state ? { existing: a.state } : {}),
    });
    this.events.push({
      type: "initiate",
      by,
      to,
      otp,
      ...(reset ? { reset } : {}),
      ...(forged ? { forgedBy: forged.by, deviceId: forged.deviceId } : {}),
    });
  }

  rotate(by: string, suites: SuiteId[]): void {
    this.p(by).rotate(suites);
    this.events.push({ type: "rotate", by, suites });
  }

  send(by: string, plaintext: string, drop = false, to?: string): number {
    const a = this.p(by);
    const r = a.e.encrypt({
      state: a.state!,
      plaintext: enc.encode(plaintext),
      ad: a.ad(),
    });
    a.state = r.state;
    this.messages.push(r.message);
    const dest = to === undefined ? {} : { to };
    this.events.push(
      drop
        ? { type: "send", by, ...dest, plaintext, drop }
        : {
            type: "send",
            by,
            ...dest,
            plaintext,
            message: canonicalJson(r.message),
          },
    );
    return this.messages.length - 1;
  }

  advance(ms: number): void {
    this.clock.ms += ms;
    this.events.push({ type: "advance", ms });
  }

  /** SPEC §8.3 receive flow. `tamper` rewrites the message first and never commits. */
  recv(
    by: string,
    from: string,
    index: number,
    tamper?: [string, (m: MessageV2) => MessageV2],
    pinSignOf?: string,
  ): void {
    const b = this.p(by);
    const a = this.p(from);
    const signPin = this.p(pinSignOf ?? from).device.signPk;
    const m = tamper
      ? tamper[1](structuredClone(this.messages[index]!))
      : this.messages[index]!;
    const ev: Extract<Event, { type: "recv" }> = {
      type: "recv",
      by,
      from,
      message: index,
      ...(tamper ? { tamper: tamper[0] } : {}),
      ...(pinSignOf ? { pinSignOf } : {}),
    };
    const expectedAd = adOf(m.suite, a.device.deviceId, b.device.deviceId);
    const accept = (existing: SessionState | null) =>
      b.e.acceptSession({
        conversationId: CONV,
        self: b.device,
        expectedPeerBoxPk: a.device.boxPk,
        expectedPeerSignPk: signPin,
        message: m,
        lookupSpk: (id) => b.spks.get(id),
        lookupOtp: (id) => b.otps.get(id),
        seenHandshake: (id, d) => b.replay.has(`${id}:${d}`),
        ...(existing ? { existing } : {}),
      });
    try {
      let r;
      if (b.state === null)
        r = b.e.decrypt({
          state: accept(null),
          message: m,
          expectedAd,
        });
      else
        try {
          r = b.e.decrypt({ state: b.state, message: m, expectedAd });
        } catch (err) {
          if (
            !(err instanceof E2eeError) ||
            err.code !== "E2EE_SESSION_CONFLICT"
          )
            throw err;
          r = b.e.decrypt({
            state: accept(b.state),
            message: m,
            expectedAd,
          });
        }
      ev.plaintext = dec.decode(r.plaintext);
      ev.messageKey = b64uEncode(r.messageKey);
      if (!tamper) {
        const info = b.e.inspectSession(r.state);
        for (const id of info.pendingOtpDeletes) b.otps.delete(id);
        for (const x of info.pendingReplayRecords)
          b.replay.add(`${x.spkId}:${x.hsDigest}`);
        b.state = r.state;
      }
    } catch (err) {
      if (!(err instanceof E2eeError)) throw err;
      ev.error = err.code;
      const reason = err.details?.["reason"];
      if (typeof reason === "string") ev.reason = reason;
    }
    this.events.push(ev);
  }

  json(description: string, extra: Record<string, unknown> = {}) {
    return {
      description,
      generator: "scripts/gen-vectors.ts",
      conversationId: CONV,
      startTime: new Date(T0).toISOString(),
      ...extra,
      parties: [...this.parties.values()].map((p) => p.json()),
      events: this.events,
    };
  }
}

/** Builds every vector file in memory: name → exact file text. */
export function buildVectors(): Record<string, string> {
  const files: Record<string, unknown> = {};

  // ── x3dh.json ──────────────────────────────────────────────────────────────
  {
    const out = [];
    for (const otp of [true, false]) {
      const s = new Script(["alice", "bob"]);
      s.initiate("alice", "bob", otp);
      s.recv("bob", "alice", s.send("alice", `x3dh ${otp ? "4-DH" : "3-DH"}`));
      const h = s.messages[0]!.handshake!;
      out.push(
        s.json(
          otp
            ? "X3DH with a one-time prekey (4-DH)"
            : "X3DH without a one-time prekey (3-DH)",
          {
            handshake: h,
            hsDigest: s.p("bob").e.handshakeDigest(h),
            sid: s.messages[0]!.header.sid,
          },
        ),
      );
    }
    files["x3dh.json"] = {
      description: "X3DH (SPEC §6) with and without OTP",
      cases: out,
    };
  }

  // ── ratchet-linear.json ────────────────────────────────────────────────────
  {
    const s = new Script(["alice", "bob"]);
    s.initiate("alice", "bob");
    for (let i = 0; i < 4; i++) {
      s.recv("bob", "alice", s.send("alice", `a${i}`));
      s.recv("alice", "bob", s.send("bob", `b${i}`));
    }
    files["ratchet-linear.json"] = s.json(
      "Linear Double Ratchet: alternating messages, one DH ratchet per turn (SPEC §7)",
    );
  }

  // ── ratchet-interleaved.json (D1) ──────────────────────────────────────────
  {
    const s = new Script(["alice", "bob"]);
    s.initiate("alice", "bob");
    const a1 = s.send("alice", "a1");
    const a2 = s.send("alice", "a2");
    const a3 = s.send("alice", "a3");
    s.recv("bob", "alice", a1);
    s.recv("alice", "bob", s.send("bob", "b1"));
    const a4 = s.send("alice", "a4 (pn = 3)");
    s.recv("bob", "alice", a4);
    s.recv("bob", "alice", a3);
    s.recv("bob", "alice", a2);
    s.recv("bob", "alice", a2);
    files["ratchet-interleaved.json"] = s.json(
      "Previous-chain messages after a DH ratchet via pn skipping (D1, DR §3.5); final replay → E2EE_DUPLICATE_MESSAGE",
    );
  }

  // ── ratchet-skip.json ──────────────────────────────────────────────────────
  {
    const cases = [];
    for (const gap of [1, 999, 1000, 1001]) {
      const s = new Script(["alice", "bob"]);
      s.initiate("alice", "bob");
      s.recv("bob", "alice", s.send("alice", "first"));
      s.recv("alice", "bob", s.send("bob", "reply"));
      for (let i = 0; i < gap; i++) s.send("alice", "dropped", true);
      s.recv("bob", "alice", s.send("alice", `after gap ${gap}`));
      cases.push(
        s.json(
          `Skip gap ${gap} on the current chain: ${gap <= 1000 ? "ok" : "E2EE_SKIP_TOO_LARGE"}`,
        ),
      );
    }
    files["ratchet-skip.json"] = {
      description: "MAX_SKIP edges (SPEC §7.6)",
      cases,
    };
  }

  // ── handshake-resend.json (D3) ─────────────────────────────────────────────
  {
    const s = new Script(["alice", "bob"]);
    s.initiate("alice", "bob");
    s.send("alice", "dropped first message", true);
    const m2 = s.send("alice", "second carries the handshake");
    s.recv("bob", "alice", m2);
    s.recv("bob", "alice", s.send("alice", "third still carries it"));
    s.recv("alice", "bob", s.send("bob", "reply"));
    s.recv("bob", "alice", s.send("alice", "fourth has no handshake"));
    files["handshake-resend.json"] = s.json(
      "Handshake on every message until the first inbound decrypt (D3, SPEC §8.1)",
    );
  }

  // ── session-conflict.json ──────────────────────────────────────────────────
  {
    const cases = [];
    {
      const s = new Script(["alice", "bob"]);
      s.initiate("alice", "bob");
      s.initiate("bob", "alice");
      const a1 = s.send("alice", "a1");
      const b1 = s.send("bob", "b1");
      s.recv("bob", "alice", a1);
      s.recv("alice", "bob", b1);
      s.recv("bob", "alice", s.send("alice", "a2"));
      s.recv("alice", "bob", s.send("bob", "b2"));
      cases.push(s.json("Simultaneous initiation converges (R1-1)"));
    }
    {
      const s = new Script(["alice", "bob"]);
      s.initiate("alice", "bob");
      s.recv("bob", "alice", s.send("alice", "a1"));
      s.recv("alice", "bob", s.send("bob", "b1"));
      s.initiate("alice", "bob", true, true);
      s.recv("bob", "alice", s.send("alice", "after reset"));
      s.recv("alice", "bob", s.send("bob", "b2"));
      cases.push(
        s.json(
          "Peer reset: a new handshake on an unknown sid is accepted (SESSION_CONFLICT flow)",
        ),
      );
    }
    {
      const s = new Script(["alice", "bob"]);
      s.initiate("alice", "bob", false);
      const f = s.send("alice", "founding");
      s.recv("bob", "alice", f);
      for (let i = 0; i < 3; i++) {
        s.advance(1000);
        s.initiate("alice", "bob", true);
        s.recv("bob", "alice", s.send("alice", `reinit ${i}`));
      }
      s.recv("bob", "alice", f);
      cases.push(
        s.json(
          "Replayed old founding message after its session was evicted → E2EE_DUPLICATE_MESSAGE (evicted-session)",
        ),
      );
    }
    files["session-conflict.json"] = {
      description: "Routing by sid (SPEC §8.2, §8.3)",
      cases,
    };
  }

  // ── aead-ad.json ───────────────────────────────────────────────────────────
  {
    const s = new Script(["alice", "bob"]);
    s.initiate("alice", "bob");
    const m = s.send("alice", "bound");
    const other = b64uEncode(new Uint8Array(32).fill(7));
    const t: Array<[string, (x: MessageV2) => MessageV2]> = [
      [
        "header.n",
        (x) => ({ ...x, header: { ...x.header, n: x.header.n + 1 } }),
      ],
      [
        "header.pn",
        (x) => ({ ...x, header: { ...x.header, pn: x.header.pn + 1 } }),
      ],
      ["header.dh", (x) => ({ ...x, header: { ...x.header, dh: other } })],
      [
        "header.sid",
        (x) => ({ ...x, header: { ...x.header, sid: "AAAAAAAAAAA" } }),
      ],
      [
        "handshake.initiatorEphPk",
        (x) => ({
          ...x,
          handshake: { ...x.handshake!, initiatorEphPk: other },
        }),
      ],
      [
        "ad.senderDeviceId",
        (x) => ({ ...x, ad: { ...x.ad, senderDeviceId: "mallory-dev" } }),
      ],
      ["nonce", (x) => ({ ...x, nonce: b64uEncode(new Uint8Array(24)) })],
    ];
    for (const tm of t) s.recv("bob", "alice", m, tm);
    s.recv("bob", "alice", m);
    // Same chain (dh == DHr, CKr set): pn plays no part in key derivation here, so only the AAD rejects it.
    const m2 = s.send("alice", "same chain");
    s.recv("bob", "alice", m2, [
      "header.pn (same chain)",
      (x) => ({ ...x, header: { ...x.header, pn: x.header.pn + 1 } }),
    ]);
    s.recv("bob", "alice", m2);
    files["aead-ad.json"] = s.json(
      "Tampering with sid, dh, pn, n, handshake, AD or nonce fails; the untampered message then decrypts (SPEC §7.4). The last tamper changes an AAD-only field.",
    );
  }

  // ── x3dh-v2.json ──────────────────────────────────────────────────────────
  const BOTH = { alice: [V2, V1], bob: [V2, V1], eve: [V2, V1] };
  {
    const out = [];
    for (const otp of [true, false]) {
      const s = new Script(["alice", "bob"], BOTH);
      s.initiate("alice", "bob", otp);
      s.recv(
        "bob",
        "alice",
        s.send("alice", `x3dh v2 ${otp ? "4-DH" : "3-DH"}`),
      );
      s.recv("alice", "bob", s.send("bob", "reply"));
      s.recv("bob", "alice", s.send("alice", "after a DH ratchet"));
      const h = s.messages[0]!.handshake!;
      const a = s.p("alice").device;
      const b = s.p("bob").device;
      out.push(
        s.json(
          otp
            ? "Suite v2 X3DH with a one-time prekey (4-DH), then one round trip"
            : "Suite v2 X3DH without a one-time prekey (3-DH), then one round trip",
          {
            handshake: h,
            hsDigest: s.p("bob").e.handshakeDigest(h),
            sid: s.messages[0]!.header.sid,
            info: hex(x3dhInfo(V2, a, b)),
          },
        ),
      );
    }
    files["x3dh-v2.json"] = {
      description:
        "Suite v2 X3DH (SPEC §6.2): the KDF info binds both device identities; handshake, digest and sid",
      cases: out,
    };
  }

  // ── aead-ad-v2.json ─────────────────────────────────────────────────────────
  {
    const s = new Script(["alice", "bob"], BOTH);
    s.initiate("alice", "bob");
    const m = s.send("alice", "bound");
    const other = b64uEncode(new Uint8Array(32).fill(7));
    const t: Array<[string, (x: MessageV2) => MessageV2]> = [
      [
        "header.n",
        (x) => ({ ...x, header: { ...x.header, n: x.header.n + 1 } }),
      ],
      ["header.dh", (x) => ({ ...x, header: { ...x.header, dh: other } })],
      [
        "handshake.initiatorEphPk",
        (x) => ({
          ...x,
          handshake: { ...x.handshake!, initiatorEphPk: other },
        }),
      ],
      [
        "ad.senderDeviceId",
        (x) => ({ ...x, ad: { ...x.ad, senderDeviceId: "mallory-dev" } }),
      ],
      [
        "ad.recipientDeviceId",
        (x) => ({ ...x, ad: { ...x.ad, recipientDeviceId: "mallory-dev" } }),
      ],
      ["nonce", (x) => ({ ...x, nonce: b64uEncode(new Uint8Array(24)) })],
    ];
    for (const tm of t) s.recv("bob", "alice", m, tm);
    s.recv("bob", "alice", m);
    s.recv("alice", "bob", s.send("bob", "reply"));
    const m2 = s.send("alice", "after a DH ratchet");
    s.recv("bob", "alice", m2, [
      "ad.recipientDeviceId",
      (x) => ({ ...x, ad: { ...x.ad, recipientDeviceId: "mallory-dev" } }),
    ]);
    s.recv("bob", "alice", m2);
    files["aead-ad-v2.json"] = s.json(
      "Suite v2 (SPEC §7.4): tampering with the header, handshake, AD (including recipientDeviceId) or nonce fails; the untampered message then decrypts",
    );
  }

  // ── uks-v2.json ─────────────────────────────────────────────────────────────
  {
    const retarget = (bob: Party): [string, (x: MessageV2) => MessageV2] => [
      "retarget to bob",
      (x) => {
        const handshake = {
          ...x.handshake!,
          responderDeviceId: bob.device.deviceId,
          responderSignPk: bob.device.signPk,
        };
        return {
          ...x,
          handshake,
          header: { ...x.header, sid: sidOf(handshake) },
          ad: { ...x.ad, recipientDeviceId: bob.device.deviceId },
        };
      },
    ];
    const cases = [];
    for (const deviceId of ["eve-dev", "bob-dev"]) {
      const s = new Script(["alice", "bob", "eve"], BOTH);
      s.initiate("alice", "bob", true, false, { by: "eve", deviceId });
      const m = s.send("alice", "for Eve only", false, "bob");
      s.recv("bob", "alice", m);
      s.recv("bob", "alice", m, retarget(s.p("bob")));
      cases.push(
        s.json(
          `Eve signs a bundle under deviceId ${deviceId} carrying Bob's box key and SPK; Alice's suite v2 message to it is refused by Bob (E2EE_IDENTITY_MISMATCH), and rewriting the handshake to name Bob fails the AEAD`,
        ),
      );
    }
    {
      const s = new Script(["alice", "bob", "eve"], BOTH);
      s.initiate("alice", "bob");
      const m = s.send("alice", "for Bob", false, "bob");
      const eve = s.p("eve").device;
      s.recv("bob", "alice", m, undefined, "eve");
      s.recv(
        "bob",
        "alice",
        m,
        [
          "initiatorSignPk = eve",
          (x) => {
            const handshake = { ...x.handshake!, initiatorSignPk: eve.signPk };
            return {
              ...x,
              handshake,
              header: { ...x.header, sid: sidOf(handshake) },
            };
          },
        ],
        "eve",
      );
      s.recv("bob", "alice", m);
      cases.push(
        s.json(
          "Bob pins, for Eve's device, Alice's box key and Eve's signing key: Alice's suite v2 message is refused (E2EE_IDENTITY_MISMATCH), rewriting initiatorSignPk to Eve's fails the AEAD, and with the right pins it decrypts",
        ),
      );
    }
    files["uks-v2.json"] = {
      description:
        "Unknown-key-share attempts against suite v2 (SPEC §6.5). Every refused receive leaves Bob without a session.",
      cases,
    };
  }

  // ── suite-upgrade.json ──────────────────────────────────────────────────────
  {
    const s = new Script(["alice", "bob"], { alice: [V1], bob: [V1] });
    s.initiate("alice", "bob");
    s.recv("bob", "alice", s.send("alice", "v1 hello"));
    s.recv("alice", "bob", s.send("bob", "v1 reply"));
    s.rotate("bob", [V2, V1]);
    const inflight = s.send("alice", "v1, delivered late");
    s.initiate("alice", "bob");
    s.recv("bob", "alice", s.send("alice", "first v2 message"));
    s.recv("bob", "alice", inflight);
    s.recv("alice", "bob", s.send("bob", "reply on the active session"));
    s.recv("bob", "alice", s.send("alice", "v2 again"));
    s.recv("alice", "bob", s.send("bob", "v2 reply"));
    files["suite-upgrade.json"] = s.json(
      "A v1 state gains a v2 session when the peer's new SPK offers v2 (SPEC §9.1, §18); once the state is v2, the v1 message still in flight is refused (E2EE_UNSUPPORTED_SUITE), and both sides continue on the v2 session",
    );
  }

  // ── state-schema-v2.json ────────────────────────────────────────────────────
  {
    const s = new Script(["alice", "bob"], BOTH);
    s.initiate("alice", "bob");
    s.recv("bob", "alice", s.send("alice", "x"));
    const e = s.p("bob").e;
    const raw = e.serializeState(s.p("bob").state!);
    const parsed = JSON.parse(raw) as Record<string, unknown> & {
      sessions: Array<{ founding: Record<string, unknown> }>;
    };
    const { peerSignPk: _drop, ...missing } = parsed;
    // The sid is re-derived, so only the founding identity check rejects it.
    const wrong = structuredClone(parsed) as typeof parsed & {
      activeSid: string;
      sessions: Array<{ sid: string }>;
    };
    const f = wrong.sessions[0]!.founding;
    f["responderSignPk"] = parsed["peerSignPk"];
    wrong.sessions[0]!.sid = wrong.activeSid = sidOf(f as never);
    const code = (x: string) => {
      try {
        e.parseState(x);
        return "ok";
      } catch (err) {
        return (err as E2eeError).code;
      }
    };
    const c = (name: string, serialized: string) => ({
      name,
      serialized,
      result: code(serialized),
    });
    files["state-schema-v2.json"] = {
      description:
        "SessionStateV2 with a suite v2 session (SPEC §9.1-§9.2): valid; without peerSignPk → E2EE_INVALID_STATE; a founding handshake (with its sid re-derived) that disagrees with the sign keys → E2EE_INVALID_STATE",
      cases: [
        c("valid suite v2 state", raw),
        c("missing peerSignPk", JSON.stringify(missing)),
        c("founding responderSignPk is the peer's", JSON.stringify(wrong)),
      ],
    };
  }

  // ── report.json (F-6) ──────────────────────────────────────────────────────
  {
    const s = new Script(["alice", "bob"]);
    s.initiate("alice", "bob");
    const i = s.send("alice", "report me");
    s.recv("bob", "alice", i);
    const ev = s.events.at(-1) as Extract<Event, { type: "recv" }>;
    const e = s.p("bob").e;
    const message = s.messages[i]!;
    const item = e.buildReportDisclosure([
      {
        envelopeId: "env-1",
        message,
        messageKey: b64uDecode(ev.messageKey!)!,
        plaintext: enc.encode(ev.plaintext!),
      },
    ]).items[0]!;
    const payload = canonicalJson(message);
    const spaced = JSON.stringify(message, null, 2);
    const cases = [
      { name: "valid", item },
      {
        name: "wrong key",
        item: { ...item, messageKey: b64uEncode(new Uint8Array(32).fill(1)) },
      },
      { name: "altered plaintext", item: { ...item, plaintext: "report me!" } },
    ].map((c) => ({ ...c, verifies: e.verifyReportDisclosureItem(c.item) }));
    files["report.json"] = s.json(
      "Report disclosure (SPEC §14): a valid item verifies; a wrong key or altered plaintext fails; the server accepts only the canonical payload",
      {
        cases,
        payloads: [
          {
            name: "canonical",
            payload,
            accepted: payload === canonicalJson(e.parseMessage(payload)),
          },
          {
            name: "non-canonical (indented)",
            payload: spaced,
            accepted: spaced === canonicalJson(e.parseMessage(spaced)),
          },
        ],
      },
    );
  }

  // ── padding.json ───────────────────────────────────────────────────────────
  {
    const lengths = [
      0, 1, 60, 61, 124, 125, 252, 253, 508, 509, 1020, 1021, 2044, 2045, 4092,
      4093, 8192,
    ];
    const bad = (len: number, size: number, tail = 0) => {
      const b = new Uint8Array(size);
      b.set([len >>> 24, (len >>> 16) & 255, (len >>> 8) & 255, len & 255]);
      if (tail) b[size - 1] = tail;
      return b;
    };
    const neg: Array<[string, Uint8Array]> = [
      ["non-zero padding byte", bad(3, 64, 1)],
      ["length larger than the bucket", bad(61, 64)],
      ["non-minimal bucket", bad(3, 128)],
      ["not a bucket size", bad(3, 100)],
      ["shorter than the length prefix", new Uint8Array(3)],
    ];
    files["padding.json"] = {
      description:
        "pad/unpad (SPEC §7.5): bucket edges; 8193 → E2EE_PLAINTEXT_TOO_LARGE; bad padding → E2EE_INVALID_PADDING",
      buckets: [64, 128, 256, 512, 1024, 2048, 4096, 8196],
      valid: lengths.map((n) => {
        const p = Uint8Array.from({ length: n }, (_, i) => (i * 7 + 1) & 255);
        const padded = pad(p);
        if (hex(unpad(padded)) !== hex(p)) throw new Error("pad round trip");
        return { plaintextLength: n, plaintext: hex(p), padded: hex(padded) };
      }),
      tooLarge: { plaintextLength: 8193, error: "E2EE_PLAINTEXT_TOO_LARGE" },
      invalid: neg.map(([why, b]) => {
        let error = "none";
        try {
          unpad(b);
        } catch (e) {
          error = (e as E2eeError).code;
        }
        return { why, padded: hex(b), error };
      }),
    };
  }

  // ── device-list.json ───────────────────────────────────────────────────────
  {
    const { rng, tape } = drbgRng(seedFor("vector/device-list"));
    const e = createE2ee({
      rng,
      now: () => new Date(T0),
      dangerouslyAllowTestRng: true,
    });
    const account = e.generateAccountIdentity();
    const d1 = e.generateDeviceIdentity("dev-1");
    const d2 = e.generateDeviceIdentity("dev-2");
    const at = new Date(T0).toISOString();
    const list = e.buildSignedDeviceList({
      account,
      accountId: "account-1",
      epoch: 7,
      devices: [
        {
          deviceId: d1.deviceId,
          deviceSignPk: d1.signPk,
          deviceBoxPk: d1.boxPk,
          addedAt: at,
        },
        {
          deviceId: d2.deviceId,
          deviceSignPk: d2.signPk,
          deviceBoxPk: d2.boxPk,
          addedAt: at,
          revokedAt: at,
        },
      ],
    });
    const b1 = e.buildDeviceBundle({
      device: d1,
      spk: e.generateSignedPrekey(d1, 1, [V1]),
    });
    const b2 = e.buildDeviceBundle({
      device: d2,
      spk: e.generateSignedPrekey(d2, 1, [V1]),
    });
    const code = (f: () => unknown) => {
      try {
        f();
        return "ok";
      } catch (x) {
        return (x as E2eeError).code;
      }
    };
    files["device-list.json"] = {
      description: "Signed device list (SPEC §5.5)",
      seed: hex(seedFor("vector/device-list")),
      tape: tapeJson(tape),
      list,
      digest: e.deviceListDigest(list),
      cases: [
        {
          name: "valid",
          list,
          opts: { minEpoch: 7, pinnedAccountSignPk: account.signPk },
          result: code(() =>
            e.verifySignedDeviceList(list, {
              minEpoch: 7,
              pinnedAccountSignPk: account.signPk,
            }),
          ),
        },
        {
          name: "tampered signature (epoch changed)",
          list: { ...list, epoch: 8 },
          opts: {},
          result: code(() => e.verifySignedDeviceList({ ...list, epoch: 8 })),
        },
        {
          name: "epoch rollback",
          list,
          opts: { minEpoch: 8 },
          result: code(() => e.verifySignedDeviceList(list, { minEpoch: 8 })),
        },
      ],
      bundles: [
        {
          name: "active device matches",
          bundle: b1,
          matches: e.bundleMatchesDeviceList(b1, list),
        },
        {
          name: "revoked device does not match",
          bundle: b2,
          matches: e.bundleMatchesDeviceList(b2, list),
        },
      ],
    };
  }

  // ── bundle.json ────────────────────────────────────────────────────────────
  {
    const s = new Script(["bob"]);
    const b = s.p("bob").bundle(true);
    const e = s.p("bob").e;
    const code = (x: unknown) => {
      try {
        e.verifyDeviceBundle(x as DeviceBundleV2);
        return "ok";
      } catch (err) {
        return (err as E2eeError).code;
      }
    };
    const other = b64uEncode(new Uint8Array(32).fill(9));
    const negatives: Array<[string, unknown]> = [
      ["deviceBoxPk swapped (boxpk signature)", { ...b, deviceBoxPk: other }],
      ["spkPk swapped (spk signature)", { ...b, spkPk: other }],
      ["createdAt changed", { ...b, createdAt: "2026-10-22T12:00:00.001Z" }],
      [
        "suites stripped to another id",
        { ...b, suites: ["x25519-xchacha20poly1305-sha256-v0"] },
      ],
      ["unknown v", { ...b, v: 3 }],
      ["unknown key", { ...b, extra: "x" }],
      [
        "small-order deviceSignPk",
        {
          ...b,
          deviceSignPk: b64uEncode(Uint8Array.of(1, ...new Uint8Array(31))),
        },
      ],
    ];
    files["bundle.json"] = s.json(
      "Device bundle (SPEC §5.3-§5.4): boxpk, SPK and suite-strip negatives",
      {
        bundle: b,
        result: code(b),
        negatives: negatives.map(([name, x]) => ({
          name,
          bundle: x,
          result: code(x),
        })),
      },
    );
  }

  // ── state-schema.json ──────────────────────────────────────────────────────
  {
    const s = new Script(["alice", "bob"]);
    s.initiate("alice", "bob");
    s.recv("bob", "alice", s.send("alice", "x"));
    const raw = s.p("bob").e.serializeState(s.p("bob").state!);
    const parsed = JSON.parse(raw) as Record<string, unknown>;
    const { peerDeviceId: _drop, ...missing } = parsed;
    const code = (x: string) => {
      try {
        s.p("bob").e.parseState(x);
        return "ok";
      } catch (err) {
        return (err as E2eeError).code;
      }
    };
    const brnrV1 = JSON.stringify({
      sessionId: "s",
      rootKeyB64: "AA==",
      sendChainKeyB64: "AA==",
      recvChainKeyB64: null,
    });
    files["state-schema.json"] = {
      description:
        "SessionStateV2 parse (SPEC §9.2): valid; BRNR v1 → E2EE_UNSUPPORTED_VERSION; missing field → E2EE_INVALID_STATE",
      cases: [
        { name: "valid v2 state", serialized: raw, result: code(raw) },
        { name: "BRNR v1 state", serialized: brnrV1, result: code(brnrV1) },
        {
          name: "missing peerDeviceId",
          serialized: JSON.stringify(missing),
          result: code(JSON.stringify(missing)),
        },
      ],
    };
  }

  // ── link.json ──────────────────────────────────────────────────────────────
  {
    const mk = (name: string) => {
      const { rng, tape } = drbgRng(seedFor(`vector/${name}`));
      return {
        e: createE2ee({
          rng,
          now: () => new Date(T0),
          dangerouslyAllowTestRng: true,
        }),
        tape,
        seed: hex(seedFor(`vector/${name}`)),
      };
    };
    const oldD = mk("link-old");
    const newD = mk("link-new");
    const account = oldD.e.generateAccountIdentity();
    const dev = newD.e.generateDeviceIdentity("new-device");
    const requestId = newD.e.generateLinkRequestId();
    const ephNew = newD.e.generateLinkEphemeral();
    const ephOld = oldD.e.generateLinkEphemeral();
    const transcriptInput = {
      requestId,
      accountId: "account-1",
      newDeviceId: dev.deviceId,
      newDeviceSignPk: dev.signPk,
      newDeviceBoxPk: dev.boxPk,
      suites: [V1],
    };
    const transcript = newD.e.linkTranscript(transcriptInput);
    const sealed = oldD.e.sealAccountKey({
      account,
      transcript,
      ephSelf: ephOld,
      ephPeerPk: ephNew.pk,
    });
    files["link.json"] = {
      description:
        "Device-link ceremony (SPEC §13): transcript, commitment, code and seal",
      old: { seed: oldD.seed, tape: tapeJson(oldD.tape) },
      new: { seed: newD.seed, tape: tapeJson(newD.tape) },
      account,
      transcriptInput,
      transcript,
      ephNew,
      ephOld,
      commitment: newD.e.linkCommitment(transcript, ephNew.pk),
      code: oldD.e.linkConfirmationCode({
        transcript,
        ephNewPk: ephNew.pk,
        ephOldPk: ephOld.pk,
      }),
      sealed,
      opened: newD.e.openAccountKey({
        sealed,
        transcript,
        ephSelf: ephNew,
        ephPeerPk: ephOld.pk,
      }),
    };
  }

  // ── wire-size.json, wire-size-v2.json ───────────────────────────────────────
  for (const [file, suite] of [
    ["wire-size.json", V1],
    ["wire-size-v2.json", V2],
  ] as const) {
    const conv = "c".repeat(128);
    const { rng: ra, tape: ta } = drbgRng(seedFor("vector/wire-a"));
    const { rng: rb, tape: tb } = drbgRng(seedFor("vector/wire-b"));
    const now = () => new Date(T0);
    const ea = createE2ee({ rng: ra, now, dangerouslyAllowTestRng: true });
    const eb = createE2ee({ rng: rb, now, dangerouslyAllowTestRng: true });
    const da = ea.generateDeviceIdentity("a".repeat(128));
    const db = eb.generateDeviceIdentity("b".repeat(128));
    const spk = eb.generateSignedPrekey(db, 2 ** 31 - 1, [suite]);
    const [otp] = eb.generateOneTimePrekeys(2 ** 31 - 1, 1) as [
      OneTimePrekeyPair,
    ];
    let st = ea.initiateSession({
      conversationId: conv,
      self: da,
      peerBundle: {
        ...eb.buildDeviceBundle({ device: db, spk }),
        otp: { otpId: otp.otpId, pk: otp.pk },
      },
    });
    const j = JSON.parse(ea.serializeState(st)) as {
      sessions: Array<{ ns: number; pn: number }>;
    };
    j.sessions[0]!.ns = 2 ** 31 - 2;
    j.sessions[0]!.pn = 2 ** 31 - 1;
    st = ea.parseState(JSON.stringify(j));
    const plaintext = new Uint8Array(8192).fill(0x41);
    const ad: AssociatedData =
      suite === V2
        ? {
            conversationId: conv,
            senderDeviceId: da.deviceId,
            recipientDeviceId: db.deviceId,
            suite: V2,
            v: 2,
          }
        : {
            conversationId: conv,
            senderDeviceId: da.deviceId,
            suite: V1,
            v: 2,
          };
    const { message } = ea.encrypt({ state: st, plaintext, ad });
    const wire = canonicalJson(message);
    files[file] = {
      description:
        suite === V2
          ? "Worst-case MessageV2 for suite v2: 128-byte ids (including recipientDeviceId and responderDeviceId), max counters, 4-DH handshake with max ids, 8,192-byte plaintext. JCS size must be ≤ MAX_WIRE_BYTES (12,288)."
          : "Worst-case MessageV2: 128-byte ids, max counters, 4-DH handshake with max ids, 8,192-byte plaintext. JCS size must be ≤ MAX_WIRE_BYTES (12,288).",
      tapes: { a: tapeJson(ta), b: tapeJson(tb) },
      message: wire,
      bytes: enc.encode(wire).length,
      maxWireBytes: 12288,
    };
    if (enc.encode(wire).length > 12288)
      throw new Error("wire-size over limit");
  }

  // ── fingerprint.json ───────────────────────────────────────────────────────
  {
    const alice = fromHex(
      "0506863bc66d02b40d27b8d49ca7c09e9239236f9d7d25d6fcca5ce13c7064d868",
    );
    const bob = fromHex(
      "05f781b6fb32fed9ba1cf2de978d4d5da28dc34046ae814402b5c0dbd96fda907b",
    );
    const fa = fingerprintChain(alice, "+14152222222").slice(0, 32);
    const fb = fingerprintChain(bob, "+14153333333").slice(0, 32);
    const [x, y] = [digits30(fa), digits30(fb)];
    const { rng } = drbgRng(seedFor("vector/fingerprint"));
    const e = createE2ee({
      rng,
      now: () => new Date(T0),
      dangerouslyAllowTestRng: true,
    });
    const local = {
      accountSignPk: e.generateAccountIdentity().signPk,
      stableId: "local-user",
    };
    const remote = {
      accountSignPk: e.generateAccountIdentity().signPk,
      stableId: "remote-user",
    };
    const sn = e.computeSafetyNumber({ local, remote });
    files["fingerprint.json"] = {
      description:
        "Safety numbers (SPEC §12). The libsignal case feeds the internal chain the 33-byte serialized keys.",
      source:
        "libsignal rust/protocol/src/fingerprint.rs tests (test values only; AGPL code not copied), commit b2a5c30f3245c1bcad04b27b1e752a38321c793d, fetched 2026-10-22",
      iterations: 5200,
      libsignal: {
        aliceIdentity: hex(alice),
        aliceStableId: "+14152222222",
        bobIdentity: hex(bob),
        bobStableId: "+14153333333",
        aliceFp32: hex(fa),
        bobFp32: hex(fb),
        displayable: x < y ? x + y : y + x,
      },
      api: { local, remote, digits: sn.digits, qrPayload: hex(sn.qrPayload) },
    };
  }

  // ── jcs.json ───────────────────────────────────────────────────────────────
  {
    // Two 32-byte keys whose base64url order differs from their raw byte order:
    // 0x3e... encodes to "P..." and 0xfb... to "-..."; raw 0x3e < 0xfb, but "-" < "P" in text.
    const k1 = new Uint8Array(32).fill(0x3e);
    const k2 = new Uint8Array(32).fill(0xfb);
    files["jcs.json"] = {
      description:
        "RFC 8785 subset (SPEC §4.6) and raw-bytes ordering (SPEC §1)",
      cases: [
        {
          input: { b: "2", a: "1", aa: [] },
          output: '{"a":"1","aa":[],"b":"2"}',
        },
        {
          input: { "€": "e", "\r": "r", "1": "o", ö: "x", "😀": "g", דּ: "h" },
          output: canonicalJson({
            "€": "e",
            "\r": "r",
            "1": "o",
            ö: "x",
            "😀": "g",
            דּ: "h",
          }),
        },
        {
          input: { s: '\u0000\b\t\n\f\r"\\/\u007f' },
          output: canonicalJson({ s: '\u0000\b\t\n\f\r"\\/\u007f' }),
        },
        { input: { n: [0, 1, 2147483647] }, output: '{"n":[0,1,2147483647]}' },
      ],
      rawOrder: {
        a: b64uEncode(k1),
        b: b64uEncode(k2),
        rawBytesOrder: "a < b",
        textOrder: b64uEncode(k1) < b64uEncode(k2) ? "a < b" : "b < a",
      },
    };
  }
  return Object.fromEntries(
    Object.entries(files).map(([n, d]) => [
      n,
      JSON.stringify(d, null, 1) + "\n",
    ]),
  );
}
