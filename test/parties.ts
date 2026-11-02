// Two-party test fixture: devices, prekey stores and the SPEC §8.3 receive flow.
import type {
  AssociatedData,
  DeviceBundleV2,
  DeviceIdentityKeyPair,
  E2ee,
  MessageV2,
  OneTimePrekeyPair,
  SessionState,
  SignedPrekeyPair,
} from "../src/index.js";
import { E2eeError, SUITES, type SuiteId } from "../src/index.js";
import { makeE2ee, testClock } from "./helpers.js";

export const CONV = "conv-1";

export interface Party {
  name: string;
  e: E2ee;
  device: DeviceIdentityKeyPair;
  spks: Map<number, SignedPrekeyPair>;
  otps: Map<number, OneTimePrekeyPair>;
  replay: Set<string>;
  state: SessionState | null;
  nextOtp: number;
}

export const V1 = "x25519-xchacha20poly1305-sha256-v1" as const;
export const V2 = "x25519-xchacha20poly1305-sha256-v2" as const;

/** A party whose SPK offers `suites` (default SUITES: v2, then v1). */
export function party(
  name: string,
  clock = testClock(),
  suites: SuiteId[] = [...SUITES],
): Party {
  const { e } = makeE2ee(name, clock);
  const device = e.generateDeviceIdentity(`${name}-dev`);
  const spk = e.generateSignedPrekey(device, 1, suites);
  const p: Party = {
    name,
    e,
    device,
    spks: new Map([[1, spk]]),
    otps: new Map(),
    replay: new Set(),
    state: null,
    nextOtp: 1,
  };
  return p;
}

/** The bundle the server would serve, optionally with a fresh OTP. */
export function bundleOf(
  p: Party,
  withOtp = true,
  spkId = Math.max(...p.spks.keys()),
): DeviceBundleV2 {
  const spk = p.spks.get(spkId) as SignedPrekeyPair;
  const b: DeviceBundleV2 = p.e.buildDeviceBundle({ device: p.device, spk });
  if (!withOtp) return b;
  const [otp] = p.e.generateOneTimePrekeys(p.nextOtp++, 1) as [
    OneTimePrekeyPair,
  ];
  p.otps.set(otp.otpId, otp);
  return { ...b, otp: { otpId: otp.otpId, pk: otp.pk } };
}

/** The AD of `suite` (SPEC §7.4): v2 also names the recipient device. */
export const adOf = (
  suite: SuiteId,
  sender: string,
  recipient: string,
): AssociatedData =>
  suite === V2
    ? {
        conversationId: CONV,
        senderDeviceId: sender,
        recipientDeviceId: recipient,
        suite,
        v: 2,
      }
    : { conversationId: CONV, senderDeviceId: sender, suite, v: 2 };

/** The AD `p` sends with: its state's suite and peer (SUITES[0] and `to` before it has a state). */
export function adFrom(p: Party, to?: Party): AssociatedData {
  const st = p.state as { suite: SuiteId; peerDeviceId: string } | null;
  return adOf(
    st?.suite ?? SUITES[0]!,
    p.device.deviceId,
    to?.device.deviceId ?? st?.peerDeviceId ?? "unknown-dev",
  );
}

export function send(from: Party, text: string): MessageV2 {
  const { state, message } = from.e.encrypt({
    state: from.state as SessionState,
    plaintext: new TextEncoder().encode(text),
    ad: adFrom(from),
  });
  from.state = state;
  return message;
}

/** The AD a receiver expects for `m`: the message's suite, `from` to `to`. */
export const expectedAdOf = (
  m: MessageV2,
  from: Party,
  to: Party,
): AssociatedData => adOf(m.suite, from.device.deviceId, to.device.deviceId);

/** SPEC §8.3: decrypt, and on SESSION_CONFLICT or no state, accept then decrypt. Commits on success only. */
export function receive(to: Party, from: Party, m: MessageV2): string {
  const e = to.e;
  let state = to.state;
  const doAccept = () =>
    e.acceptSession({
      conversationId: CONV,
      self: to.device,
      expectedPeerBoxPk: from.device.boxPk,
      expectedPeerSignPk: from.device.signPk,
      message: m,
      lookupSpk: (id) => to.spks.get(id),
      lookupOtp: (id) => to.otps.get(id),
      seenHandshake: (id, d) => to.replay.has(`${id}:${d}`),
      ...(state ? { existing: state } : {}),
    });
  if (state === null) state = doAccept();
  let r;
  try {
    r = e.decrypt({ state, message: m, expectedAd: expectedAdOf(m, from, to) });
  } catch (err) {
    if (!(err instanceof E2eeError) || err.code !== "E2EE_SESSION_CONFLICT")
      throw err;
    const candidate = doAccept();
    r = e.decrypt({
      state: candidate,
      message: m,
      expectedAd: expectedAdOf(m, from, to),
    });
  }
  commit(to, r.state);
  return new TextDecoder().decode(r.plaintext);
}

/** What withSession would persist: device-level records applied, lists emptied. */
export function commit(p: Party, state: SessionState): void {
  const info = p.e.inspectSession(state);
  for (const id of info.pendingOtpDeletes) p.otps.delete(id);
  for (const r of info.pendingReplayRecords)
    p.replay.add(`${r.spkId}:${r.hsDigest}`);
  p.state = p.e.parseState(p.e.serializeState(state));
}

/** Alice initiates to Bob. */
export function initiate(a: Party, b: Party, withOtp = true): void {
  a.state = a.e.initiateSession({
    conversationId: CONV,
    self: a.device,
    peerBundle: bundleOf(b, withOtp),
    ...(a.state ? { existing: a.state } : {}),
  });
}
