// createE2ee: binds the injected RNG and clock to the protocol functions.
import { createCtx } from "./context.js";
import * as dl from "./deviceList.js";
import { canonicalJson } from "./jcs.js";
import * as fp from "./fingerprint.js";
import * as keys from "./keys.js";
import * as link from "./link.js";
import * as rec from "./recovery.js";
import * as report from "./report.js";
import * as session from "./session.js";
import * as st from "./state.js";
import { handshakeDigest, parseMessage } from "./x3dh.js";
import type { E2ee, E2eeOptions } from "./types.js";

export function createE2ee(opts?: E2eeOptions): E2ee {
  const ctx = createCtx(opts);
  return {
    generateAccountIdentity: () => keys.generateAccountIdentity(ctx),
    generateDeviceIdentity: (deviceId) =>
      keys.generateDeviceIdentity(ctx, deviceId),
    generateSignedPrekey: (device, spkId, suites) =>
      keys.generateSignedPrekey(ctx, device, spkId, suites),
    generateOneTimePrekeys: (first, count) =>
      keys.generateOneTimePrekeys(ctx, first, count),
    buildDeviceBundle: (p) => keys.buildDeviceBundle(p),
    verifyDeviceBundle: (b) => {
      keys.verifyDeviceBundle(b);
    },
    parseBundle: (raw) => keys.parseBundle(raw),
    canonicalJson,
    buildSignedDeviceList: (p) => dl.buildSignedDeviceList(p),
    verifySignedDeviceList: (l, o) => dl.verifySignedDeviceList(l, o),
    deviceListDigest: dl.deviceListDigest,
    bundleMatchesDeviceList: dl.bundleMatchesDeviceList,
    handshakeDigest: handshakeDigest,
    initiateSession: (p) => session.initiateSession(ctx, p),
    acceptSession: (p) => session.acceptSession(ctx, p),
    encrypt: (p) => session.encrypt(ctx, p),
    decrypt: (p) => session.decrypt(ctx, p),
    inspectSession: (s) => st.inspect(s, ctx.clock()),
    recordRecoverySignal: (t, r) => rec.recordRecoverySignal(ctx.clock(), t, r),
    recoveryDecision: (t) => rec.recoveryDecision(ctx.clock(), t),
    refreshDecision: (t) => rec.refreshDecision(ctx.clock(), t),
    onDecrypt: (t, i) => rec.onDecrypt(ctx.clock(), t, i),
    serializeState: st.serializeState,
    parseState: st.parseState,
    serializeTracker: rec.serializeTracker,
    parseTracker: rec.parseTracker,
    parseMessage: parseMessage,
    parseDeviceList: dl.parseDeviceList,
    computeSafetyNumber: (p) => fp.computeSafetyNumber(p),
    verifySafetyNumberPayload: fp.verifySafetyNumberPayload,
    generateLinkEphemeral: () => link.generateLinkEphemeral(ctx),
    generateLinkRequestId: () => link.generateLinkRequestId(ctx),
    linkTranscript: link.linkTranscript,
    linkCommitment: link.linkCommitment,
    verifyLinkCommitment: link.verifyLinkCommitment,
    linkConfirmationCode: link.linkConfirmationCode,
    sealAccountKey: (p) => link.sealAccountKey(ctx, p),
    openAccountKey: link.openAccountKey,
    buildReportDisclosure: report.buildReportDisclosure,
    verifyReportDisclosureItem: report.verifyReportDisclosureItem,
  };
}
