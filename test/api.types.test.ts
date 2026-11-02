// Type-level contract test: imports every public name and pins each signature.
import { describe, expectTypeOf, it } from "vitest";
import {
  createE2ee,
  E2EE_ERROR_CODES,
  E2eeError,
  isE2eeError,
  LIMITS,
  SUITES,
  withSession,
  type AccountIdentityKeyPair,
  type AssociatedData,
  type AssociatedDataV1,
  type AssociatedDataV2,
  type B64u,
  type DecryptResult,
  type DeviceBundleV2,
  type DeviceIdentityKeyPair,
  type E2ee,
  type E2eeErrorCode,
  type E2eeOptions,
  type HandshakeV2,
  type KeyStore,
  type MessageHeader,
  type MessageV2,
  type OneTimePrekeyPair,
  type RecoveryReason,
  type RecoveryTrackerV1,
  type ReportDisclosureV1,
  type Rng,
  type RngPurpose,
  type SafetyNumber,
  type SessionInfo,
  type SessionState,
  type SignedDeviceList,
  type SignedPrekeyPair,
  type StoredSession,
  type SuiteId,
  type WithSessionFn,
} from "../src/index.js";

describe("public API shape", () => {
  it("constants", () => {
    expectTypeOf(SUITES).toEqualTypeOf<readonly SuiteId[]>();
    expectTypeOf(LIMITS.MAX_SKIP).toEqualTypeOf<1000>();
    expectTypeOf(E2EE_ERROR_CODES).toEqualTypeOf<readonly E2eeErrorCode[]>();
    expectTypeOf<SuiteId>().toEqualTypeOf<
      | "x25519-xchacha20poly1305-sha256-v2"
      | "x25519-xchacha20poly1305-sha256-v1"
    >();
  });

  it("errors", () => {
    expectTypeOf<
      ConstructorParameters<typeof E2eeError>[0]
    >().toEqualTypeOf<E2eeErrorCode>();
    expectTypeOf(
      new E2eeError("E2EE_DECRYPT_FAILED", "message", { reason: "x" }),
    ).toEqualTypeOf<E2eeError>();
    expectTypeOf<E2eeError["code"]>().toEqualTypeOf<E2eeErrorCode>();
    expectTypeOf(isE2eeError).guards.toEqualTypeOf<E2eeError>();
  });

  it("factories", () => {
    expectTypeOf(createE2ee).toEqualTypeOf<(opts?: E2eeOptions) => E2ee>();
    expectTypeOf(withSession<number>).parameters.toEqualTypeOf<
      [E2ee, KeyStore, string, string, WithSessionFn<number>]
    >();
    expectTypeOf<Rng>().toEqualTypeOf<
      (n: number, purpose?: RngPurpose) => Uint8Array
    >();
  });

  it("wire structs carry v", () => {
    expectTypeOf<MessageV2["v"]>().toEqualTypeOf<2>();
    expectTypeOf<HandshakeV2["v"]>().toEqualTypeOf<2>();
    expectTypeOf<AssociatedData["v"]>().toEqualTypeOf<2>();
    expectTypeOf<DeviceBundleV2["v"]>().toEqualTypeOf<2>();
    expectTypeOf<SignedDeviceList["v"]>().toEqualTypeOf<1>();
    expectTypeOf<AccountIdentityKeyPair["v"]>().toEqualTypeOf<1>();
    expectTypeOf<DeviceIdentityKeyPair["v"]>().toEqualTypeOf<1>();
    expectTypeOf<SignedPrekeyPair["v"]>().toEqualTypeOf<1>();
    expectTypeOf<OneTimePrekeyPair["v"]>().toEqualTypeOf<1>();
    expectTypeOf<RecoveryTrackerV1["v"]>().toEqualTypeOf<1>();
    expectTypeOf<ReportDisclosureV1["v"]>().toEqualTypeOf<1>();
    expectTypeOf<SessionState["v"]>().toEqualTypeOf<2>();
  });

  it("header carries sid and SPK carries suites", () => {
    expectTypeOf<MessageHeader>().toEqualTypeOf<{
      sid: B64u;
      dh: B64u;
      pn: number;
      n: number;
    }>();
    expectTypeOf<SignedPrekeyPair["suites"]>().toEqualTypeOf<string[]>();
  });

  it("session methods", () => {
    expectTypeOf<E2ee["decrypt"]>().returns.toEqualTypeOf<DecryptResult>();
    expectTypeOf<E2ee["inspectSession"]>().returns.toEqualTypeOf<SessionInfo>();
    expectTypeOf<E2ee["acceptSession"]>()
      .parameter(0)
      .toHaveProperty("seenHandshake");
    expectTypeOf<E2ee["acceptSession"]>()
      .parameter(0)
      .toHaveProperty("lookupOtp");
    expectTypeOf<E2ee["initiateSession"]>()
      .parameter(0)
      .toHaveProperty("existing");
    expectTypeOf<E2ee["recordRecoverySignal"]>()
      .parameter(1)
      .toEqualTypeOf<RecoveryReason>();
    expectTypeOf<
      E2ee["computeSafetyNumber"]
    >().returns.toEqualTypeOf<SafetyNumber>();
  });

  it("suite v2 API (SPEC §6.1, §6.4, §7.4, §9.4)", () => {
    expectTypeOf<AssociatedData>().toEqualTypeOf<
      AssociatedDataV1 | AssociatedDataV2
    >();
    expectTypeOf<AssociatedDataV1>().toEqualTypeOf<{
      conversationId: string;
      senderDeviceId: string;
      suite: "x25519-xchacha20poly1305-sha256-v1";
      v: 2;
    }>();
    expectTypeOf<AssociatedDataV2>().toEqualTypeOf<{
      conversationId: string;
      senderDeviceId: string;
      recipientDeviceId: string;
      suite: "x25519-xchacha20poly1305-sha256-v2";
      v: 2;
    }>();
    expectTypeOf<HandshakeV2>().toEqualTypeOf<{
      v: 2;
      initiatorBoxPk: B64u;
      initiatorSignPk?: B64u;
      initiatorEphPk: B64u;
      responderDeviceId?: string;
      responderSignPk?: B64u;
      spkId: number;
      otpId?: number;
    }>();
    expectTypeOf<
      Parameters<E2ee["acceptSession"]>[0]["expectedPeerSignPk"]
    >().toEqualTypeOf<B64u | undefined>();
    expectTypeOf<SessionInfo["suite"]>().toEqualTypeOf<SuiteId>();
  });

  it("handshake digest export and suite lists (SPEC §6.1, §20.9)", () => {
    expectTypeOf<E2ee["handshakeDigest"]>().returns.toEqualTypeOf<B64u>();
    expectTypeOf<DeviceBundleV2["suites"]>().toEqualTypeOf<string[]>();
  });

  it("KeyStore", () => {
    expectTypeOf<KeyStore["getSession"]>().returns.toEqualTypeOf<
      Promise<StoredSession | null>
    >();
    expectTypeOf<KeyStore["hasAcceptedHandshake"]>().returns.toEqualTypeOf<
      Promise<boolean>
    >();
    expectTypeOf<KeyStore["deleteOtp"]>().returns.toEqualTypeOf<
      Promise<void>
    >();
  });
});
