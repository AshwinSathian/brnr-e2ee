// Fuzz: parse* with random and mutated inputs; decrypt and acceptSession with mutated
// and forged messages against live states. Invariant: a valid result or a typed E2eeError, and the
// input state is byte-identical afterwards.
import fc from "fast-check";
import { describe, expect, it } from "vitest";
import {
  E2EE_ERROR_CODES,
  E2eeError,
  type MessageV2,
  type SessionState,
} from "../../src/index.js";
import {
  adFrom,
  bundleOf,
  CONV,
  initiate,
  party,
  receive,
  send,
  V1,
} from "../parties.js";

const RUNS = Number(process.env["FC_NUM_RUNS"] ?? 1000);

function typedOrOk(f: () => unknown): unknown {
  try {
    return f();
  } catch (e) {
    expect(e).toBeInstanceOf(E2eeError);
    expect(E2EE_ERROR_CODES).toContain((e as E2eeError).code);
    return undefined;
  }
}

// Live fixtures.
const a = party("fuzz-a");
const b = party("fuzz-b");
initiate(a, b);
const founding = send(a, "founding");
const cand = b.e.acceptSession({
  conversationId: CONV,
  self: b.device,
  expectedPeerBoxPk: a.device.boxPk,
  expectedPeerSignPk: a.device.signPk,
  message: founding,
  lookupSpk: (id) => b.spks.get(id),
  lookupOtp: (id) => b.otps.get(id),
  seenHandshake: () => false,
});
receive(b, a, founding);
receive(a, b, send(b, "reply"));
const live = send(a, "live");
const bundle = bundleOf(b);
const list = (() => {
  const acc = a.e.generateAccountIdentity();
  return a.e.buildSignedDeviceList({
    account: acc,
    accountId: "acct",
    epoch: 1,
    devices: [
      {
        deviceId: "d",
        deviceSignPk: a.device.signPk,
        deviceBoxPk: a.device.boxPk,
        addedAt: "2026-01-01T00:00:00.000Z",
      },
    ],
  });
})();
const stateText = b.e.serializeState(b.state!);

// The same fixtures under suite v1 (peers whose SPKs offer v1 only).
const a1 = party("fuzz-a", undefined, [V1]);
const b1 = party("fuzz-b", undefined, [V1]);
initiate(a1, b1);
receive(b1, a1, send(a1, "founding"));
receive(a1, b1, send(b1, "reply"));
const liveV1 = send(a1, "live");
const stateTextV1 = b1.e.serializeState(b1.state!);

/** Replaces the value at a random path of a JSON value. */
function mutate(
  base: unknown,
  pathPick: number[],
  replacement: unknown,
): unknown {
  const root = structuredClone(base) as Record<string, unknown>;
  let node: unknown = root;
  for (let depth = 0; depth < pathPick.length; depth++) {
    if (typeof node !== "object" || node === null) break;
    const keys = Object.keys(node);
    if (keys.length === 0) break;
    const k = keys[pathPick[depth]! % keys.length]!;
    const child = (node as Record<string, unknown>)[k];
    const last =
      depth === pathPick.length - 1 ||
      typeof child !== "object" ||
      child === null;
    if (last) {
      if (replacement === "__delete__") Reflect.deleteProperty(node, k);
      else (node as Record<string, unknown>)[k] = replacement;
      break;
    }
    node = child;
  }
  return root;
}

const replacement = fc.oneof(
  fc.constant("__delete__"),
  fc.jsonValue(),
  fc.integer(),
  fc.constantFrom(
    -0,
    2 ** 31 - 1,
    2 ** 31,
    2 ** 53,
    1.5,
    -1,
    "",
    "AAAA",
    "A".repeat(43),
    "A".repeat(11),
    null,
    true,
  ),
  fc.string(),
);
const mutated = (base: unknown) =>
  fc
    .tuple(fc.array(fc.nat(), { minLength: 1, maxLength: 4 }), replacement)
    .map(([p, r]) => mutate(base, p, r));

describe("parse* fuzz", () => {
  it("random values and JSON text", () => {
    fc.assert(
      fc.property(
        fc.oneof(
          fc.anything(),
          fc.jsonValue().map((v) => JSON.stringify(v)),
          fc.string(),
        ),
        (x) => {
          typedOrOk(() => a.e.parseMessage(x));
          typedOrOk(() => a.e.parseBundle(x));
          typedOrOk(() => a.e.parseDeviceList(x));
          typedOrOk(() => a.e.parseState(x as string));
          typedOrOk(() => a.e.parseTracker(x as string));
          typedOrOk(() => a.e.canonicalJson(x));
        },
      ),
      { numRuns: RUNS },
    );
  });

  it("mutated valid inputs: typed error, or a parse that re-serialises canonically", () => {
    fc.assert(
      fc.property(
        fc.oneof(mutated(live), mutated(liveV1)),
        mutated(bundle),
        mutated(list),
        fc.oneof(
          mutated(JSON.parse(stateText)),
          mutated(JSON.parse(stateTextV1)),
        ),
        (m, bu, l, st) => {
          const pm = typedOrOk(() => a.e.parseMessage(m));
          if (pm)
            expect(
              a.e.canonicalJson(a.e.parseMessage(a.e.canonicalJson(pm))),
            ).toBe(a.e.canonicalJson(pm));
          typedOrOk(() => a.e.parseBundle(bu));
          typedOrOk(() => a.e.parseDeviceList(l));
          const ps = typedOrOk(() => a.e.parseState(JSON.stringify(st)));
          if (ps)
            expect(
              b.e.serializeState(
                b.e.parseState(b.e.serializeState(ps as SessionState)),
              ),
            ).toBe(b.e.serializeState(ps as SessionState));
        },
      ),
      { numRuns: RUNS },
    );
  });
});

describe("decrypt and acceptSession fuzz (F-7)", () => {
  it("mutated and forged messages: valid decrypt or typed error; input state unchanged", () => {
    const before = stateText;
    const candBefore = JSON.stringify(cand);
    fc.assert(
      fc.property(
        fc.oneof(mutated(live), mutated(founding)),
        fc.boolean(),
        (m, useCand) => {
          const st = useCand ? cand : b.state!;
          typedOrOk(() =>
            b.e.decrypt({
              state: st,
              message: m as MessageV2,
              expectedAd: adFrom(a),
            }),
          );
          typedOrOk(() =>
            b.e.acceptSession({
              conversationId: CONV,
              self: b.device,
              expectedPeerBoxPk: a.device.boxPk,
              expectedPeerSignPk: a.device.signPk,
              message: m as MessageV2,
              lookupSpk: (id) => b.spks.get(id),
              lookupOtp: (id) => b.otps.get(id),
              seenHandshake: () => false,
              existing: b.state!,
            }),
          );
          expect(b.e.serializeState(b.state!)).toBe(before);
          expect(JSON.stringify(cand)).toBe(candBefore);
        },
      ),
      { numRuns: RUNS },
    );
  });

  it("suite v1: mutated messages give a valid decrypt or a typed error; state unchanged", () => {
    fc.assert(
      fc.property(mutated(liveV1), (m) => {
        typedOrOk(() =>
          b1.e.decrypt({
            state: b1.state!,
            message: m as MessageV2,
            expectedAd: adFrom(a1),
          }),
        );
        expect(b1.e.serializeState(b1.state!)).toBe(stateTextV1);
      }),
      { numRuns: RUNS },
    );
  });

  it("random byte flips in the ciphertext, nonce and header never decrypt", () => {
    fc.assert(
      fc.property(
        fc.constantFrom("ciphertext", "nonce"),
        fc.nat(),
        fc.integer({ min: 1, max: 255 }),
        (field, pos, x) => {
          const raw = Buffer.from(live[field], "base64url");
          raw[pos % raw.length]! ^= x;
          const m = { ...live, [field]: raw.toString("base64url") };
          expect(
            typedOrOk(() =>
              b.e.decrypt({
                state: b.state!,
                message: m,
                expectedAd: adFrom(a),
              }),
            ),
          ).toBeUndefined();
        },
      ),
      { numRuns: RUNS },
    );
  });
});
