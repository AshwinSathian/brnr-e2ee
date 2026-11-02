// withSession (SPEC §10.2): lock, load, flush crash leftovers, run fn, persist, flush.
import { isOpaqueId } from "./codec.js";
import { fail } from "./errors.js";
import type {
  E2ee,
  KeyStore,
  PutSessionOptions,
  RecoveryTrackerV1,
  SessionState,
  WithSessionFn,
} from "./types.js";

interface Lists {
  conversationId: string;
  peerDeviceId: string;
  pendingOtpDeletes: number[];
  pendingReplayRecords: Array<{ spkId: number; hsDigest: string }>;
}
const lists = (s: SessionState): Lists => s as unknown as Lists;

const STORE_METHODS = [
  "getSession",
  "putSession",
  "getSpk",
  "getOtp",
  "deleteOtp",
  "hasAcceptedHandshake",
  "withLock",
] as const;

export async function withSession<T>(
  e2ee: E2ee,
  store: KeyStore,
  peerDeviceId: string,
  conversationId: string,
  fn: WithSessionFn<T>,
): Promise<T> {
  if (!isOpaqueId(peerDeviceId) || !isOpaqueId(conversationId))
    fail("E2EE_INVALID_INPUT", "invalid peerDeviceId or conversationId");
  if (typeof fn !== "function")
    fail("E2EE_INVALID_INPUT", "fn is not a function");
  for (const k of STORE_METHODS)
    if (
      typeof (store as unknown as Record<string, unknown> | null)?.[k] !==
      "function"
    )
      fail("E2EE_INVALID_INPUT", `store.${k} is not a function`);
  return store.withLock(conversationId, async () => {
    // 1.
    const loaded = await store.getSession(peerDeviceId, conversationId);
    let version = loaded?.version ?? null;
    let state =
      loaded?.serialized != null ? e2ee.parseState(loaded.serialized) : null;
    const tracker =
      loaded?.tracker != null ? e2ee.parseTracker(loaded.tracker) : null;
    // 2. Flush device-level records left by an earlier crash.
    let flushed = false;
    if (state !== null) {
      const l = lists(state);
      if (l.pendingOtpDeletes.length > 0 || l.pendingReplayRecords.length > 0) {
        version = await store.putSession(
          peerDeviceId,
          conversationId,
          null,
          version,
          {
            deleteOtpIds: [...l.pendingOtpDeletes],
            acceptedHandshakes: l.pendingReplayRecords.map((r) => ({ ...r })),
          },
        );
        for (const id of l.pendingOtpDeletes) await store.deleteOtp(id);
        state = {
          ...state,
          pendingOtpDeletes: [],
          pendingReplayRecords: [],
        } as unknown as SessionState;
        flushed = true;
      }
    }
    // 3.
    const out: unknown = await fn(state, tracker);
    const proto =
      typeof out === "object" && out !== null
        ? (Object.getPrototypeOf(out) as unknown)
        : undefined;
    // A plain object only (SPEC §4.8): prototype Object.prototype or null.
    if (proto !== Object.prototype && proto !== null)
      return fail(
        "E2EE_INVALID_INPUT",
        "fn must return { state, tracker, result }",
      );
    const o = out as {
      state?: SessionState | null;
      tracker?: RecoveryTrackerV1 | null;
      result: T;
    };
    // 4. null or undefined tracker = unchanged; compare serialised forms.
    const outTracker =
      o.tracker == null ? null : e2ee.serializeTracker(o.tracker);
    const trackerChanged =
      outTracker !== null &&
      (tracker === null || outTracker !== e2ee.serializeTracker(tracker));
    if (o.state != null || trackerChanged || flushed) {
      const raw = o.state ?? (flushed ? state : null);
      const serialized = raw ? e2ee.serializeState(raw) : null;
      // Everything below reads the validated copy, never the caller's object again.
      const S = serialized === null ? null : e2ee.parseState(serialized);
      const opts: PutSessionOptions = {};
      if (outTracker !== null) opts.tracker = outTracker;
      if (S) {
        const l = lists(S);
        if (
          l.conversationId !== conversationId ||
          l.peerDeviceId !== peerDeviceId
        )
          fail(
            "E2EE_INVALID_INPUT",
            "fn returned a state for another conversation or peer",
          );
        opts.deleteOtpIds = [...l.pendingOtpDeletes];
        opts.acceptedHandshakes = l.pendingReplayRecords.map((r) => ({ ...r }));
      }
      await store.putSession(
        peerDeviceId,
        conversationId,
        serialized,
        version,
        opts,
      );
      if (S)
        for (const id of lists(S).pendingOtpDeletes) await store.deleteOtp(id);
    }
    // 5.
    return o.result;
  });
}
