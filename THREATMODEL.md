# Threat model

This document says what `brnr-e2ee` protects, against whom, and where it stops. SPEC.md is the normative protocol; section numbers below refer to it. **The library has had no independent security audit.**

## Assets

- Message plaintext and the message keys that protect it.
- Long-term keys: the account signing key, device signing and box keys, signed prekeys (SPK) and one-time prekeys (OTP).
- Session state: root, chain and skipped message keys.
- The binding between a conversation, its two devices and their identity keys.

## Adversaries

| Adversary                    | Can                                                                                                               | The library aims to                                                                                                                                           |
| ---------------------------- | ----------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Network or server (active)   | Read, drop, delay, reorder, replay and forge any message; serve any bundle or device list; fake recovery triggers | Keep plaintext confidential and authentic; detect replays inside the retained window; bound forced recoveries                                                 |
| Server that substitutes keys | Serve its own bundle or device list                                                                               | Fail when the consumer pins identity keys (§19 item 4) and compares safety numbers (§12)                                                                      |
| Peer device                  | Send any message it can encrypt                                                                                   | Not crash, corrupt state or exhaust memory beyond the stated limits                                                                                           |
| Later compromise of a device | Read current state and long-term keys                                                                             | Forward secrecy for messages whose keys were already deleted; post-compromise security once the peer completes a DH ratchet step on the active session (§8.1) |

Local malware, a compromised OS, and physical access to an unlocked device are out of scope.

## What the design provides

- **Authenticated key agreement.** X3DH (§6) with separate Ed25519 and X25519 keys. The initiator's box key is checked in constant time against a pin the caller supplies (§6.4 step 3), never against the message itself. Under suite v2 the initiator's signing key is pinned too, and the handshake names the device it was made for.
- **Identity binding (suite v2).** Both devices' id, signing key and box key go into the X3DH KDF and every message key, and the associated data names the recipient device. A bundle that pairs one device's id with another device's keys gives the two sides different keys, so the unknown-key-share attacks on v1 fail (§6.5).
- **Message confidentiality and integrity.** The Double Ratchet (§7) with XChaCha20-Poly1305. The AAD covers the version, suite, associated data, header (sid, dh, pn, n) and handshake. The message key also binds both identity keys and the associated data (§7.4).
- **Replay detection.** Inside the retained window (§7.6): receive counters, skipped keys, 64 previous ratchet keys per session, 32 accepted handshakes per state, and the device-level per-SPK replay set (§8.6). A replay never changes state.
- **Strict input handling.** Canonical base64url, exact lengths, strict schemas, low-order and small-order key rejection, ciphertext-length checks before any cryptography, and typed errors only (§4, §16).
- **Crash safety.** OTP private keys are deleted only after the session that used them is durable, and replay records are retried after a crash (§8.5, §10.2).

## Known limits and accepted risks

Each item was found during design review or SPEC review (SPEC.md §20) and accepted rather than fixed.

1. **No independent audit.** The adversarial reviews were automated and run by the author.
2. **Forced recoveries.** Recovery triggers arrive before authentication. A hostile server can force up to 3 re-initiations or refreshes, together, per conversation per 24 hours of the device's clock, which can delay a genuine recovery by up to a day (§8.4). A clock that jumps forward counts as time passing, so whoever controls the device clock (for example through spoofed NTP) can force more.
3. **Messages on an evicted session are lost.** A state keeps at most 3 sessions and drops sessions idle for more than 30 days. Delivery resumes through recovery (§8.3).
4. **Clock jumps.** A forward jump beyond 30 days drops skipped keys and idle sessions on the next commit (§9.3). Stamps more than 24 hours in the future are re-stamped. A clock stepped backwards only delays expiry, sightings later than the current time are ignored, and the recovery tracker keeps the latest time it has seen so a backwards step can't reset its limits (§8.4).
5. **3-DH founding messages are replayable while their SPK exists.** The per-SPK replay set covers this, provided consumers keep the set as long as the SPK private key and write the replay records (§8.6, §19 items 5 and 6).
6. **OTPs are not signed.** A server that substitutes or omits the OTP causes `E2EE_OTP_UNKNOWN` (denial of service) or forces 3-DH (§5.4).
7. **`sid` is 64 bits.** A second preimage costs about 2^64 work and yields only `E2EE_INVALID_INPUT`, a denial of service.
8. **No memory zeroisation.** Keys pass through JavaScript strings, which cannot be wiped (§11).
9. **Metadata is visible.** The server sees who talks to whom, when, message sizes (bucketed, §7.5), session ids and handshakes. There is no header encryption or sealed sender (§2, deferred). Control messages look like any other message to the server, so an app that sends a push notification per message also sends one for each control message.
10. **Report disclosure is not franking.** A disclosure reveals one message's key and plaintext. It does not prove authorship cryptographically (§14).
11. **State rollback.** Restoring session state from a backup loses messages. The library does not detect it, and consumers must not do it (§19 item 8).
12. **Error codes reveal local state.** `E2EE_OTP_UNKNOWN`, `E2EE_DUPLICATE_MESSAGE` and `E2EE_SESSION_CONFLICT` reveal what a device holds. Consumers must never send codes or their timing to the server (§16, §19 item 10).
13. **Device lists.** Two different lists with the same epoch can only come from the account-key holder. Consumers who need to detect that pin `(epoch, deviceListDigest)` (§5.5).
14. **Release pipeline.** Each release is built and published by `.github/workflows/release.yml` through npm trusted publishing, so no long-lived npm token exists, and every tarball carries a Sigstore provenance attestation naming the commit and workflow run that built it. Provenance says where a tarball was built, not that its source is safe: anyone who controls the owner's GitHub account, or can change the workflow on `main`, can publish. The npm trust is tied to the workflow file, not to a branch, so a workflow changed on any branch could publish if the `npm` environment let it run. The environment only accepts `v*.*.*` tags, only admins can create those tags, and the publish job waits for the owner's approval. Builds are not reproduced on a second, independent machine.
15. **Post-quantum.** None. PQXDH and post-quantum ratchets are deferred (§2).
16. **Side-channel blinding depends on WebCrypto.** `@noble/curves` 2.4.0 probes `globalThis.crypto.getRandomValues` once at load and uses it to blind secret scalar multiplications. Where it is missing (for example Hermes without a polyfill installed before the library loads), noble falls back to its unblinded constant-time path. The `rng` passed to `createE2ee` is used only for the library's own draws (§15), not for this blinding.
17. **Retired sessions accept messages for 48 hours.** Once the peer confirms the active session, older sessions are retired: they can never become active again and are deleted 48 hours later (§8.1). Until then they still decrypt. Someone holding a stolen copy of an older state can therefore forge incoming messages on a retired session for up to 48 hours after it was retired, or up to about 72 hours if the device clock ran up to 24 hours fast when it was retired. They can't read anything the device sends, because the device never sends on a retired session.
18. **Sessions newer than the confirmed one aren't retired.** Retirement never touches a session after the confirming one in the state's creation order, so an unanswered newer session stays exposed to someone holding a stolen copy of the state until it's confirmed or expires.
19. **Retirement races.** Simultaneous initiation can, rarely, leave each side active on a session the other has retired. Messages still decrypt for 48 hours, and recovery then brings both sides onto a new session (§8.1, "Stuck races").
20. **The RNG is trusted.** `createE2ee` refuses the test RNGs unless `dangerouslyAllowTestRng` is set (a wrapped test RNG, for example `rng.bind(null)`, isn't recognised), and catches an RNG that returns the same seed twice in a row, but it can't tell a weak or predictable RNG from a good one (§15).
21. **First contact can still be v1.** A device keeps listing v1 on its SPKs so that 1.0 peers can reach it, and the owner of a bundle chooses its suite list. While a responder's SPK lists v1, an attacker who publishes a v1-only bundle around that SPK can still mount the v1 unknown-key-share. Once a conversation is on v2 it never goes back to v1. Consumers close the gap by publishing SPKs that list only v2 and passing `suite: v2` to `initiateSession` once all their clients run 1.1.0 (§6.5, §19 item 17).
22. **Account membership isn't bound.** A signed device list can name another account's real device, since all its keys are public, and v2 can't tell. Consumers that care must reject a device key that appears in two accounts' lists (§6.5, §19).

## Consumer responsibilities

The guarantees above hold only if consumers follow SPEC.md §19. The ones with security impact:

- pin `expectedPeerBoxPk` and `expectedPeerSignPk` from a verified bundle or device list, never from the message (item 4);
- move to v2-only SPKs and `suite: v2` once every client supports it (item 17);
- persist state before sending, and route every operation through `withSession` (items 2, 3);
- keep retired SPKs and their replay sets for the delivery window, and flush pending lists before deleting a session (items 5, 6);
- provide a secure RNG where `globalThis.crypto` is missing (item 1).
