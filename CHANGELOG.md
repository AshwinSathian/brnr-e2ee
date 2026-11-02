# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow SemVer. Any wire-format or label change is a new suite id ([SPEC §18](SPEC.md#18-versioning)).

## [Unreleased]

## [1.1.0] - 2026-11-02

The first public release, and the first on npm. Before publishing, the library went through an adversarial review: six attack passes, one per part of the protocol, each trying to break it with working exploit tests. This release fixes what they found. Every exploit is kept in `test/security/` as a regression test. The 1.0.0 vectors are unchanged, byte for byte.

### Security

- **v1 allowed an unknown-key-share.** Nothing proves that whoever signs a bundle holds its box key, and v1 binds only box keys. So Eve could publish a bundle with her own id and signing key around Bob's box key and prekey: Alice would think she was talking to Eve while Bob read her messages, or Bob would put Alice's messages down to Eve. The new suite `x25519-xchacha20poly1305-sha256-v2` binds both devices' id, signing key and box key into the X3DH KDF, the handshake, the message key and the AD, and `acceptSession` checks a new `expectedPeerSignPk` pin. New SPKs list v2 first, and a conversation that reaches v2 never goes back to v1. v1 stays for 1.0 peers, so a first contact can still be v1; SPEC §6.5 and §19 item 17 say how to turn it off.
- **Post-compromise security held only for the active session.** Someone with a stolen copy of a device's state could forge a message on an idle older session, kept for up to 30 days, make it active again, and read what the device sent next. Older sessions are now retired once the peer confirms the active one. A retired session never becomes active again, still decrypts for 48 hours for messages in flight, and is then deleted. Which sessions count as older follows the order they were created in, not their timestamps, so correcting a fast clock can't stop a retirement (SPEC §8.1).
- **A server could crash clients with an oversized device list.** About 900 KB of JSON made validation allocate around 560 MB before the 64-device cap was checked. Every array in wire and state structs is now bounded, and caps are checked before the entries are parsed. Base64url and ciphertext lengths are checked before decoding (SPEC §4.1, §4.7, §9.2).
- **The recovery limit was 4 per 24 hours, not 3.** Refreshes, which an unauthenticated `E2EE_SKIP_TOO_LARGE` can trigger, weren't counted. They now share the limit, and the recovery tracker remembers the latest time it has seen, so stepping the clock back can't reset the limit (SPEC §8.4).
- X25519 public keys must be canonical, and parsers accept only plain objects, nested ones included (SPEC §4.2, §4.8).
- `createE2ee` refuses the test RNGs from `brnr-e2ee/testing` unless you pass `dangerouslyAllowTestRng: true`, and fails if the RNG returns the same seed twice in a row (SPEC §15).
- zod 4.6.5 → 4.6.6, for [GHSA-mrhx-c7xc-m3w5](https://github.com/advisories/GHSA-mrhx-c7xc-m3w5).

### Added

- Suite `x25519-xchacha20poly1305-sha256-v2`, with its vectors. The v2 AD carries `recipientDeviceId`.
- `LIMITS.RETIRED_SESSION_TTL_MS` (48 hours) and `LIMITS.MAX_PENDING_RECORDS` (256). Both bound local state only, so they aren't suite changes.
- Optional `retiredAt` on each session in the state, reported by `inspectSession`, and optional `seenAt` on the recovery tracker. States and trackers written by 1.0.0 still parse.
- An API reference, built with TypeDoc and published to GitHub Pages.
- CI on every push and pull request, including Node 22.12, 22 and 24, `publint` and Are the Types Wrong. CONTRIBUTING.md, a code of conduct, issue forms, OpenSSF Scorecard and Dependabot.

### Changed

- **Upgrading:** pass `expectedPeerSignPk` to `acceptSession`, taken from the same verified bundle or device-list entry as `expectedPeerBoxPk`. A v2 founding message without it fails with `E2EE_INVALID_INPUT`, and a 1.1.0 peer sends v2 by default. Build the AD with `recipientDeviceId` when the state's suite is v2; the README's quick start shows how.
- The package is now `brnr-e2ee` (it was `@brnr/e2ee`), under the MIT licence; 1.0.0 was proprietary.
- Releases are published from GitHub Actions through npm trusted publishing, with a provenance attestation. The SSH-signed manifest and the vendored tarball are retired.
- `isE2eeError` also recognises errors thrown by the other build of the package (ESM or CommonJS).

## [1.0.0] - 2026-10-22

First release. Suite `x25519-xchacha20poly1305-sha256-v1`, wire `v: 2`. **No independent security audit.** Released privately as `@brnr/e2ee`, as a signed tarball; it was never on npm.

### Added

- X3DH (3-DH and 4-DH), the Double Ratchet with XChaCha20-Poly1305, padding buckets and AD binding (SPEC §6, §7).
- Sesame-style sessions: up to three per peer device, routing by `sid`, activation on receive, eviction, pruning and re-stamping; strict versioned state (SPEC §8, §9).
- `withSession` and the `KeyStore` contract with crash-safe OTP deletion and the per-SPK handshake replay set (SPEC §8.5, §8.6, §10).
- Recovery tracker with rate limits and a refresh limit (SPEC §8.4).
- Signed device bundles and device lists, safety numbers, the device-link ceremony and report disclosure (SPEC §5, §12-§14).
- Typed errors from a closed union of 19 codes (SPEC §16).
- Deterministic vectors (`vectors/*.json`), an independent reference implementation used to check them, known-answer and Wycheproof tests, a fast-check command model, fuzzing, a counted-operation benchmark and mutation testing.

### Specification changes made during implementation

SPEC.md §20 records the design decisions made while this version was implemented.
