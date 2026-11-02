# Reference specifications

Local copies of Signal's specifications, which their authors placed in the public domain:

- `x3dh.html.txt`: The X3DH Key Agreement Protocol, revision 1.
- `dr.html.txt`: The Double Ratchet Algorithm, revision 4 (2025-11-04).
- `sesame.html.txt`: The Sesame Algorithm, revision 2.

libsignal's `rust/protocol/src/fingerprint.rs` is AGPL-3.0 and is deliberately **not** copied here. The fingerprint code is written from its description, and only its published test-vector values are reused (SPEC.md §Fingerprint records where they come from).
