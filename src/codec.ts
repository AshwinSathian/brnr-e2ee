// Byte encodings and input rules (SPEC §1, §4.1, §4.3, §4.5). No dependencies.

const ALPHABET =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const LOOKUP = new Map([...ALPHABET].map((c, i) => [c, i]));

export function b64uEncode(bytes: Uint8Array): string {
  let out = "";
  let i = 0;
  for (; i + 3 <= bytes.length; i += 3) {
    const n =
      ((bytes[i] as number) << 16) |
      ((bytes[i + 1] as number) << 8) |
      (bytes[i + 2] as number);
    out +=
      ALPHABET.charAt(n >>> 18) +
      ALPHABET.charAt((n >>> 12) & 63) +
      ALPHABET.charAt((n >>> 6) & 63) +
      ALPHABET.charAt(n & 63);
  }
  const rest = bytes.length - i;
  if (rest === 1) {
    const n = (bytes[i] as number) << 16;
    out += ALPHABET.charAt(n >>> 18) + ALPHABET.charAt((n >>> 12) & 63);
  } else if (rest === 2) {
    const n = ((bytes[i] as number) << 16) | ((bytes[i + 1] as number) << 8);
    out +=
      ALPHABET.charAt(n >>> 18) +
      ALPHABET.charAt((n >>> 12) & 63) +
      ALPHABET.charAt((n >>> 6) & 63);
  }
  return out;
}

/** Strict base64url (SPEC §4.1): no padding, canonical. Returns null on any violation. */
export function b64uDecode(s: unknown, length?: number): Uint8Array | null {
  if (typeof s !== "string") return null;
  // A fixed length is checked on the string first, so an oversized input costs nothing to reject.
  // For a canonical string, ceil(4n / 3) characters decode to exactly n bytes.
  if (length !== undefined && s.length !== Math.ceil((length * 4) / 3))
    return null;
  const out = new Uint8Array(Math.floor((s.length * 3) / 4));
  let bits = 0;
  let acc = 0;
  let o = 0;
  for (const c of s) {
    // An unknown character decodes as 0 here and then fails the re-encode check below.
    acc = (acc << 6) | (LOOKUP.get(c) ?? 0);
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[o++] = (acc >>> bits) & 0xff;
    }
  }
  // Non-zero trailing bits fail the re-encode check.
  if (b64uEncode(out) !== s) return null;
  return out;
}

/** SPEC §4.2: a canonical X25519 public key has bit 255 clear and u < p = 2^255 − 19. `b` has 32 bytes. */
export function isCanonicalX25519(b: Uint8Array): boolean {
  const top = b[31] as number;
  if (top > 0x7f) return false;
  // u ≥ p only when the top byte is 0x7f, bytes 1..30 are 0xff and byte 0 is ≥ 0xed.
  return !(
    top === 0x7f &&
    b.subarray(1, 31).every((x) => x === 0xff) &&
    (b[0] as number) >= 0xed
  );
}

/** A canonical 32-byte X25519 public key in base64url (SPEC §4.1, §4.2), or null. */
export function decodeX25519Pk(s: unknown): Uint8Array | null {
  const b = b64uDecode(s, 32);
  return b !== null && isCanonicalX25519(b) ? b : null;
}

/** UTF-8 of a well-formed string; null if it has a lone surrogate. */
export function utf8Encode(s: string): Uint8Array | null {
  const out: number[] = [];
  for (let i = 0; i < s.length; i++) {
    let c = s.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdfff) {
      const d = s.charCodeAt(i + 1);
      if (c > 0xdbff || !(d >= 0xdc00 && d <= 0xdfff)) return null;
      c = 0x10000 + ((c - 0xd800) << 10) + (d - 0xdc00);
      i++;
    }
    if (c < 0x80) out.push(c);
    else if (c < 0x800) out.push(0xc0 | (c >> 6), 0x80 | (c & 63));
    else if (c < 0x10000)
      out.push(0xe0 | (c >> 12), 0x80 | ((c >> 6) & 63), 0x80 | (c & 63));
    else
      out.push(
        0xf0 | (c >> 18),
        0x80 | ((c >> 12) & 63),
        0x80 | ((c >> 6) & 63),
        0x80 | (c & 63),
      );
  }
  return Uint8Array.from(out);
}

/** UTF-8 for strings already known to be well formed (ids, labels, JCS output). */
export function utf8(s: string): Uint8Array {
  const b = utf8Encode(s);
  if (b === null) throw new TypeError("lone surrogate"); // unreachable for validated input
  return b;
}

/** Strict UTF-8 decode (no overlongs, surrogates or values above U+10FFFF). Null on failure. */
export function utf8DecodeStrict(b: Uint8Array): string | null {
  let s = "";
  for (let i = 0; i < b.length;) {
    const c = b[i] as number;
    if (c < 0x80) {
      s += String.fromCharCode(c);
      i++;
      continue;
    }
    // Lead byte: 110xxxxx, 1110xxxx or 11110xxx; anything else is invalid.
    const need =
      c >= 0xf8 ? 0 : c >= 0xf0 ? 3 : c >= 0xe0 ? 2 : c >= 0xc0 ? 1 : 0;
    // need 0 (a continuation byte or 0xf8+) yields cp < 0x10000 = min below, so it fails there.
    let cp = c & (0x3f >> need);
    for (let k = 1; k <= need; k++) {
      const d = b[i + k] ?? 0; // a missing byte fails the continuation check
      if ((d & 0xc0) !== 0x80) return null;
      cp = (cp << 6) | (d & 0x3f);
    }
    const min = need === 1 ? 0x80 : need === 2 ? 0x800 : 0x10000;
    if (cp < min || cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff))
      return null;
    s += String.fromCodePoint(cp);
    i += need + 1;
  }
  return s;
}

/**
 * A private copy of caller bytes, or null. new Uint8Array(x) reads a real typed array through its
 * internal length, so a subclass with a lying length getter cannot mislead later checks; a Proxy
 * or getPrototypeOf trap that throws gives null (SPEC §4.8).
 */
export function copyBytes(x: unknown): Uint8Array | null {
  try {
    return x instanceof Uint8Array ? new Uint8Array(x) : null;
  } catch {
    return null;
  }
}

export function concat(...parts: Uint8Array[]): Uint8Array {
  let n = 0;
  for (const p of parts) n += p.length;
  const out = new Uint8Array(n);
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

export function u16be(x: number): Uint8Array {
  return Uint8Array.of((x >>> 8) & 0xff, x & 0xff);
}

export function u32be(x: number): Uint8Array {
  return Uint8Array.of(
    (x >>> 24) & 0xff,
    (x >>> 16) & 0xff,
    (x >>> 8) & 0xff,
    x & 0xff,
  );
}

/** x is a non-negative safe integer. */
export function u64be(x: number): Uint8Array {
  const hi = Math.floor(x / 2 ** 32);
  // Stryker disable next-line ArithmeticOperator: for x < 2^53, x - hi / 2^32 rounds to x, whose low word is the same
  return concat(u32be(hi), u32be(x - hi * 2 ** 32));
}

/** lp(x) = u16be(len(x)) ‖ x, len(x) < 65,536 (SPEC §1). */
export function lp(x: Uint8Array): Uint8Array {
  if (x.length >= 65536) throw new RangeError("lp: too long"); // unreachable for validated input
  return concat(u16be(x.length), x);
}

/** Lexicographic unsigned byte compare. */
export function compareBytes(a: Uint8Array, b: Uint8Array): number {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) {
    const d = (a[i] as number) - (b[i] as number);
    if (d !== 0) return d;
  }
  return a.length - b.length;
}

const ID_RE = /^[A-Za-z0-9._:-]+$/;

/** Opaque id (SPEC §4.3): 1..128 bytes of [A-Za-z0-9._:-]. */
export const isOpaqueId = (s: unknown): s is string =>
  typeof s === "string" && s.length <= 128 && ID_RE.test(s);

/** stableId (SPEC §4.3): 1..256 bytes of well-formed UTF-8. */
export function isStableId(s: unknown): s is string {
  if (typeof s !== "string") return false;
  const b = utf8Encode(s);
  return b !== null && b.length >= 1 && b.length <= 256;
}

const MIN_STAMP = Date.UTC(2000, 0, 1);
const MAX_STAMP = Date.UTC(10000, 0, 1) - 1;

// Stryker disable next-line Regex: dropping an anchor still fails, through the exact round trip below
const TS_RE = /^(\d{4})-(\d\d)-(\d\d)T(\d\d):(\d\d):(\d\d)\.(\d{3})Z$/;

/**
 * SPEC §4.5. Returns ms since the epoch, or null. Fields come from the pattern and Date.UTC (never
 * Date.parse, whose behaviour varies across engines). The exact round trip through toISOString rejects
 * impossible dates (Feb 30), hours past 23 and leap seconds; the bounds pin the year to [2000, 9999].
 */
export function parseTimestamp(s: unknown): number | null {
  if (typeof s !== "string") return null;
  const m = TS_RE.exec(s);
  if (m === null) return null;
  const f = m.slice(1).map(Number) as [
    number,
    number,
    number,
    number,
    number,
    number,
    number,
  ];
  const t = Date.UTC(f[0], f[1] - 1, f[2], f[3], f[4], f[5], f[6]);
  if (!(t >= MIN_STAMP && t <= MAX_STAMP)) return null;
  return new Date(t).toISOString() === s ? t : null;
}

export const isTimestamp = (s: unknown): s is string =>
  parseTimestamp(s) !== null;

/** ms(s) for a stamp that has already been validated. */
export const ms = (s: string): number => parseTimestamp(s) as number;

export const iso = (t: number): string => new Date(t).toISOString();

export const MAX_INT = 2 ** 31 - 1;

export const isIntIn = (x: unknown, lo: number, hi: number): x is number =>
  Number.isSafeInteger(x) &&
  !Object.is(x, -0) &&
  (x as number) >= lo &&
  (x as number) <= hi;
