// seal.ts — store an encrypted JSON payload (incl. private key) in the URL fragment.
// Uses TweetNaCl secretbox (XSalsa20-Poly1305) and scrypt-js for a memory-hard KDF.

import nacl from "tweetnacl";
import { scrypt } from "scrypt-js";
import { uint8ArrayToBase32Crockford, base32CrockfordToUint8Array } from "./encoding";

// ---------- helpers ----------
const enc = new TextEncoder();
const dec = new TextDecoder();

const b32c = {
  enc(u8: Uint8Array): string {
    return uint8ArrayToBase32Crockford(u8);
  },
  dec(s: string): Uint8Array {
    return base32CrockfordToUint8Array(s);
  },
};

// ---------- types ----------
export type ScryptParams = { N: number; r: number; p: number; salt: Uint8Array };

export interface PlainPayload<T = unknown> {
  seq: number;      // anti-rollback counter
  iat: number;      // issued-at (ms since epoch)
  context: string;  // bind to origin/app id (e.g., location.origin)
  data: T;          // your JSON payload (e.g., includes private key)
}

// ---------- KDF ----------
async function kdfScrypt(passphrase: string, params: ScryptParams): Promise<Uint8Array> {
  const pw = enc.encode(passphrase);
  const dk = await scrypt(pw, params.salt, params.N, params.r, params.p, 32);
  return new Uint8Array(dk); // 32 bytes for secretbox
}

// ---------- envelope ----------
// Fragment format (dot-separated, base32 Crockford):
// v1.scrypt.<N>.<r>.<p>.<salt>.<nonce>.<ct>
// - salt: constant per secret (random 16–32B); keep the same across rotations
// - nonce: 24B random per encryption (fresh every read/write)
// - ct: secretbox(ciphertext)
// All fields base32 Crockford except N/r/p (decimal strings).

function buildFragment(
  params: ScryptParams,
  nonce: Uint8Array,
  ct: Uint8Array
): string {
  return [
    "v1",
    "scrypt",
    String(params.N),
    String(params.r),
    String(params.p),
    b32c.enc(params.salt),
    b32c.enc(nonce),
    b32c.enc(ct),
  ].join(".");
}

function parseFragment(fragment: string): {
  params: ScryptParams;
  nonce: Uint8Array;
  ct: Uint8Array;
} {
  const parts = fragment.replace(/^#/, "").split(".");
  if (parts.length !== 8 || parts[0] !== "v1" || parts[1] !== "scrypt") {
    throw new Error("Bad fragment envelope");
  }
  const N = parseInt(parts[2], 10);
  const r = parseInt(parts[3], 10);
  const p = parseInt(parts[4], 10);
  if (!Number.isFinite(N) || !Number.isFinite(r) || !Number.isFinite(p)) {
    throw new Error("Bad scrypt parameters");
  }
  const salt = b32c.dec(parts[5]);
  const nonce = b32c.dec(parts[6]);
  const ct = b32c.dec(parts[7]);
  if (nonce.length !== nacl.secretbox.nonceLength) throw new Error("Bad nonce length");
  return { params: { N, r, p, salt }, nonce, ct };
}

// ---------- API ----------

/** Create a new fragment for the given payload. */
export async function encryptToFragment<T>(
  passphrase: string,
  data: T,
  {
    // Reasonable starting params: N=2^15 (32768) desktop, 2^14 (16384) mobile; r=8, p=1
    N = 32768,
    r = 8,
    p = 1,
    salt,                 // if omitted, a new random salt will be generated
    context = location.origin,
    seq = 1,
  }: Partial<ScryptParams> & { context?: string; seq?: number } = {}
): Promise<string> {
  const kdfParams: ScryptParams = {
    N, r, p,
    salt: salt ?? crypto.getRandomValues(new Uint8Array(16)),
  };
  const key = await kdfScrypt(passphrase, kdfParams);

  const payload: PlainPayload<T> = { seq, iat: Date.now(), context, data };
  const pt = enc.encode(JSON.stringify(payload));

  const nonce = crypto.getRandomValues(new Uint8Array(nacl.secretbox.nonceLength));
  const ct = nacl.secretbox(pt, nonce, key);

  // optional: zeroize key after use
  key.fill(0);

  return buildFragment(kdfParams, nonce, ct);
}

/** Decrypt an existing fragment. Returns payload and a rotate() helper. */
export async function decryptFromFragment<T = unknown>(
  passphrase: string,
  fragment: string,
  { lastSeenSeq }: { lastSeenSeq?: number } = {}
): Promise<{
  payload: PlainPayload<T>;
  params: ScryptParams;
  rotate: (bumpSeq?: boolean) => Promise<string>;
}> {
  const { params, nonce, ct } = parseFragment(fragment);
  const key = await kdfScrypt(passphrase, params);

  const pt = nacl.secretbox.open(ct, nonce, key);
  if (!pt) throw new Error("Decryption/authentication failed");

  const payload = JSON.parse(dec.decode(pt)) as PlainPayload<T>;

  // Context binding: prevent cross-origin reuse
  const expected = location.origin;
  if (payload.context !== expected) throw new Error("Context mismatch");

  // Anti-rollback
  if (typeof lastSeenSeq === "number" && payload.seq < lastSeenSeq) {
    throw new Error("Rollback detected (seq too low)");
  }

  async function rotate(bumpSeq = true): Promise<string> {
    if (bumpSeq) payload.seq += 1;
    payload.iat = Date.now();
    const newNonce = crypto.getRandomValues(new Uint8Array(nacl.secretbox.nonceLength));
    const newPt = enc.encode(JSON.stringify(payload));
    const newCt = nacl.secretbox(newPt, newNonce, key);
    return buildFragment(params, newNonce, newCt);
  }

  // optional: zeroize key after use
  key.fill(0);

  return { payload, params, rotate };
}

/** Convenience: read fragment, decrypt, rotate with fresh nonce, and replace URL without adding history entries. */
export async function readAndRotateFragment(
  passphrase: string,
  onPayload: (p: PlainPayload<any>) => void
) {
  const frag = location.hash.startsWith("#") ? location.hash.slice(1) : "";
  if (!frag) return;

  // Scrub immediately to reduce accidental sharing/leaks
  history.replaceState(null, "", location.pathname + location.search);

  const { payload, rotate } = await decryptFromFragment(passphrase, frag);
  onPayload(payload);

  const updated = await rotate(true);
  history.replaceState(null, "", location.pathname + location.search + "#" + updated);
}
