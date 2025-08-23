/**
 * Encoding utilities for converting between different formats
 */

//
// ---------- RFC 4648 Base32 ----------
const RFC4648_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const RFC4648_DECODE: Record<string, number> = (() => {
  const m: Record<string, number> = {};
  for (let i = 0; i < RFC4648_ALPHABET.length; i++) {
    m[RFC4648_ALPHABET[i]] = i;
    m[RFC4648_ALPHABET[i].toLowerCase()] = i;
  }
  return m;
})();

export function uint8ArrayToBase32(bytes: Uint8Array, pad = true): string {
  if (bytes.length === 0) return "";
  let bits = 0, value = 0, out = "";
  for (let i = 0; i < bytes.length; i++) {
    value = (value << 8) | bytes[i];
    bits += 8;
    while (bits >= 5) {
      out += RFC4648_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += RFC4648_ALPHABET[(value << (5 - bits)) & 31];
  if (pad) while (out.length % 8 !== 0) out += "=";
  return out;
}

export function base32ToUint8Array(s: string): Uint8Array {
  s = s.replace(/=+$/g, "").replace(/\s+/g, "");
  if (s.length === 0) return new Uint8Array();
  let bits = 0, value = 0;
  const out: number[] = [];
  for (const ch of s) {
    const v = RFC4648_DECODE[ch];
    if (v === undefined) throw new Error(`invalid base32 char '${ch}'`);
    value = (value << 5) | v;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return new Uint8Array(out);
}

// ---------- Crockford Base32 ----------

const CROCKFORD_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const CROCKFORD_DECODE: Record<string, number> = (() => {
  const m: Record<string, number> = {};
  for (let i = 0; i < CROCKFORD_ALPHABET.length; i++) {
    const ch = CROCKFORD_ALPHABET[i];
    m[ch] = i; m[ch.toLowerCase()] = i;
  }
  // Ambiguity mappings
  m["O"] = m["o"] = m["0"];
  m["I"] = m["i"] = m["1"];
  m["L"] = m["l"] = m["1"];
  return m;
})();

export function uint8ArrayToBase32Crockford(bytes: Uint8Array): string {
  if (bytes.length === 0) return "";
  let bits = 0, value = 0, out = "";
  for (let i = 0; i < bytes.length; i++) {
    value = (value << 8) | bytes[i];
    bits += 8;
    while (bits >= 5) {
      out += CROCKFORD_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += CROCKFORD_ALPHABET[(value << (5 - bits)) & 31];
  return out;
}

export function base32CrockfordToUint8Array(s: string): Uint8Array {
  s = s.replace(/\s+/g, "");
  if (s.length === 0) return new Uint8Array();
  let bits = 0, value = 0;
  const out: number[] = [];
  for (const ch of s) {
    const v = CROCKFORD_DECODE[ch];
    if (v === undefined) throw new Error(`invalid Crockford base32 char '${ch}'`);
    value = (value << 5) | v;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return new Uint8Array(out);
}

// ---------- Node-friendly Buffer wrappers ----------
export function bufferToBase32(buf: Buffer, pad = true): string {
  return uint8ArrayToBase32(new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength), pad);
}
export function base32ToBuffer(s: string): Buffer {
  const u8 = base32ToUint8Array(s);
  return Buffer.from(u8.buffer, u8.byteOffset, u8.byteLength);
}

export function bufferToBase32Crockford(buf: Buffer): string {
  return uint8ArrayToBase32Crockford(new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength));
}
export function base32CrockfordToBuffer(s: string): Buffer {
  const u8 = base32CrockfordToUint8Array(s);
  return Buffer.from(u8.buffer, u8.byteOffset, u8.byteLength);
}

// ---------- Utility functions ----------
export const formatInGroups = (str: string, addNewlines: boolean = false): string => {
  const groups = str.match(/.{1,5}/g) || [str];
  if (!addNewlines) {
    return groups.join(' ');
  }
  
  // Add newlines every 5 groups (25 characters)
  const lines: string[] = [];
  for (let i = 0; i < groups.length; i += 5) {
    lines.push(groups.slice(i, i + 5).join(' '));
  }
  return lines.join('\n');
};

export const generateUserId = (publicKey: Uint8Array): string => {
  // Import nacl dynamically to avoid circular dependency
  const nacl = require('tweetnacl');
  const hash = nacl.hash(publicKey);
  const idBytes = hash.slice(0, 8);
  const hexId = Array.from(idBytes as Uint8Array)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')
    .toUpperCase();
  return hexId.match(/.{1,4}/g)?.join('-') || hexId;
};
