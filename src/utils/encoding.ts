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
  
  // Add newlines every 6 groups (30 characters)
  const lines: string[] = [];
  for (let i = 0; i < groups.length; i += 6) {
    lines.push(groups.slice(i, i + 6).join(' '));
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

/**
 * Encode PRP-Cap public key with epoch parameters
 * Format: [version(1)][publicKey(32)][A(32)][B(32)][metadata(variable)]
 */
export const encodePRPCapPublicKey = (
  publicKey: Uint8Array,
  epochA: Uint8Array,
  epochB: Uint8Array,
  validFrom: number,
  validUntil: number,
  epochId: string
): string => {
  // Create metadata
  const metadata = {
    validFrom,
    validUntil,
    epochId
  };
  const metadataBytes = new TextEncoder().encode(JSON.stringify(metadata));
  
  // Combine all parts
  const totalLength = 1 + 32 + 32 + 32 + metadataBytes.length;
  const combined = new Uint8Array(totalLength);
  let offset = 0;
  
  // Version byte
  combined[offset++] = 0x01; // Version 1
  
  // Public key
  combined.set(publicKey, offset);
  offset += 32;
  
  // Epoch A
  combined.set(epochA, offset);
  offset += 32;
  
  // Epoch B
  combined.set(epochB, offset);
  offset += 32;
  
  // Metadata
  combined.set(metadataBytes, offset);
  
  // Encode as base32
  return uint8ArrayToBase32(combined);
};

/**
 * Decode PRP-Cap public key with epoch parameters
 */
export const decodePRPCapPublicKey = (encoded: string): {
  publicKey: Uint8Array;
  epochA: Uint8Array;
  epochB: Uint8Array;
  validFrom: number;
  validUntil: number;
  epochId: string;
} | null => {
  try {
    const combined = base32ToUint8Array(encoded);
    
    // Check version
    if (combined[0] !== 0x01) {
      return null; // Unknown version
    }
    
    // Extract parts
    const publicKey = combined.slice(1, 33);
    const epochA = combined.slice(33, 65);
    const epochB = combined.slice(65, 97);
    const metadataBytes = combined.slice(97);
    
    // Parse metadata
    const metadataStr = new TextDecoder().decode(metadataBytes);
    const metadata = JSON.parse(metadataStr);
    
    return {
      publicKey,
      epochA,
      epochB,
      validFrom: metadata.validFrom,
      validUntil: metadata.validUntil,
      epochId: metadata.epochId
    };
  } catch (error) {
    return null;
  }
};
