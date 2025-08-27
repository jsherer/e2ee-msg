/**
 * Ed25519 Point Operations for PRP-Cap Protocol
 * Provides low-level Ed25519 curve operations needed for the PRP-Cap key exchange
 */

import * as ed from '@noble/ed25519';
import * as nacl from 'tweetnacl';

// Use nacl.hash for SHA-512 instead of @noble/hashes to avoid module issues
const sha512 = (data: Uint8Array): Uint8Array => nacl.hash(data);

// Configure SHA-512 for @noble/ed25519
ed.etc.sha512Sync = (...m: Uint8Array[]) => sha512(ed.etc.concatBytes(...m));

/**
 * Convert bytes to little-endian bigint
 */
export function bytesToNumberLE(bytes: Uint8Array): bigint {
  let result = 0n;
  for (let i = 0; i < bytes.length; i++) {
    result += BigInt(bytes[i]) << BigInt(8 * i);
  }
  return result;
}

/**
 * Convert bigint to little-endian bytes
 */
export function numberToBytesLE(num: bigint, len: number): Uint8Array {
  const bytes = new Uint8Array(len);
  let temp = num;
  for (let i = 0; i < len; i++) {
    bytes[i] = Number(temp & 0xffn);
    temp >>= 8n;
  }
  return bytes;
}

/**
 * Perform Diffie-Hellman on Ed25519 curve directly
 * DH(secret, point) = secret * point
 */
export function ed25519DH(secret: Uint8Array, publicPoint: Uint8Array): Uint8Array {
  // Parse the public point
  const point = ed.Point.fromHex(publicPoint);
  
  // The secret should be a scalar - ensure it's in valid range
  const scalar = ed.etc.mod(bytesToNumberLE(secret), ed.CURVE.n);
  
  // Compute secret * point
  const sharedPoint = point.multiply(scalar);
  
  // Return the shared point (caller will hash it for the final secret)
  return sharedPoint.toRawBytes();
}

/**
 * Hash to scalar for t_i derivation
 * Takes arbitrary data and produces a valid scalar in the field
 */
export function hashToScalar(data: Uint8Array): Uint8Array {
  const hash = sha512(data);
  const scalar_bigint = ed.etc.mod(bytesToNumberLE(hash), ed.CURVE.n);
  return numberToBytesLE(scalar_bigint, 32);
}

/**
 * Generate a random scalar suitable for Ed25519
 * This includes the clamping operations required for X25519 compatibility
 */
export function generateScalar(): Uint8Array {
  const seed = ed.utils.randomPrivateKey();
  const hash = sha512(seed);
  const scalar = hash.slice(0, 32);
  
  // Apply X25519 clamping
  scalar[0] &= 248;
  scalar[31] &= 63;
  scalar[31] |= 64;
  
  return scalar;
}

/**
 * Compute public key from scalar: P = s·G
 */
export function scalarMultBase(scalar: Uint8Array): Uint8Array {
  const scalar_bigint = ed.etc.mod(bytesToNumberLE(scalar), ed.CURVE.n);
  return ed.Point.BASE.multiply(scalar_bigint).toRawBytes();
}

/**
 * Add two Ed25519 points: P1 + P2
 */
export function pointAdd(p1: Uint8Array, p2: Uint8Array): Uint8Array {
  const point1 = ed.Point.fromHex(p1);
  const point2 = ed.Point.fromHex(p2);
  return point1.add(point2).toRawBytes();
}

/**
 * Scalar multiplication of a point: s·P
 */
export function scalarMultPoint(scalar: Uint8Array, point: Uint8Array): Uint8Array {
  const p = ed.Point.fromHex(point);
  const s = ed.etc.mod(bytesToNumberLE(scalar), ed.CURVE.n);
  return p.multiply(s).toRawBytes();
}

/**
 * Modular addition of two scalars: (s1 + s2) mod n
 */
export function scalarAdd(s1: Uint8Array, s2: Uint8Array): Uint8Array {
  const s1_bigint = bytesToNumberLE(s1);
  const s2_bigint = bytesToNumberLE(s2);
  const sum = ed.etc.mod(s1_bigint + s2_bigint, ed.CURVE.n);
  return numberToBytesLE(sum, 32);
}

/**
 * Modular multiplication of two scalars: (s1 * s2) mod n
 */
export function scalarMult(s1: Uint8Array, s2: Uint8Array): Uint8Array {
  const s1_bigint = bytesToNumberLE(s1);
  const s2_bigint = bytesToNumberLE(s2);
  const product = ed.etc.mod(s1_bigint * s2_bigint, ed.CURVE.n);
  return numberToBytesLE(product, 32);
}

/**
 * Verify that a point is valid on the Ed25519 curve
 */
export function isValidPoint(point: Uint8Array): boolean {
  try {
    ed.Point.fromHex(point);
    return true;
  } catch {
    return false;
  }
}

/**
 * Convert Ed25519 public key to X25519 format
 * This is needed for compatibility with existing X25519 code
 */
export function ed25519ToX25519Public(edPublic: Uint8Array): Uint8Array {
  // This conversion is complex and typically requires the ed2curve library
  // For now we'll use the Ed25519 point directly since we're doing pure Ed25519 DH
  // The actual conversion would involve mapping between Montgomery and twisted Edwards curves
  return edPublic; // Placeholder - actual implementation would use ed2curve
}

/**
 * Securely erase a Uint8Array by overwriting with random data
 */
export function secureErase(data: Uint8Array): void {
  // Overwrite with random data multiple times
  for (let i = 0; i < 3; i++) {
    crypto.getRandomValues(data);
  }
  // Final overwrite with zeros
  data.fill(0);
}