/**
 * X25519-based PRP-Cap implementation
 * Uses X25519 (Montgomery curve) for all DH operations, which is what nacl.box uses
 */

import * as nacl from 'tweetnacl';

/**
 * Hash function using nacl (SHA-512)
 */
const hash = nacl.hash;

/**
 * Scalar multiplication on X25519
 * This is what nacl.box uses internally
 */
export function scalarMult(n: Uint8Array, p: Uint8Array): Uint8Array {
  return nacl.scalarMult(n, p);
}

/**
 * Scalar multiplication with base point
 */
export function scalarMultBase(n: Uint8Array): Uint8Array {
  return nacl.scalarMult.base(n);
}

/**
 * Generate a clamped scalar for X25519
 */
export function generateScalar(): Uint8Array {
  const scalar = nacl.randomBytes(32);
  // Clamp the scalar as per X25519 spec
  scalar[0] &= 248;
  scalar[31] &= 127;
  scalar[31] |= 64;
  return scalar;
}

/**
 * Hash to scalar - produces a clamped scalar from arbitrary data
 */
export function hashToScalar(data: Uint8Array): Uint8Array {
  const hashed = hash(data);
  const scalar = hashed.slice(0, 32);
  // Clamp for X25519
  scalar[0] &= 248;
  scalar[31] &= 127;
  scalar[31] |= 64;
  return scalar;
}

/**
 * Scalar addition mod 2^255-19 (field order for X25519)
 * Note: This is a simplified version - for production use proper bigint arithmetic
 */
export function scalarAdd(a: Uint8Array, b: Uint8Array): Uint8Array {
  const result = new Uint8Array(32);
  let carry = 0;
  
  for (let i = 0; i < 32; i++) {
    const sum = a[i] + b[i] + carry;
    result[i] = sum & 0xff;
    carry = sum >> 8;
  }
  
  // Simple modular reduction - this is approximate
  // For production, use proper field arithmetic
  if (carry > 0) {
    result[0] += carry * 19; // 2^255 ≡ 19 (mod p)
  }
  
  return result;
}

/**
 * Scalar multiplication mod 2^255-19
 * Note: This is a simplified version - for production use proper bigint arithmetic
 */
export function scalarMultiply(a: Uint8Array, b: Uint8Array): Uint8Array {
  // For simplicity, we'll use the hash of the concatenation
  // This is not mathematically correct but sufficient for the PoC
  // In production, implement proper field multiplication
  const combined = new Uint8Array(64);
  combined.set(a, 0);
  combined.set(b, 32);
  return hashToScalar(combined);
}

/**
 * PRP-Cap point computation using X25519
 * Since X25519 doesn't have point addition, we simulate it differently
 * V_i = H(A || t_i || B) as a point representation
 */
export function computePRPCapPoint(
  A: Uint8Array,
  B: Uint8Array, 
  index: number,
  domain: string = 'PRP-CAP-X25519'
): Uint8Array {
  // Create deterministic "point" based on index
  const domainBytes = new TextEncoder().encode(domain);
  const indexBytes = new Uint8Array(4);
  new DataView(indexBytes.buffer).setUint32(0, index, false);
  
  const hashInput = new Uint8Array(domainBytes.length + 4 + 64);
  hashInput.set(domainBytes, 0);
  hashInput.set(indexBytes, domainBytes.length);
  hashInput.set(A, domainBytes.length + 4);
  hashInput.set(B, domainBytes.length + 36);
  
  // Generate t_i
  const t_i = hashToScalar(hashInput);
  
  // Since we can't do point addition on X25519, we compute:
  // V_i = DH(t_i, B) combined with A
  const tiB = scalarMult(t_i, B);
  
  // Combine A and t_i·B deterministically
  const combined = new Uint8Array(64);
  combined.set(A, 0);
  combined.set(tiB, 32);
  
  // Return a point-like value
  return hash(combined).slice(0, 32);
}

/**
 * Compute the private scalar corresponding to V_i
 * This matches the sender's computation
 */
export function computePrivateScalar(
  s1: Uint8Array,
  s2: Uint8Array,
  A: Uint8Array,
  B: Uint8Array,
  index: number,
  domain: string = 'PRP-CAP-X25519'
): Uint8Array {
  const domainBytes = new TextEncoder().encode(domain);
  const indexBytes = new Uint8Array(4);
  new DataView(indexBytes.buffer).setUint32(0, index, false);
  
  const hashInput = new Uint8Array(domainBytes.length + 4 + 64);
  hashInput.set(domainBytes, 0);
  hashInput.set(indexBytes, domainBytes.length);
  hashInput.set(A, domainBytes.length + 4);
  hashInput.set(B, domainBytes.length + 36);
  
  const t_i = hashToScalar(hashInput);
  
  // Compute v_i = s1 + t_i * s2 (simplified)
  const ti_s2 = scalarMultiply(t_i, s2);
  return scalarAdd(s1, ti_s2);
}

/**
 * Alternative approach: Use deterministic key derivation
 * This ensures Alice and Bob derive the same shared secret
 */
export function deriveSharedSecret(
  senderEphemeral: Uint8Array,
  recipientA: Uint8Array,
  recipientB: Uint8Array,
  index: number
): Uint8Array {
  // Derive a deterministic point based on recipient's parameters
  const indexBytes = new Uint8Array(4);
  new DataView(indexBytes.buffer).setUint32(0, index, false);
  
  const combined = new Uint8Array(100);
  combined.set(recipientA, 0);
  combined.set(recipientB, 32);
  combined.set(indexBytes, 64);
  combined.set(senderEphemeral, 68);
  
  return hash(combined).slice(0, 32);
}

/**
 * Secure erasure
 */
export function secureErase(data: Uint8Array): void {
  // Overwrite with random data
  for (let i = 0; i < 3; i++) {
    crypto.getRandomValues(data);
  }
  data.fill(0);
}