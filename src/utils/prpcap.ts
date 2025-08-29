/**
 * Actual PRP-Cap Protocol Implementation
 * This implements the real protocol: V_i = A + t_i·B
 * 
 * Note: This requires @noble/ed25519 for point operations.
 * To use in Jest tests, you'll need to transpile or use tsx.
 */

import * as nacl from 'tweetnacl';

// We'll dynamically import @noble/ed25519 to handle the ES module issue
let ed: any = null;
let sha512Impl: (data: Uint8Array) => Uint8Array = nacl.hash;

/**
 * Initialize the Ed25519 library
 */
export async function initializeEd25519(): Promise<void> {
  if (ed) return;
  
  try {
    // Dynamic import to handle ES modules
    const edModule = await import('@noble/ed25519');
    const hashModule = await import('@noble/hashes/sha2');
    
    ed = edModule;
    sha512Impl = (data: Uint8Array) => hashModule.sha512(data);
    
    // Configure SHA-512 for @noble/ed25519
    ed.etc.sha512Sync = (...m: Uint8Array[]) => {
      const concat = ed.etc.concatBytes(...m);
      return sha512Impl(concat);
    };
  } catch (error) {
    console.warn('Failed to load @noble/ed25519, falling back to nacl');
    // Fallback - won't support point addition but basic ops will work
    sha512Impl = nacl.hash;
  }
}

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
 * Hash to scalar for t_i derivation
 */
export function hashToScalar(data: Uint8Array): Uint8Array {
  const hash = sha512Impl(data);
  if (ed) {
    const scalar_bigint = ed.etc.mod(bytesToNumberLE(hash), ed.CURVE.n);
    return numberToBytesLE(scalar_bigint, 32);
  } else {
    // Fallback without proper modular reduction
    const scalar = hash.slice(0, 32);
    scalar[0] &= 248;
    scalar[31] &= 127;
    scalar[31] |= 64;
    return scalar;
  }
}

/**
 * PRP-Cap Epoch Parameters
 */
export interface PRPCapEpoch {
  A: Uint8Array;  // s1·G
  B: Uint8Array;  // s2·G
  s1: Uint8Array; // Secret scalar 1
  s2: Uint8Array; // Secret scalar 2
}

/**
 * Generate epoch parameters for PRP-Cap
 */
export async function generatePRPCapEpoch(): Promise<PRPCapEpoch> {
  await initializeEd25519();
  
  if (!ed) {
    throw new Error('Ed25519 library not initialized');
  }
  
  // Generate random scalars
  const s1_seed = ed.utils.randomPrivateKey();
  const s2_seed = ed.utils.randomPrivateKey();
  
  // Extract the actual scalars
  const s1_hash = sha512Impl(s1_seed);
  const s2_hash = sha512Impl(s2_seed);
  
  const s1 = s1_hash.slice(0, 32);
  s1[0] &= 248;
  s1[31] &= 63;
  s1[31] |= 64;
  
  const s2 = s2_hash.slice(0, 32);
  s2[0] &= 248;
  s2[31] &= 63;
  s2[31] |= 64;
  
  // Compute public points
  const s1_bigint = ed.etc.mod(bytesToNumberLE(s1), ed.CURVE.n);
  const s2_bigint = ed.etc.mod(bytesToNumberLE(s2), ed.CURVE.n);
  
  // A = s1 * G
  // B = s2 * G
  const A = ed.Point.BASE.multiply(s1_bigint).toRawBytes();
  const B = ed.Point.BASE.multiply(s2_bigint).toRawBytes();
  
  return { A, B, s1, s2 };
}

/**
 * Compute PRP Capability: V_i = A + t_i·B
 */
export async function computeVi(
  A: Uint8Array,
  B: Uint8Array,
  index: number
): Promise<Uint8Array> {
  await initializeEd25519();
  
  if (!ed) {
    throw new Error('Ed25519 library not initialized');
  }
  
  const domain = new TextEncoder().encode('PRP-CAP');
  const indexBytes = new Uint8Array(4);
  new DataView(indexBytes.buffer).setUint32(0, index, false);
  
  const hashInput = new Uint8Array(domain.length + 4 + 64);
  hashInput.set(domain, 0);
  hashInput.set(indexBytes, domain.length);
  hashInput.set(A, domain.length + 4);
  hashInput.set(B, domain.length + 36);
  
  // ti = H(info || i || A || B)
  const t_i = hashToScalar(hashInput);
  const t_i_bigint = ed.etc.mod(bytesToNumberLE(t_i), ed.CURVE.n);
  
  // V_i = A + ti * BB
  const pointA = ed.Point.fromHex(A);
  const pointB = ed.Point.fromHex(B);
  const tiB = pointB.multiply(t_i_bigint);
  const V_i = pointA.add(tiB);
  
  return V_i.toRawBytes();
}

/**
 * Compute private scalar: v_i = s1 + t_i·s2
 */
export async function compute_vi(
  s1: Uint8Array,
  s2: Uint8Array,
  A: Uint8Array,
  B: Uint8Array,
  index: number
): Promise<Uint8Array> {
  await initializeEd25519();
  
  if (!ed) {
    throw new Error('Ed25519 library not initialized');
  }
  
  const domain = new TextEncoder().encode('PRP-CAP');
  const indexBytes = new Uint8Array(4);
  new DataView(indexBytes.buffer).setUint32(0, index, false);
  
  const hashInput = new Uint8Array(domain.length + 4 + 64);
  hashInput.set(domain, 0);
  hashInput.set(indexBytes, domain.length);
  hashInput.set(A, domain.length + 4);
  hashInput.set(B, domain.length + 36);
  
  const t_i = hashToScalar(hashInput);
  
  const s1_bigint = bytesToNumberLE(s1);
  const s2_bigint = bytesToNumberLE(s2);
  const t_i_bigint = ed.etc.mod(bytesToNumberLE(t_i), ed.CURVE.n);
  
  const ti_s2 = ed.etc.mod(t_i_bigint * s2_bigint, ed.CURVE.n);
  const v_i_bigint = ed.etc.mod(s1_bigint + ti_s2, ed.CURVE.n);
  
  return numberToBytesLE(v_i_bigint, 32);
}

/**
 * Ed25519 Diffie-Hellman: DH(secret, point)
 */
export async function ed25519DH(secret: Uint8Array, publicPoint: Uint8Array): Promise<Uint8Array> {
  await initializeEd25519();
  
  if (!ed) {
    throw new Error('Ed25519 library not initialized');
  }
  
  const point = ed.Point.fromHex(publicPoint);
  const scalar = ed.etc.mod(bytesToNumberLE(secret), ed.CURVE.n);
  const sharedPoint = point.multiply(scalar);
  
  return sharedPoint.toRawBytes();
}

/**
 * Create a 0-RTT message using PRP-Cap
 */
export interface PRPCapMessage {
  ephemeralPublic: Uint8Array;
  index: number;
  ciphertext: Uint8Array;
  nonce: Uint8Array;
}

export async function createPRPCapMessage(
  plaintext: Uint8Array,
  recipientA: Uint8Array,
  recipientB: Uint8Array,
  index: number = Math.floor(Math.random() * 2**32)
): Promise<PRPCapMessage> {
  await initializeEd25519();
  
  // Generate ephemeral scalar
  const ephemeralSeed = ed.utils.randomPrivateKey();
  const ephemeralHash = sha512Impl(ephemeralSeed);
  const ephemeralScalar = ephemeralHash.slice(0, 32);
  ephemeralScalar[0] &= 248;
  ephemeralScalar[31] &= 63;
  ephemeralScalar[31] |= 64;
  
  // Compute ephemeral public
  const ephemeralBigint = ed.etc.mod(bytesToNumberLE(ephemeralScalar), ed.CURVE.n);
  const ephemeralPublic = ed.Point.BASE.multiply(ephemeralBigint).toRawBytes();
  
  // Compute V_i
  const V_i = await computeVi(recipientA, recipientB, index);
  
  // DH(ephemeral, V_i)
  const sharedPoint = await ed25519DH(ephemeralScalar, V_i);
  const sharedSecret = sha512Impl(sharedPoint).slice(0, 32);
  
  // Encrypt (ensure proper Uint8Arrays)
  const nonce = nacl.randomBytes(24);
  const ciphertext = nacl.secretbox(
    new Uint8Array(plaintext),
    new Uint8Array(nonce),
    new Uint8Array(sharedSecret)
  );
  
  return {
    ephemeralPublic,
    index,
    ciphertext,
    nonce
  };
}

/**
 * Process a PRP-Cap message
 */
export async function processPRPCapMessage(
  message: PRPCapMessage,
  epoch: PRPCapEpoch
): Promise<Uint8Array | null> {
  await initializeEd25519();
  
  try {
    // Compute v_i
    const v_i = await compute_vi(epoch.s1, epoch.s2, epoch.A, epoch.B, message.index);
    
    // DH(v_i, ephemeralPublic)
    const sharedPoint = await ed25519DH(v_i, message.ephemeralPublic);
    const sharedSecret = sha512Impl(sharedPoint).slice(0, 32);
    
    // Decrypt
    return nacl.secretbox.open(message.ciphertext, message.nonce, sharedSecret);
  } catch (error) {
    return null;
  }
}

/**
 * Test convergence
 */
export async function testPRPCapConvergence(): Promise<boolean> {
  await initializeEd25519();
  
  const epoch = await generatePRPCapEpoch();
  const plaintext = new TextEncoder().encode('Hello PRP-Cap!');
  
  const message = await createPRPCapMessage(
    plaintext,
    epoch.A,
    epoch.B,
    42
  );
  
  const decrypted = await processPRPCapMessage(message, epoch);
  
  if (!decrypted) return false;
  
  return new TextDecoder().decode(decrypted) === 'Hello PRP-Cap!';
}
