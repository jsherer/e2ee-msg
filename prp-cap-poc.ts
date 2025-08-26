// prp-cap-poc.ts
// Minimal PoC for PRP-Cap 0-RTT Key Exchange Protocol

import * as nacl from 'tweetnacl';
import * as ed from '@noble/ed25519';
import { sha512 } from '@noble/hashes/sha2';

// Configure SHA-512 for @noble/ed25519
ed.etc.sha512Sync = (...m: Uint8Array[]) => sha512(ed.etc.concatBytes(...m));

// ============= Helper Functions =============

/**
 * Convert bytes to number (little-endian)
 */
function bytesToNumberLE(bytes: Uint8Array): bigint {
  let result = 0n;
  for (let i = 0; i < bytes.length; i++) {
    result += BigInt(bytes[i]) << BigInt(8 * i);
  }
  return result;
}

/**
 * Convert number to bytes (little-endian)
 */
function numberToBytesLE(num: bigint, len: number): Uint8Array {
  const bytes = new Uint8Array(len);
  let temp = num;
  for (let i = 0; i < len; i++) {
    bytes[i] = Number(temp & 0xffn);
    temp >>= 8n;
  }
  return bytes;
}

/**
 * Hash data to a valid Ed25519 scalar
 */
function H_to_scalar(data: Uint8Array): Uint8Array {
  const hash = nacl.hash(data); // SHA-512
  // Reduce modulo curve order using @noble/ed25519
  const scalar = ed.etc.mod(bytesToNumberLE(hash), ed.CURVE.n);
  return numberToBytesLE(scalar, 32);
}

/**
 * Convert bytes to hex string for display
 */
function toHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Clamp scalar for X25519 operations
 */
function clampScalar(scalar: Uint8Array): Uint8Array {
  const clamped = new Uint8Array(scalar);
  clamped[0] &= 248;
  clamped[31] &= 127;
  clamped[31] |= 64;
  return clamped;
}

/**
 * Convert Ed25519 point to X25519 format for DH operations
 */
async function ed25519ToX25519Public(edPoint: Uint8Array): Promise<Uint8Array> {
  // Convert Ed25519 point to X25519 Montgomery format
  // In Ed25519, we need to convert the Edwards curve point to Montgomery curve
  // The conversion is well-defined mathematically
  // For simplicity, we'll use a direct conversion based on the curve relationship
  
  // Parse the Ed25519 point
  const point = ed.Point.fromHex(edPoint);
  
  // Extract y-coordinate (Ed25519 encodes y and a sign bit)
  const y = point.y;
  
  // Convert to Montgomery x-coordinate: u = (1 + y) / (1 - y) mod p
  const one = 1n;
  const p = 2n ** 255n - 19n;
  
  const numerator = ed.etc.mod(one + y, p);
  const denominator = ed.etc.mod(one - y, p);
  const denominatorInv = ed.etc.invert(denominator, p);
  
  const u = ed.etc.mod(numerator * denominatorInv, p);
  
  return numberToBytesLE(u, 32);
}

/**
 * Convert Ed25519 scalar to X25519 scalar
 */
function ed25519ToX25519Scalar(edScalar: Uint8Array): Uint8Array {
  // Hash the scalar and clamp it for X25519
  const hashed = nacl.hash(edScalar);
  return clampScalar(hashed.slice(0, 32));
}

// ============= Core Protocol Functions =============

/**
 * Generate epoch parameters (A, B, s1, s2)
 */
function generateEpochParams(): {
  A: Uint8Array;      // Public: s1·G (32 bytes)
  B: Uint8Array;      // Public: s2·G (32 bytes)
  s1: Uint8Array;     // Secret: kept entire epoch (32 bytes)
  s2: Uint8Array;     // Secret: deleted at epoch end (32 bytes)
} {
  // Generate random scalars
  const s1 = ed.utils.randomPrivateKey();
  const s2 = ed.utils.randomPrivateKey();
  
  // Compute public points using Ed25519
  const A = ed.getPublicKey(s1);
  const B = ed.getPublicKey(s2);
  
  return { A, B, s1, s2 };
}

/**
 * Compute PRP Capability: V_i = A + t_i·B
 */
function computePRPCap(
  A: Uint8Array,      // Public point A
  B: Uint8Array,      // Public point B
  index: number       // Arbitrary index
): Uint8Array {       // Returns V_i = A + t_i·B (32 bytes)
  // Domain separation and index encoding
  const domain = new TextEncoder().encode('PRP-CAP');
  const indexBytes = new Uint8Array(4);
  new DataView(indexBytes.buffer).setUint32(0, index, false); // Big-endian
  
  // Compute t_i = H_to_scalar("PRP-CAP" || index || A || B)
  const hashInput = new Uint8Array(domain.length + 4 + 32 + 32);
  hashInput.set(domain, 0);
  hashInput.set(indexBytes, domain.length);
  hashInput.set(A, domain.length + 4);
  hashInput.set(B, domain.length + 36);
  const t_i = H_to_scalar(hashInput);
  
  // Compute t_i·B
  const pointB = ed.Point.fromHex(B);
  const t_i_num = ed.etc.mod(bytesToNumberLE(t_i), ed.CURVE.n);
  const tiB = pointB.multiply(t_i_num);
  
  // Compute V_i = A + t_i·B
  const pointA = ed.Point.fromHex(A);
  const V_i = pointA.add(tiB);
  
  return V_i.toRawBytes();
}

/**
 * Single Ladder - Sender side
 */
async function deriveSingleLadder(
  senderEphemeralSecret: Uint8Array,   // e_alice (32 bytes)
  recipientV_i: Uint8Array              // V_i_bob (32 bytes)
): Promise<Uint8Array> {                // Shared secret (32 bytes)
  // Convert V_i from Ed25519 to X25519 format
  const V_i_x25519 = await ed25519ToX25519Public(recipientV_i);
  
  // Compute DH(e_alice, V_i_bob)
  const ephemeralX25519 = clampScalar(senderEphemeralSecret);
  const sharedSecret = nacl.scalarMult(ephemeralX25519, V_i_x25519);
  
  // KDF with domain separation
  const kdfInput = new Uint8Array(sharedSecret.length + 12);
  kdfInput.set(sharedSecret, 0);
  kdfInput.set(new TextEncoder().encode('SingleLadder'), sharedSecret.length);
  
  return nacl.hash(kdfInput).slice(0, 32);
}

/**
 * Single Ladder - Receiver side
 */
async function deriveSingleLadderReceiver(
  senderEphemeralPublic: Uint8Array,   // E_alice (32 bytes)
  recipientS1: Uint8Array,              // s1_bob (32 bytes)
  recipientS2: Uint8Array,              // s2_bob (32 bytes)
  index: number,                        // Index used for V_i
  A: Uint8Array,                        // Public point A
  B: Uint8Array                         // Public point B
): Promise<Uint8Array> {                // Shared secret (32 bytes)
  // Compute t_i the same way as in computePRPCap
  const domain = new TextEncoder().encode('PRP-CAP');
  const indexBytes = new Uint8Array(4);
  new DataView(indexBytes.buffer).setUint32(0, index, false);
  
  const hashInput = new Uint8Array(domain.length + 4 + 32 + 32);
  hashInput.set(domain, 0);
  hashInput.set(indexBytes, domain.length);
  hashInput.set(A, domain.length + 4);
  hashInput.set(B, domain.length + 36);
  const t_i = H_to_scalar(hashInput);
  
  // Compute private scalar: v_i = s1 + t_i·s2 (mod n)
  const s1_num = ed.etc.mod(bytesToNumberLE(recipientS1), ed.CURVE.n);
  const s2_num = ed.etc.mod(bytesToNumberLE(recipientS2), ed.CURVE.n);
  const t_i_num = ed.etc.mod(bytesToNumberLE(t_i), ed.CURVE.n);
  
  const v_i_num = ed.etc.mod(s1_num + ed.etc.mod(t_i_num * s2_num, ed.CURVE.n), ed.CURVE.n);
  const v_i = numberToBytesLE(v_i_num, 32);
  
  // Convert E_alice from Ed25519 to X25519
  const E_x25519 = await ed25519ToX25519Public(senderEphemeralPublic);
  
  // Compute DH(v_i, E_alice)
  const v_i_x25519 = ed25519ToX25519Scalar(v_i);
  const sharedSecret = nacl.scalarMult(v_i_x25519, E_x25519);
  
  // KDF with domain separation (same as sender)
  const kdfInput = new Uint8Array(sharedSecret.length + 12);
  kdfInput.set(sharedSecret, 0);
  kdfInput.set(new TextEncoder().encode('SingleLadder'), sharedSecret.length);
  
  return nacl.hash(kdfInput).slice(0, 32);
}

/**
 * Double Ladder - Merge two shared secrets
 */
function deriveDoubleLadder(
  aliceEphemeralSecret: Uint8Array,    // e_alice
  aliceV_i: Uint8Array,                // V_i_alice  
  aliceS1: Uint8Array,                 // s1_alice
  aliceS2: Uint8Array,                 // s2_alice
  aliceIndex: number,                  // i_alice
  aliceA: Uint8Array,                  // A_alice
  aliceB: Uint8Array,                  // B_alice
  bobEphemeralPublic: Uint8Array,      // E_bob
  bobV_j: Uint8Array,                  // V_j_bob
  bobIndex: number                     // j_bob (not used in calculation but kept for completeness)
): Promise<Uint8Array> {                // Merged secret (32 bytes)
  return (async () => {
    // Compute ladder1: Alice's ephemeral to Bob's V_j
    const ladder1 = await deriveSingleLadder(aliceEphemeralSecret, bobV_j);
    
    // Compute ladder2: Alice's V_i private to Bob's ephemeral
    const ladder2 = await deriveSingleLadderReceiver(
      bobEphemeralPublic,
      aliceS1,
      aliceS2,
      aliceIndex,
      aliceA,
      aliceB
    );
    
    // Sort ladders for canonical ordering
    const [first, second] = compareArrays(ladder1, ladder2) < 0 
      ? [ladder1, ladder2] 
      : [ladder2, ladder1];
    
    // Merge with KDF
    const mergeInput = new Uint8Array(64 + 12);
    mergeInput.set(first, 0);
    mergeInput.set(second, 32);
    mergeInput.set(new TextEncoder().encode('DoubleLadder'), 64);
    
    return nacl.hash(mergeInput).slice(0, 32);
  })();
}

function compareArrays(a: Uint8Array, b: Uint8Array): number {
  for (let i = 0; i < Math.min(a.length, b.length); i++) {
    if (a[i] < b[i]) return -1;
    if (a[i] > b[i]) return 1;
  }
  return 0;
}

// ============= Test Scenarios =============

async function testSingleLadder(): Promise<boolean> {
  console.log("Alice ephemeral public: ", end="");
  
  // Bob generates epoch parameters
  const bobEpoch = generateEpochParams();
  
  // Alice creates ephemeral keypair
  const aliceEphemeralSecret = ed.utils.randomPrivateKey();
  const aliceEphemeralPublic = ed.getPublicKey(aliceEphemeralSecret);
  console.log(toHex(aliceEphemeralPublic).slice(0, 16) + "...");
  
  // Alice computes V_42 for Bob's epoch
  const index = 42;
  const bobV_42 = computePRPCap(bobEpoch.A, bobEpoch.B, index);
  console.log("Bob's V_42: " + toHex(bobV_42).slice(0, 16) + "...");
  
  // Alice derives shared secret
  const aliceShared = await deriveSingleLadder(aliceEphemeralSecret, bobV_42);
  console.log("Alice derives: " + toHex(aliceShared).slice(0, 16) + "...");
  
  // Bob derives shared secret
  const bobShared = await deriveSingleLadderReceiver(
    aliceEphemeralPublic,
    bobEpoch.s1,
    bobEpoch.s2,
    index,
    bobEpoch.A,
    bobEpoch.B
  );
  console.log("Bob derives: " + toHex(bobShared).slice(0, 16) + "...");
  
  // Check if they match
  const match = nacl.verify(aliceShared, bobShared);
  console.log(match ? "✓ Single ladder SUCCESS - both parties derived same secret" :
                      "✗ Single ladder FAILED - secrets don't match");
  
  return match;
}

async function testDoubleLadder(): Promise<boolean> {
  // Generate epoch params for both parties
  const aliceEpoch = generateEpochParams();
  const bobEpoch = generateEpochParams();
  
  // Both create ephemeral keypairs
  const aliceEphemeralSecret = ed.utils.randomPrivateKey();
  const aliceEphemeralPublic = ed.getPublicKey(aliceEphemeralSecret);
  
  const bobEphemeralSecret = ed.utils.randomPrivateKey();
  const bobEphemeralPublic = ed.getPublicKey(bobEphemeralSecret);
  
  // Choose indices
  const aliceIndex = 42;
  const bobIndex = 99;
  
  // Compute V_i values
  const aliceV_42 = computePRPCap(aliceEpoch.A, aliceEpoch.B, aliceIndex);
  const bobV_99 = computePRPCap(bobEpoch.A, bobEpoch.B, bobIndex);
  
  console.log("Alice -> Bob ladder: calculating...");
  console.log("Bob -> Alice ladder: calculating...");
  
  // Alice derives merged secret
  const aliceMerged = await deriveDoubleLadder(
    aliceEphemeralSecret,
    aliceV_42,
    aliceEpoch.s1,
    aliceEpoch.s2,
    aliceIndex,
    aliceEpoch.A,
    aliceEpoch.B,
    bobEphemeralPublic,
    bobV_99,
    bobIndex
  );
  console.log("Alice merged secret: " + toHex(aliceMerged).slice(0, 16) + "...");
  
  // Bob derives merged secret
  const bobMerged = await deriveDoubleLadder(
    bobEphemeralSecret,
    bobV_99,
    bobEpoch.s1,
    bobEpoch.s2,
    bobIndex,
    bobEpoch.A,
    bobEpoch.B,
    aliceEphemeralPublic,
    aliceV_42,
    aliceIndex
  );
  console.log("Bob merged secret: " + toHex(bobMerged).slice(0, 16) + "...");
  
  // Check if they match
  const match = nacl.verify(aliceMerged, bobMerged);
  console.log(match ? "✓ Double ladder SUCCESS - merge produced identical secrets" :
                      "✗ Double ladder FAILED - merged secrets don't match");
  
  return match;
}

function testPRPCapProperties(): boolean {
  const epoch = generateEpochParams();
  const indices = [0, 1, 42, 999999];
  const values: Map<number, Uint8Array> = new Map();
  
  // Compute V_i for multiple indices
  for (const i of indices) {
    const V_i = computePRPCap(epoch.A, epoch.B, i);
    values.set(i, V_i);
    console.log(`V_${i.toString().padEnd(6)}: ${toHex(V_i).slice(0, 16)}...`);
  }
  
  // Verify all V_i values are different
  const uniqueValues = new Set();
  for (const v of values.values()) {
    uniqueValues.add(toHex(v));
  }
  
  // Verify recomputing gives same result
  let deterministic = true;
  for (const i of indices) {
    const V_i_again = computePRPCap(epoch.A, epoch.B, i);
    if (!nacl.verify(values.get(i)!, V_i_again)) {
      deterministic = false;
      break;
    }
  }
  
  const allUnique = uniqueValues.size === values.size;
  const success = allUnique && deterministic;
  
  console.log(success ? "✓ All V_i values are unique and deterministic" :
                        "✗ PRP properties test failed");
  
  return success;
}

// ============= Main Test Runner =============

async function main() {
  console.log("=== PRP-Cap 0-RTT PoC ===\n");
  
  console.log("Test 1: Single Ladder");
  const test1 = await testSingleLadder();
  
  console.log("\nTest 2: Double Ladder");
  const test2 = await testDoubleLadder();
  
  console.log("\nTest 3: PRP-Cap Properties");
  const test3 = testPRPCapProperties();
  
  console.log("\n=== Results ===");
  console.log(`Single Ladder: ${test1 ? "PASS ✓" : "FAIL ✗"}`);
  console.log(`Double Ladder: ${test2 ? "PASS ✓" : "FAIL ✗"}`);
  console.log(`PRP Properties: ${test3 ? "PASS ✓" : "FAIL ✗"}`);
  
  const allPass = test1 && test2 && test3;
  if (allPass) {
    console.log("\n🎉 All tests passed! PRP-Cap protocol validated.");
  } else {
    console.log("\n⚠️ Some tests failed. Check implementation.");
  }
}

// Run the tests
main().catch(console.error);