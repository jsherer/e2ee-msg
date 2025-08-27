// prp-cap-poc-ed2curve.ts
// PRP-Cap implementation using ed2curve for proper Ed25519→X25519 conversion

import * as nacl from 'tweetnacl';
import * as ed from '@noble/ed25519';
import * as ed2curve from 'ed2curve';
import { sha512 } from '@noble/hashes/sha2';

// Configure SHA-512 for @noble/ed25519
ed.etc.sha512Sync = (...m: Uint8Array[]) => sha512(ed.etc.concatBytes(...m));

// ============= Helper Functions =============

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

function bytesToNumberLE(bytes: Uint8Array): bigint {
  let result = 0n;
  for (let i = 0; i < bytes.length; i++) {
    result += BigInt(bytes[i]) << BigInt(8 * i);
  }
  return result;
}

function numberToBytesLE(num: bigint, len: number): Uint8Array {
  const bytes = new Uint8Array(len);
  let temp = num;
  for (let i = 0; i < len; i++) {
    bytes[i] = Number(temp & 0xffn);
    temp >>= 8n;
  }
  return bytes;
}

// ============= Core Protocol Functions =============

/**
 * Hash to scalar with proper reduction
 */
function hashToScalar(data: Uint8Array): Uint8Array {
  const hash = sha512(data);
  const scalar_bigint = ed.etc.mod(bytesToNumberLE(hash), ed.CURVE.n);
  return numberToBytesLE(scalar_bigint, 32);
}

/**
 * Generate epoch parameters
 */
function generateEpochParams(): {
  A: Uint8Array;      // Public Ed25519 point: s1·G
  B: Uint8Array;      // Public Ed25519 point: s2·G
  s1: Uint8Array;     // Private Ed25519 key (32 bytes)
  s2: Uint8Array;     // Private Ed25519 key (32 bytes)
} {
  // Generate Ed25519 keypairs using nacl
  const keypair1 = nacl.sign.keyPair();
  const keypair2 = nacl.sign.keyPair();
  
  // Extract the 32-byte private keys (nacl stores them as 64 bytes)
  const s1 = keypair1.secretKey.slice(0, 32);
  const s2 = keypair2.secretKey.slice(0, 32);
  
  // Public keys are already 32 bytes
  const A = keypair1.publicKey;
  const B = keypair2.publicKey;
  
  return { A, B, s1, s2 };
}

/**
 * Compute PRP Capability: V_i = A + t_i·B
 */
function computePRPCap(
  A: Uint8Array,
  B: Uint8Array,
  index: number
): Uint8Array {
  // Domain separation: t_i = H("PRP-CAP" || index || A || B)
  const domain = new TextEncoder().encode('PRP-CAP');
  const indexBytes = new Uint8Array(4);
  new DataView(indexBytes.buffer).setUint32(0, index, false); // Big-endian
  
  const hashInput = new Uint8Array(domain.length + 4 + 64);
  hashInput.set(domain, 0);
  hashInput.set(indexBytes, domain.length);
  hashInput.set(A, domain.length + 4);
  hashInput.set(B, domain.length + 36);
  
  const t_i = hashToScalar(hashInput);
  
  // Use @noble/ed25519 for point arithmetic
  const pointA = ed.Point.fromHex(A);
  const pointB = ed.Point.fromHex(B);
  
  const t_i_bigint = ed.etc.mod(bytesToNumberLE(t_i), ed.CURVE.n);
  
  // V_i = A + t_i·B
  const tiB = pointB.multiply(t_i_bigint);
  const V_i = pointA.add(tiB);
  
  return V_i.toRawBytes();
}

/**
 * Compute private key for V_i that works with nacl
 * We need to create a valid Ed25519 private key that corresponds to v_i = s1 + t_i·s2
 */
function computePrivateKeyForVi(
  s1: Uint8Array,  // 32-byte Ed25519 private key
  s2: Uint8Array,  // 32-byte Ed25519 private key
  A: Uint8Array,
  B: Uint8Array,
  index: number
): Uint8Array {
  // Compute t_i the same way as in computePRPCap
  const domain = new TextEncoder().encode('PRP-CAP');
  const indexBytes = new Uint8Array(4);
  new DataView(indexBytes.buffer).setUint32(0, index, false);
  
  const hashInput = new Uint8Array(domain.length + 4 + 64);
  hashInput.set(domain, 0);
  hashInput.set(indexBytes, domain.length);
  hashInput.set(A, domain.length + 4);
  hashInput.set(B, domain.length + 36);
  
  const t_i = hashToScalar(hashInput);
  
  // Extract the actual scalars from the private keys
  // In nacl/Ed25519, the scalar is SHA512(privkey)[0:32] with clamping
  const s1_hash = nacl.hash(s1);
  const s2_hash = nacl.hash(s2);
  
  // Get the scalar parts and clamp them
  const s1_scalar = s1_hash.slice(0, 32);
  s1_scalar[0] &= 248;
  s1_scalar[31] &= 63;
  s1_scalar[31] |= 64;
  
  const s2_scalar = s2_hash.slice(0, 32);
  s2_scalar[0] &= 248;
  s2_scalar[31] &= 63;
  s2_scalar[31] |= 64;
  
  // Convert to bigints for arithmetic
  const s1_bigint = bytesToNumberLE(s1_scalar);
  const s2_bigint = bytesToNumberLE(s2_scalar);
  const t_i_bigint = ed.etc.mod(bytesToNumberLE(t_i), ed.CURVE.n);
  
  // v_i = s1 + t_i·s2 (mod n)
  const n = ed.CURVE.n;
  const ti_s2 = ed.etc.mod(t_i_bigint * s2_bigint, n);
  const v_i_bigint = ed.etc.mod(s1_bigint + ti_s2, n);
  
  // Convert back to bytes
  const v_i_scalar = numberToBytesLE(v_i_bigint, 32);
  
  // Return the raw scalar (will be handled specially in conversion)
  return v_i_scalar;
}

// ============= Single Ladder with ed2curve =============

/**
 * Alice (sender) computes shared secret
 */
function senderDeriveSingleLadder(
  senderEphemeralSecret: Uint8Array,  // Ed25519 private key (32 bytes)
  recipientVi: Uint8Array              // Ed25519 public point V_i
): Uint8Array {
  // Convert V_i from Ed25519 to X25519 using ed2curve
  const Vi_x25519 = ed2curve.convertPublicKey(recipientVi);
  if (!Vi_x25519) {
    throw new Error('Failed to convert V_i to X25519');
  }
  
  // Convert ephemeral secret from Ed25519 to X25519
  // First create a full Ed25519 keypair
  const ephemeralKeypair = nacl.sign.keyPair.fromSeed(senderEphemeralSecret);
  
  // Convert the secret key
  const ephemeral_x25519 = ed2curve.convertSecretKey(ephemeralKeypair.secretKey);
  if (!ephemeral_x25519) {
    throw new Error('Failed to convert ephemeral secret to X25519');
  }
  
  // Perform X25519 DH
  const sharedSecret = nacl.scalarMult(ephemeral_x25519, Vi_x25519);
  
  // KDF
  const kdfInput = new Uint8Array(32 + 12);
  kdfInput.set(sharedSecret, 0);
  kdfInput.set(new TextEncoder().encode('SingleLadder'), 32);
  
  return nacl.hash(kdfInput).slice(0, 32);
}

/**
 * Bob (receiver) computes shared secret
 * Special handling for the computed v_i scalar
 */
function receiverDeriveSingleLadder(
  senderEphemeralPublic: Uint8Array,  // Ed25519 public key
  v_i_scalar: Uint8Array               // Raw scalar v_i
): Uint8Array {
  // Convert ephemeral public from Ed25519 to X25519
  const E_x25519 = ed2curve.convertPublicKey(senderEphemeralPublic);
  if (!E_x25519) {
    throw new Error('Failed to convert ephemeral public to X25519');
  }
  
  // v_i_scalar is already the correct scalar, just need to clamp it for X25519
  const v_i_x25519 = new Uint8Array(v_i_scalar);
  v_i_x25519[0] &= 248;
  v_i_x25519[31] &= 127;  // X25519 clamping
  v_i_x25519[31] |= 64;
  
  // Perform X25519 DH
  const sharedSecret = nacl.scalarMult(v_i_x25519, E_x25519);
  
  // KDF (same as sender)
  const kdfInput = new Uint8Array(32 + 12);
  kdfInput.set(sharedSecret, 0);
  kdfInput.set(new TextEncoder().encode('SingleLadder'), 32);
  
  return nacl.hash(kdfInput).slice(0, 32);
}

// ============= Test Scenarios =============

function testSingleLadder(): boolean {
  console.log("Testing with ed2curve conversion library\n");
  
  // Bob generates epoch parameters
  const bob = generateEpochParams();
  console.log("Bob's epoch A: " + toHex(bob.A).slice(0, 16) + "...");
  console.log("Bob's epoch B: " + toHex(bob.B).slice(0, 16) + "...");
  
  // Alice generates ephemeral keypair
  const aliceKeypair = nacl.sign.keyPair();
  const aliceEphemeralSecret = aliceKeypair.secretKey.slice(0, 32);
  const aliceEphemeralPublic = aliceKeypair.publicKey;
  console.log("Alice ephemeral: " + toHex(aliceEphemeralPublic).slice(0, 16) + "...");
  
  const index = 42;
  
  // Alice computes V_42
  const V_42 = computePRPCap(bob.A, bob.B, index);
  console.log("\nV_42 = " + toHex(V_42).slice(0, 16) + "...");
  
  // Bob computes private scalar v_42
  const v_42 = computePrivateKeyForVi(bob.s1, bob.s2, bob.A, bob.B, index);
  
  // Verify v_42·G = V_42
  const v_42_bigint = bytesToNumberLE(v_42);
  const V_42_check = ed.Point.BASE.multiply(v_42_bigint).toRawBytes();
  const pointsMatch = nacl.verify(V_42, V_42_check);
  console.log("Math check: v_42·G == V_42? " + (pointsMatch ? "✓" : "✗"));
  
  // Alice derives shared secret
  console.log("\n[Alice] DH(e_alice, V_42)");
  const aliceShared = senderDeriveSingleLadder(aliceEphemeralSecret, V_42);
  console.log("Alice: " + toHex(aliceShared).slice(0, 16) + "...");
  
  // Bob derives shared secret
  console.log("\n[Bob] DH(v_42, E_alice)");
  const bobShared = receiverDeriveSingleLadder(aliceEphemeralPublic, v_42);
  console.log("Bob:   " + toHex(bobShared).slice(0, 16) + "...");
  
  // Check if they match
  const match = nacl.verify(aliceShared, bobShared);
  console.log("\n" + (match ? "✓ SUCCESS!" : "✗ Failed"));
  
  return match;
}

function testMultipleIndices(): boolean {
  console.log("Testing multiple indices\n");
  
  const bob = generateEpochParams();
  const aliceKeypair = nacl.sign.keyPair();
  const aliceSecret = aliceKeypair.secretKey.slice(0, 32);
  const alicePublic = aliceKeypair.publicKey;
  
  const indices = [0, 1, 42, 999999];
  const results: boolean[] = [];
  
  for (const i of indices) {
    const V_i = computePRPCap(bob.A, bob.B, i);
    const v_i = computePrivateKeyForVi(bob.s1, bob.s2, bob.A, bob.B, i);
    
    const aliceShared = senderDeriveSingleLadder(aliceSecret, V_i);
    const bobShared = receiverDeriveSingleLadder(alicePublic, v_i);
    
    const match = nacl.verify(aliceShared, bobShared);
    results.push(match);
    
    console.log(`Index ${i.toString().padEnd(6)}: ${match ? '✓' : '✗'}`);
  }
  
  const allMatch = results.every(r => r);
  console.log("\n" + (allMatch ? "✓ All indices work!" : "✗ Some failed"));
  
  return allMatch;
}

function testDoubleladder(): boolean {
  console.log("Testing double ladder (simultaneous initiation)\n");
  
  // Both have epoch parameters
  const alice = generateEpochParams();
  const bob = generateEpochParams();
  
  // Both create ephemeral keys
  const aliceEph = nacl.sign.keyPair();
  const bobEph = nacl.sign.keyPair();
  
  // Indices
  const aliceIndex = 42;
  const bobIndex = 99;
  
  // Compute V_i values
  const aliceV = computePRPCap(alice.A, alice.B, aliceIndex);
  const bobV = computePRPCap(bob.A, bob.B, bobIndex);
  
  // Compute private scalars
  const alice_vi = computePrivateKeyForVi(alice.s1, alice.s2, alice.A, alice.B, aliceIndex);
  const bob_vi = computePrivateKeyForVi(bob.s1, bob.s2, bob.A, bob.B, bobIndex);
  
  // Alice computes both ladders
  const aliceLadder1 = senderDeriveSingleLadder(aliceEph.secretKey.slice(0, 32), bobV);
  const aliceLadder2 = receiverDeriveSingleLadder(bobEph.publicKey, alice_vi);
  
  // Bob computes both ladders  
  const bobLadder1 = senderDeriveSingleLadder(bobEph.secretKey.slice(0, 32), aliceV);
  const bobLadder2 = receiverDeriveSingleLadder(aliceEph.publicKey, bob_vi);
  
  // Merge (sort for canonical ordering)
  function merge(l1: Uint8Array, l2: Uint8Array): Uint8Array {
    const sorted = toHex(l1) < toHex(l2) ? [l1, l2] : [l2, l1];
    const input = new Uint8Array(64 + 12);
    input.set(sorted[0], 0);
    input.set(sorted[1], 32);
    input.set(new TextEncoder().encode('DoubleLadder'), 64);
    return nacl.hash(input).slice(0, 32);
  }
  
  const aliceMerged = merge(aliceLadder1, aliceLadder2);
  const bobMerged = merge(bobLadder2, bobLadder1);
  
  console.log("Alice merged: " + toHex(aliceMerged).slice(0, 16) + "...");
  console.log("Bob merged:   " + toHex(bobMerged).slice(0, 16) + "...");
  
  const match = nacl.verify(aliceMerged, bobMerged);
  console.log("\n" + (match ? "✓ Double ladder works!" : "✗ Double ladder failed"));
  
  return match;
}

// ============= Main =============

function main() {
  console.log("=== PRP-Cap 0-RTT with ed2curve ===\n");
  
  console.log("Test 1: Single Ladder");
  console.log("=".repeat(40));
  const test1 = testSingleLadder();
  
  console.log("\n\nTest 2: Multiple Indices");
  console.log("=".repeat(40));
  const test2 = testMultipleIndices();
  
  console.log("\n\nTest 3: Double Ladder");
  console.log("=".repeat(40));
  const test3 = testDoubleladder();
  
  console.log("\n\n=== Results ===");
  console.log(`Single Ladder: ${test1 ? "PASS ✓" : "FAIL ✗"}`);
  console.log(`Multiple Indices: ${test2 ? "PASS ✓" : "FAIL ✗"}`);
  console.log(`Double Ladder: ${test3 ? "PASS ✓" : "FAIL ✗"}`);
  
  if (test1 && test2 && test3) {
    console.log("\n🎉 SUCCESS! PRP-Cap protocol fully validated!");
    console.log("\nKey achievements:");
    console.log("• PRP-cap: V_i = A + t_i·B using Ed25519");
    console.log("• Private scalar: v_i = s1 + t_i·s2");
    console.log("• Ed25519→X25519 conversion works correctly");
    console.log("• Single and double ladder patterns validated");
    console.log("• Unlimited indices from just 2 public points");
  }
}

main();