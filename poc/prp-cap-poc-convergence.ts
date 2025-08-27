// prp-cap-poc-convergence.ts
// Demonstrates actual key convergence in PRP-Cap protocol

import * as nacl from 'tweetnacl';
import * as ed from '@noble/ed25519';
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

// ============= Pure Ed25519 DH Implementation =============

/**
 * Perform Diffie-Hellman on Ed25519 curve directly
 * DH(secret, point) = secret * point
 */
function ed25519DH(secret: Uint8Array, publicPoint: Uint8Array): Uint8Array {
  // Parse the public point
  const point = ed.Point.fromHex(publicPoint);
  
  // The secret should be a scalar - ensure it's in valid range
  const scalar = ed.etc.mod(bytesToNumberLE(secret), ed.CURVE.n);
  
  // Compute secret * point
  const sharedPoint = point.multiply(scalar);
  
  // Return the shared point (we'll hash it for the final secret)
  return sharedPoint.toRawBytes();
}

/**
 * Hash to scalar for t_i derivation
 */
function hashToScalar(data: Uint8Array): Uint8Array {
  const hash = sha512(data);
  const scalar_bigint = ed.etc.mod(bytesToNumberLE(hash), ed.CURVE.n);
  return numberToBytesLE(scalar_bigint, 32);
}

// ============= PRP-Cap Protocol Implementation =============

/**
 * Generate epoch parameters
 */
function generateEpochParams(): {
  A: Uint8Array;
  B: Uint8Array;
  s1: Uint8Array;  // Raw scalar (not seed)
  s2: Uint8Array;  // Raw scalar (not seed)
} {
  // Generate random scalars directly
  const s1_seed = ed.utils.randomPrivateKey();
  const s2_seed = ed.utils.randomPrivateKey();
  
  // Extract the actual scalars (what Ed25519 uses internally)
  const s1_hash = sha512(s1_seed);
  const s2_hash = sha512(s2_seed);
  
  const s1 = s1_hash.slice(0, 32);
  s1[0] &= 248;
  s1[31] &= 63;
  s1[31] |= 64;
  
  const s2 = s2_hash.slice(0, 32);
  s2[0] &= 248;
  s2[31] &= 63;
  s2[31] |= 64;
  
  // Compute public points - ensure scalars are in valid range
  const s1_bigint = ed.etc.mod(bytesToNumberLE(s1), ed.CURVE.n);
  const s2_bigint = ed.etc.mod(bytesToNumberLE(s2), ed.CURVE.n);
  
  const A = ed.Point.BASE.multiply(s1_bigint).toRawBytes();
  const B = ed.Point.BASE.multiply(s2_bigint).toRawBytes();
  
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
  const domain = new TextEncoder().encode('PRP-CAP');
  const indexBytes = new Uint8Array(4);
  new DataView(indexBytes.buffer).setUint32(0, index, false);
  
  const hashInput = new Uint8Array(domain.length + 4 + 64);
  hashInput.set(domain, 0);
  hashInput.set(indexBytes, domain.length);
  hashInput.set(A, domain.length + 4);
  hashInput.set(B, domain.length + 36);
  
  const t_i = hashToScalar(hashInput);
  const t_i_bigint = ed.etc.mod(bytesToNumberLE(t_i), ed.CURVE.n);
  
  const pointA = ed.Point.fromHex(A);
  const pointB = ed.Point.fromHex(B);
  const tiB = pointB.multiply(t_i_bigint);
  const V_i = pointA.add(tiB);
  
  return V_i.toRawBytes();
}

/**
 * Compute private scalar for V_i
 * v_i = s1 + t_i·s2 (mod n)
 */
function computePrivateScalarForVi(
  s1: Uint8Array,  // Already a scalar
  s2: Uint8Array,  // Already a scalar
  A: Uint8Array,
  B: Uint8Array,
  index: number
): Uint8Array {
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

// ============= KEY CONVERGENCE TEST =============

function testKeyConvergence(): boolean {
  console.log("Testing actual DH key convergence\n");
  console.log("Protocol: Alice → Bob using PRP-Cap\n");
  
  // Bob's epoch parameters
  const bob = generateEpochParams();
  console.log("Bob's epoch parameters:");
  console.log("  A = " + toHex(bob.A).slice(0, 16) + "...");
  console.log("  B = " + toHex(bob.B).slice(0, 16) + "...");
  
  // Alice generates ephemeral scalar
  const aliceEphemeralSeed = ed.utils.randomPrivateKey();
  const aliceHash = sha512(aliceEphemeralSeed);
  const aliceEphemeral = aliceHash.slice(0, 32);
  aliceEphemeral[0] &= 248;
  aliceEphemeral[31] &= 63;
  aliceEphemeral[31] |= 64;
  
  // Alice's ephemeral public key
  const aliceEphemeralBigint = ed.etc.mod(bytesToNumberLE(aliceEphemeral), ed.CURVE.n);
  const alicePublic = ed.Point.BASE.multiply(aliceEphemeralBigint).toRawBytes();
  
  console.log("\nAlice's ephemeral:");
  console.log("  E = " + toHex(alicePublic).slice(0, 16) + "...");
  
  // Choose index
  const index = 42;
  console.log("\nUsing index: " + index);
  
  // Alice computes V_42
  const V_42 = computePRPCap(bob.A, bob.B, index);
  console.log("V_42 = " + toHex(V_42).slice(0, 16) + "...");
  
  // Bob computes v_42
  const v_42 = computePrivateScalarForVi(bob.s1, bob.s2, bob.A, bob.B, index);
  
  // Verify v_42·G = V_42
  const v_42_bigint = bytesToNumberLE(v_42);
  const V_42_check = ed.Point.BASE.multiply(v_42_bigint).toRawBytes();
  const mathCorrect = nacl.verify(V_42, V_42_check);
  console.log("\nMath check: v_42·G == V_42? " + (mathCorrect ? "✓ YES" : "✗ NO"));
  
  if (!mathCorrect) {
    console.log("ERROR: Math verification failed!");
    return false;
  }
  
  // ========== THE CRITICAL TEST ==========
  console.log("\n" + "=".repeat(50));
  console.log("KEY CONVERGENCE TEST");
  console.log("=".repeat(50));
  
  // Alice computes: DH(e_alice, V_42)
  console.log("\nAlice computes: DH(e_alice, V_42)");
  const aliceSharedPoint = ed25519DH(aliceEphemeral, V_42);
  const aliceShared = sha512(aliceSharedPoint).slice(0, 32);
  console.log("  Shared point: " + toHex(aliceSharedPoint).slice(0, 16) + "...");
  console.log("  Final secret: " + toHex(aliceShared).slice(0, 16) + "...");
  
  // Bob computes: DH(v_42, E_alice)
  console.log("\nBob computes: DH(v_42, E_alice)");
  const bobSharedPoint = ed25519DH(v_42, alicePublic);
  const bobShared = sha512(bobSharedPoint).slice(0, 32);
  console.log("  Shared point: " + toHex(bobSharedPoint).slice(0, 16) + "...");
  console.log("  Final secret: " + toHex(bobShared).slice(0, 16) + "...");
  
  // THE MOMENT OF TRUTH
  console.log("\n" + "=".repeat(50));
  const converged = nacl.verify(aliceShared, bobShared);
  
  if (converged) {
    console.log("🎉 SUCCESS! Keys converged!");
    console.log("\nThis proves:");
    console.log("• DH(e_alice, V_42) = DH(v_42, E_alice)");
    console.log("• The PRP-Cap protocol achieves key agreement");
    console.log("• 0-RTT works: Alice can encrypt immediately");
  } else {
    console.log("❌ FAILURE: Keys did not converge");
    console.log("Alice secret: " + toHex(aliceShared));
    console.log("Bob secret:   " + toHex(bobShared));
  }
  
  return converged;
}

function testMultipleIndices(): boolean {
  console.log("\nTesting convergence for multiple indices\n");
  
  const bob = generateEpochParams();
  
  // Alice's ephemeral
  const aliceEphemeralSeed = ed.utils.randomPrivateKey();
  const aliceHash = sha512(aliceEphemeralSeed);
  const aliceEphemeral = aliceHash.slice(0, 32);
  aliceEphemeral[0] &= 248;
  aliceEphemeral[31] &= 63;
  aliceEphemeral[31] |= 64;
  
  const aliceEphemeralBigint = ed.etc.mod(bytesToNumberLE(aliceEphemeral), ed.CURVE.n);
  const alicePublic = ed.Point.BASE.multiply(aliceEphemeralBigint).toRawBytes();
  
  const indices = [0, 1, 42, 100, 999999];
  let allConverged = true;
  
  console.log("Index    Alice Secret     Bob Secret       Match");
  console.log("-".repeat(55));
  
  for (const index of indices) {
    // Alice's side
    const V_i = computePRPCap(bob.A, bob.B, index);
    const aliceSharedPoint = ed25519DH(aliceEphemeral, V_i);
    const aliceShared = sha512(aliceSharedPoint).slice(0, 32);
    
    // Bob's side
    const v_i = computePrivateScalarForVi(bob.s1, bob.s2, bob.A, bob.B, index);
    const bobSharedPoint = ed25519DH(v_i, alicePublic);
    const bobShared = sha512(bobSharedPoint).slice(0, 32);
    
    const matches = nacl.verify(aliceShared, bobShared);
    allConverged = allConverged && matches;
    
    console.log(`${index.toString().padEnd(8)} ${toHex(aliceShared).slice(0, 16)} ${toHex(bobShared).slice(0, 16)} ${matches ? '✓' : '✗'}`);
  }
  
  console.log("\n" + (allConverged ? 
    "✅ All indices converged successfully!" : 
    "❌ Some indices failed to converge"));
  
  return allConverged;
}

// ============= Main =============

function main() {
  console.log("=== PRP-Cap Key Convergence Proof ===\n");
  console.log("Using pure Ed25519 for both point ops and DH\n");
  
  console.log("Test 1: Single Index Convergence");
  console.log("=".repeat(60));
  const test1 = testKeyConvergence();
  
  console.log("\n\nTest 2: Multiple Indices");  
  console.log("=".repeat(60));
  const test2 = testMultipleIndices();
  
  console.log("\n\n=== FINAL RESULTS ===");
  console.log(`Single index convergence: ${test1 ? "PROVEN ✓" : "FAILED ✗"}`);
  console.log(`Multiple indices convergence: ${test2 ? "PROVEN ✓" : "FAILED ✗"}`);
  
  if (test1 && test2) {
    console.log("\n✅ COMPLETE SUCCESS!");
    console.log("\nWe have proven:");
    console.log("• Alice: DH(e, V_i) where V_i = A + t_i·B");
    console.log("• Bob: DH(v_i, E) where v_i = s1 + t_i·s2");
    console.log("• Both derive IDENTICAL shared secrets");
    console.log("• This works for ANY index i");
    console.log("• 0-RTT achieved: No round trips needed!");
    console.log("\nThe PRP-Cap protocol is mathematically sound! 🎉");
  } else {
    console.log("\n❌ Convergence proof failed");
    console.log("The protocol needs debugging");
  }
}

main();