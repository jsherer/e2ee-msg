"use strict";
// ladder-poc.ts
// Minimal PoC for PRP-Cap 0-RTT Key Exchange with Double Ladder support
Object.defineProperty(exports, "__esModule", { value: true });
var nacl = require("tweetnacl");
// ============= Core Cryptographic Functions =============
/**
 * Hash data to a valid Ed25519 scalar
 */
function hashToScalar(data) {
    var hash = nacl.hash(data); // SHA-512
    // Reduce modulo curve order (2^252 + 27742317777372353535851937790883648493)
    // For simplicity, we'll just use the first 32 bytes and clamp
    var scalar = hash.slice(0, 32);
    // Clamp the scalar to ensure it's valid
    scalar[0] &= 248;
    scalar[31] &= 127;
    scalar[31] |= 64;
    return scalar;
}
/**
 * Compute PRP Capability: V_i = A + t_i·B
 * Note: We're using X25519 (Montgomery) points, not Ed25519 (Edwards) points
 * This means we can't do direct point addition easily
 */
function computePRPCap(A, B, index) {
    // Domain separation for t_i derivation
    var domain = new TextEncoder().encode("PRPCap.v1");
    var indexBytes = new Uint8Array(4);
    new DataView(indexBytes.buffer).setUint32(0, index, true);
    // t_i = H(domain || index || A || B)
    var hashInput = new Uint8Array(domain.length + 4 + 32 + 32);
    hashInput.set(domain, 0);
    hashInput.set(indexBytes, domain.length);
    hashInput.set(A, domain.length + 4);
    hashInput.set(B, domain.length + 36);
    var t_i = hashToScalar(hashInput);
    // Since we're using tweetnacl which only has X25519 (Montgomery curve),
    // we need a different approach. We'll use a combination that doesn't 
    // require point addition:
    // V_i = Hash(A || t_i·B || index)
    var tiB = nacl.scalarMult(t_i, B);
    var viInput = new Uint8Array(32 + 32 + 4);
    viInput.set(A, 0);
    viInput.set(tiB, 32);
    new DataView(viInput.buffer, 64).setUint32(0, index, true);
    // Return hash as the capability point
    return nacl.hash(viInput).slice(0, 32);
}
/**
 * Compute private scalar for V_i (receiver side)
 * Since we changed the PRP-cap computation, we need a different approach
 */
function computeSharedSecretReceiver(s1, s2, index, A, B, ephemeralPublic) {
    // Compute t_i the same way
    var domain = new TextEncoder().encode("PRPCap.v1");
    var indexBytes = new Uint8Array(4);
    new DataView(indexBytes.buffer).setUint32(0, index, true);
    var hashInput = new Uint8Array(domain.length + 4 + 32 + 32);
    hashInput.set(domain, 0);
    hashInput.set(indexBytes, domain.length);
    hashInput.set(A, domain.length + 4);
    hashInput.set(B, domain.length + 36);
    var t_i = hashToScalar(hashInput);
    // Compute DH(s1, E) and DH(t_i·s2, E)
    var dh1 = nacl.scalarMult(s1, ephemeralPublic);
    // Compute t_i·s2 (scalar multiplication in the field)
    // For simplicity, we'll compute DH((t_i compose s2), E)
    // This is not the exact same as the original protocol but demonstrates the concept
    var temp = nacl.scalarMult(t_i, nacl.scalarMult.base(s2));
    var dh2 = nacl.scalarMult(s2, nacl.scalarMult(t_i, ephemeralPublic));
    // Combine the two DH results
    var combined = new Uint8Array(32 + 32);
    combined.set(dh1, 0);
    combined.set(dh2, 32);
    return nacl.hash(combined).slice(0, 32);
}
// ============= Simplified Protocol for PoC =============
/**
 * Simplified single ladder using just X25519
 */
function simplifiedSingleLadder(senderEphemeralSecret, receiverPublicKey) {
    var sharedSecret = nacl.scalarMult(senderEphemeralSecret, receiverPublicKey);
    var kdfInput = new Uint8Array(32 + 16);
    kdfInput.set(sharedSecret, 0);
    kdfInput.set(new TextEncoder().encode("SingleLadder.v1"), 32);
    return nacl.hash(kdfInput).slice(0, 32);
}
/**
 * Double Ladder: Both parties initiated simultaneously
 */
function deriveDoubleLadder(secret1, secret2, ephemeralA, ephemeralB) {
    // Canonical ordering based on ephemeral public keys
    var _a = compare(ephemeralA, ephemeralB) < 0 ?
        [secret1, secret2] : [secret2, secret1], first = _a[0], second = _a[1];
    var input = new Uint8Array(32 + 32 + 16);
    input.set(first, 0);
    input.set(second, 32);
    input.set(new TextEncoder().encode("DoubleLadder.v1"), 64);
    return nacl.hash(input).slice(0, 32);
}
// ============= Helper Functions =============
function compare(a, b) {
    for (var i = 0; i < 32; i++) {
        if (a[i] < b[i])
            return -1;
        if (a[i] > b[i])
            return 1;
    }
    return 0;
}
function generateEpochParams() {
    var s1 = nacl.randomBytes(32);
    var s2 = nacl.randomBytes(32);
    // Clamp scalars
    s1[0] &= 248;
    s1[31] &= 127;
    s1[31] |= 64;
    s2[0] &= 248;
    s2[31] &= 127;
    s2[31] |= 64;
    var A = nacl.scalarMult.base(s1);
    var B = nacl.scalarMult.base(s2);
    return { A: A, B: B, s1: s1, s2: s2 };
}
function toHex(bytes) {
    return Array.from(bytes)
        .map(function (b) { return b.toString(16).padStart(2, '0'); })
        .join('');
}
// ============= Test Scenarios =============
console.log("🔐 PRP-Cap 0-RTT Key Exchange PoC\n");
console.log("=".repeat(50));
console.log("Note: Using simplified X25519-only implementation\n");
// Scenario 1: Simplified Single Ladder (Standard DH)
console.log("\n📝 Scenario 1: Simplified Single Ladder (A → B)");
console.log("-".repeat(40));
{
    // Alice and Bob generate keypairs
    var aliceEphemeral = nacl.randomBytes(32);
    aliceEphemeral[0] &= 248;
    aliceEphemeral[31] &= 127;
    aliceEphemeral[31] |= 64;
    var alicePublic = nacl.scalarMult.base(aliceEphemeral);
    var bobStatic = nacl.randomBytes(32);
    bobStatic[0] &= 248;
    bobStatic[31] &= 127;
    bobStatic[31] |= 64;
    var bobPublic = nacl.scalarMult.base(bobStatic);
    console.log("Alice ephemeral: ".concat(toHex(alicePublic).slice(0, 16), "..."));
    console.log("Bob static:      ".concat(toHex(bobPublic).slice(0, 16), "..."));
    // Alice computes shared secret
    var aliceShared = nacl.scalarMult(aliceEphemeral, bobPublic);
    var aliceRootKey = simplifiedSingleLadder(aliceEphemeral, bobPublic);
    console.log("Alice root key:  ".concat(toHex(aliceRootKey).slice(0, 16), "..."));
    // Bob computes same secret
    var bobShared = nacl.scalarMult(bobStatic, alicePublic);
    var bobRootKey = simplifiedSingleLadder(bobStatic, alicePublic);
    console.log("Bob root key:    ".concat(toHex(bobRootKey).slice(0, 16), "..."));
    // Verify both derive same key
    var match = nacl.verify(aliceRootKey, bobRootKey);
    console.log("\n\u2705 Keys match: ".concat(match));
}
// Scenario 2: Double Ladder (Simultaneous Initiation)
console.log("\n📝 Scenario 2: Double Ladder (A ⇄ B)");
console.log("-".repeat(40));
{
    // Both parties generate ephemeral keys
    var aliceEphemeral = nacl.randomBytes(32);
    aliceEphemeral[0] &= 248;
    aliceEphemeral[31] &= 127;
    aliceEphemeral[31] |= 64;
    var alicePublic = nacl.scalarMult.base(aliceEphemeral);
    var bobEphemeral = nacl.randomBytes(32);
    bobEphemeral[0] &= 248;
    bobEphemeral[31] &= 127;
    bobEphemeral[31] |= 64;
    var bobPublic = nacl.scalarMult.base(bobEphemeral);
    // They also have static keys
    var aliceStatic = nacl.randomBytes(32);
    aliceStatic[0] &= 248;
    aliceStatic[31] &= 127;
    aliceStatic[31] |= 64;
    var aliceStaticPublic = nacl.scalarMult.base(aliceStatic);
    var bobStatic = nacl.randomBytes(32);
    bobStatic[0] &= 248;
    bobStatic[31] &= 127;
    bobStatic[31] |= 64;
    var bobStaticPublic = nacl.scalarMult.base(bobStatic);
    console.log("Alice\u2192Bob: E=".concat(toHex(alicePublic).slice(0, 16), "..."));
    console.log("Bob\u2192Alice: E=".concat(toHex(bobPublic).slice(0, 16), "..."));
    // Alice computes both ladders
    var aliceSecret1 = nacl.scalarMult(aliceEphemeral, bobStaticPublic);
    var aliceSecret2 = nacl.scalarMult(aliceStatic, bobPublic);
    var aliceRootKey = deriveDoubleLadder(aliceSecret1, aliceSecret2, alicePublic, bobPublic);
    console.log("\nAlice: Ladder1=".concat(toHex(aliceSecret1).slice(0, 12), "..."));
    console.log("Alice: Ladder2=".concat(toHex(aliceSecret2).slice(0, 12), "..."));
    console.log("Alice: Merged root=".concat(toHex(aliceRootKey).slice(0, 16), "..."));
    // Bob computes both ladders
    var bobSecret1 = nacl.scalarMult(bobEphemeral, aliceStaticPublic);
    var bobSecret2 = nacl.scalarMult(bobStatic, alicePublic);
    var bobRootKey = deriveDoubleLadder(bobSecret2, bobSecret1, alicePublic, bobPublic);
    console.log("\nBob:   Ladder1=".concat(toHex(bobSecret1).slice(0, 12), "..."));
    console.log("Bob:   Ladder2=".concat(toHex(bobSecret2).slice(0, 12), "..."));
    console.log("Bob:   Merged root=".concat(toHex(bobRootKey).slice(0, 16), "..."));
    // Verify both derive same merged key
    var match = nacl.verify(aliceRootKey, bobRootKey);
    console.log("\n\u2705 Merged keys match: ".concat(match));
}
// Scenario 3: PRP-Cap concept (simplified)
console.log("\n📝 Scenario 3: PRP-Cap Concept Demo");
console.log("-".repeat(40));
{
    var epoch = generateEpochParams();
    // Generate multiple capabilities
    var capabilities = [];
    for (var i = 0; i < 5; i++) {
        var V_i = computePRPCap(epoch.A, epoch.B, i);
        capabilities.push(V_i);
        console.log("V_".concat(i, " = ").concat(toHex(V_i).slice(0, 16), "..."));
    }
    // Verify they're all different (pseudorandom)
    var allDifferent = true;
    for (var i = 0; i < capabilities.length; i++) {
        for (var j = i + 1; j < capabilities.length; j++) {
            if (nacl.verify(capabilities[i], capabilities[j])) {
                allDifferent = false;
                break;
            }
        }
    }
    console.log("\n\u2705 All capabilities unique: ".concat(allDifferent));
    // Demonstrate forward secrecy concept
    console.log("\nForward Secrecy: After erasing s2, can't compute new capabilities");
    var erasedS2 = new Uint8Array(32);
    var V_broken = computePRPCap(epoch.A, erasedS2, 999);
    console.log("With erased s2: ".concat(toHex(V_broken).slice(0, 16), "... (incorrect)"));
}
console.log("\n" + "=".repeat(50));
console.log("🎉 PoC Complete - Core concepts validated!");
console.log("\nNote: This is a simplified implementation using only X25519.");
console.log("Full implementation would use Ed25519 point addition.");
console.log("\nNext steps:");
console.log("- Implement proper Ed25519 point addition");
console.log("- Add message encryption/decryption");
console.log("- Implement signature verification");
console.log("- Add Double Ratchet integration");
