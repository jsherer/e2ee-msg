# PRP-Cap 0-RTT Key Exchange Protocol - Implementation Brief

## Protocol Overview
A forward-secure, zero round-trip time (0-RTT) key exchange protocol designed for asynchronous, serverless peer-to-peer messaging. Enables immediate encrypted communication without prior online interaction, while providing forward secrecy through epoch-based key erasure.

## Key Innovation: PRP Capability (Pseudorandom Permutation)
Instead of pre-generating and storing individual pre-keys, the protocol uses a cryptographic construction where:
- Recipients publish two public points `(A, B)` per epoch
- Senders can derive unlimited ephemeral receiver keys `V_i = A + H(i)·B` for any index `i`
- Each `V_i` appears random but can be computed by anyone
- Only the recipient (holding private keys) can decrypt messages sent to any `V_i`

## Security Properties
- **Forward Secrecy**: Achieved by deleting `s2` (private key for B) at epoch end. Even if all other keys are compromised, past messages remain secure.
- **0-RTT**: Senders can encrypt immediately using only public epoch parameters
- **No Key Exhaustion**: Unlimited indices available without storage
- **Authentication**: Via Ed25519 signatures, separate from encryption

## Protocol Flow

### Setup (Out-of-Band)
Exchange via QR code or trusted channel:
- Identity keys (for signatures)
- Current epoch parameters `(A, B)`

### Single Initiation (Normal Case)
1. Alice generates ephemeral `e`, computes `V_i` for Bob's epoch
2. Alice sends: `E=e·G, V_i, Encrypt(key=DH(e,V_i), data), Signature`
3. Bob computes same shared secret using private key for `V_i`
4. Both initialize Double Ratchet with shared secret

### Simultaneous Initiation (Double Ladder)
1. Alice and Bob both send initial messages
2. Both compute TWO shared secrets (one from each direction)
3. Merge secrets deterministically: `KDF(ladder1 || ladder2)`
4. Initialize Double Ratchet with stronger merged secret

## Implementation Requirements
Build a proof-of-concept that demonstrates:
1. The PRP-cap construction works (computing `V_i = A + t_i·B`)
2. Both parties derive identical secrets in single ladder mode
3. Both parties derive identical merged secrets in double ladder mode
4. The construction provides the claimed security properties

---

# Minimal PoC Specification for PRP-Cap 0-RTT Key Exchange

## Objective
Build a proof-of-concept that validates the core cryptographic construction of the PRP-cap 0-RTT key exchange protocol. Focus only on key derivation, not the full messaging protocol.

## Dependencies
```json
{
  "dependencies": {
    "tweetnacl": "^1.0.3",
    "@noble/ed25519": "^2.0.0"
  }
}
```

## Core Components to Implement

### 1. Epoch Parameter Generation
```typescript
function generateEpochParams(): {
  A: Uint8Array;      // Public: s1·G (32 bytes)
  B: Uint8Array;      // Public: s2·G (32 bytes)
  s1: Uint8Array;     // Secret: kept entire epoch (32 bytes)
  s2: Uint8Array;     // Secret: deleted at epoch end (32 bytes)
}
```
- Generate two random scalars s1, s2
- Clamp them to valid Curve25519 scalars (clear/set specific bits)
- Compute public points A = s1·G, B = s2·G using `nacl.scalarMult.base()`

### 2. PRP Capability Computation
```typescript
function computePRPCap(
  A: Uint8Array,      // Public point A
  B: Uint8Array,      // Public point B
  index: number       // Arbitrary index
): Uint8Array         // Returns V_i = A + t_i·B (32 bytes)
```
- Compute t_i = H_to_scalar("PRP-CAP" || index || A || B)
- Use @noble/ed25519 for point addition: V_i = A + t_i·B
- Return the resulting point

### 3. Helper: Scalar Derivation from Hash
```typescript
function H_to_scalar(data: Uint8Array): Uint8Array
```
- Hash input with SHA-512 (nacl.hash)
- Reduce modulo curve order using @noble/ed25519's modular arithmetic
- Return valid 32-byte scalar

### 4. Single Ladder (Normal 0-RTT)
```typescript
function deriveSingleLadder(
  senderEphemeralSecret: Uint8Array,   // e_alice (32 bytes)
  recipientV_i: Uint8Array              // V_i_bob (32 bytes)
): Uint8Array                           // Shared secret (32 bytes)
```
**Sender side:**
- Compute DH(e_alice, V_i_bob) using nacl.scalarMult()
- Note: Need to convert Ed25519 point V_i to X25519 format

**Receiver side (separate function):**
```typescript
function deriveSingleLadderReceiver(
  senderEphemeralPublic: Uint8Array,   // E_alice (32 bytes)
  recipientS1: Uint8Array,              // s1_bob (32 bytes)
  recipientS2: Uint8Array,              // s2_bob (32 bytes)
  index: number                         // Index used for V_i
): Uint8Array                           // Shared secret (32 bytes)
```
- Compute private scalar: v_i = s1 + t_i·s2
- Compute DH(v_i, E_alice)
- Should yield same shared secret as sender

### 5. Double Ladder (Simultaneous Initiation)
```typescript
function deriveDoubleLadder(
  aliceEphemeralSecret: Uint8Array,    // e_alice
  aliceV_i: Uint8Array,                // V_i_alice  
  aliceS1: Uint8Array,                 // s1_alice
  aliceS2: Uint8Array,                 // s2_alice
  aliceIndex: number,                  // i_alice
  bobEphemeralPublic: Uint8Array,      // E_bob
  bobV_j: Uint8Array,                  // V_j_bob
  bobIndex: number                     // j_bob
): Uint8Array                          // Merged secret (32 bytes)
```
- Compute ladder1 = DH(e_alice, V_j_bob)
- Compute ladder2 = DH(v_i_alice_private, E_bob)
- Merge: KDF(sort(ladder1, ladder2) || metadata)
- Both parties must derive identical merged secret

### 6. Test Scenarios

#### Test 1: Single Ladder Consistency
```typescript
function testSingleLadder(): boolean
```
- Generate epoch params for Bob
- Alice creates ephemeral keypair
- Alice computes V_42 for Bob's epoch
- Alice derives shared secret via sender method
- Bob derives shared secret via receiver method
- Assert both secrets match
- Print success/failure with hex values

#### Test 2: Double Ladder Merge
```typescript
function testDoubleLadder(): boolean
```
- Generate epoch params for both Alice and Bob
- Both create ephemeral keypairs
- Alice chooses index 42, Bob chooses index 99
- Both compute their V_i values
- Alice derives merged secret
- Bob derives merged secret (should be identical)
- Assert both merged secrets match
- Print success/failure with hex values

#### Test 3: PRP-Cap Properties
```typescript
function testPRPCapProperties(): boolean
```
- Generate epoch parameters
- Compute V_i for multiple indices (0, 1, 42, 999999)
- Verify each V_i is different
- Verify V_i appears random (no obvious patterns)
- Verify recomputing same index gives same V_i
- Print sample V_i values

### 7. Main Test Runner
```typescript
function main() {
  console.log("=== PRP-Cap 0-RTT PoC ===\n");
  
  console.log("Test 1: Single Ladder");
  const test1 = testSingleLadder();
  
  console.log("\nTest 2: Double Ladder");
  const test2 = testDoubleLadder();
  
  console.log("\nTest 3: PRP-Cap Properties");
  const test3 = testPRPCapProperties();
  
  console.log("\n=== Results ===");
  console.log(`Single Ladder: ${test1 ? "PASS ✓" : "FAIL ✗"}`);
  console.log(`Double Ladder: ${test2 ? "PASS ✓" : "FAIL ✗"}`);
  console.log(`PRP Properties: ${test3 ? "PASS ✓" : "FAIL ✗"}`);
}

main();
```

## Expected Output
```
=== PRP-Cap 0-RTT PoC ===

Test 1: Single Ladder
Alice ephemeral public: 3f2e1a...
Bob's V_42: 8c4d5b...
Alice derives: 7a9b3c...
Bob derives: 7a9b3c...
✓ Single ladder SUCCESS - both parties derived same secret

Test 2: Double Ladder
Alice -> Bob ladder: 4e5f6a...
Bob -> Alice ladder: 9b8c7d...
Alice merged secret: 2a3b4c...
Bob merged secret: 2a3b4c...
✓ Double ladder SUCCESS - merge produced identical secrets

Test 3: PRP-Cap Properties
V_0:   1a2b3c...
V_1:   8e7f6d...
V_42:  9c8b7a...
V_999999: 3f4e5d...
✓ All V_i values are unique and deterministic

=== Results ===
Single Ladder: PASS ✓
Double Ladder: PASS ✓
PRP Properties: PASS ✓
```

## Implementation Notes
1. Use `nacl.scalarMult()` for X25519 operations
2. Use `@noble/ed25519` for point addition and Ed25519<->X25519 conversion
3. Clamp scalars properly (bits 0, 1, 2, 255 cleared; bit 254 set)
4. Include domain separation in all hash operations
5. Use big-endian for index encoding in hashes
6. Handle the Ed25519 to X25519 conversion carefully (use noble's `.toX25519()` method)

## Success Criteria
- [ ] Alice and Bob derive identical shared secrets in single ladder
- [ ] Alice and Bob derive identical merged secrets in double ladder  
- [ ] V_i values are deterministic but appear random
- [ ] No cryptographic operations fail or throw exceptions

## File Structure
Create a single file `prp-cap-poc.ts` with all functions and tests. Keep it under 300 lines total for clarity.

