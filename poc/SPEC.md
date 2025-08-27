# PRP-Cap 0-RTT Key Exchange Protocol Specification

## 1. Overview

A forward-secure, zero round-trip time (0-RTT) key exchange protocol for asynchronous, serverless peer-to-peer messaging. This protocol enables immediate encrypted communication without prior online interaction, while providing forward secrecy through epoch-based key erasure.

## 2. Protocol Goals

- **0-RTT**: Send encrypted messages without prior round trips
- **Forward Secrecy**: Past messages remain secure even if long-term keys are compromised
- **Asynchronous**: No requirement for parties to be online simultaneously  
- **Serverless**: No third-party infrastructure required
- **Post-Compromise Security**: Transitions to Double Ratchet after initial exchange

## 3. Cryptographic Primitives

- **Curve**: Ed25519 for point operations, X25519 for Diffie-Hellman
- **Hash**: SHA-512 (via NaCl)
- **KDF**: HKDF-SHA512 or SHA-512 based derivation
- **Signatures**: Ed25519
- **Symmetric Encryption**: XSalsa20-Poly1305 (NaCl secretbox)

## 4. Key Components

### 4.1 Identity Keys
- Each party has a long-term Ed25519 signing keypair `(IK_pub, IK_priv)`
- Exchanged out-of-band (QR code, in-person)

### 4.2 Epoch Parameters
Generated per epoch (e.g., monthly):
```
s1, s2 = random scalars (32 bytes each)
A = s1·G  (public)
B = s2·G  (public)
```

- `s1`: Retained throughout epoch (semi-static)
- `s2`: **DELETED** at epoch end (provides forward secrecy)
- `(A, B)`: Public parameters, distributed with identity keys

### 4.3 PRP Capability (V_i)
For each index `i`:
```
t_i = H_to_scalar(domain || i || A || B)
V_i = A + t_i·B = s1·G + t_i·s2·G
```

This creates a pseudorandom permutation where:
- Anyone can compute `V_i` given `(A, B, i)`
- Each `V_i` appears random without knowing `s1` or `s2`
- Receiver with `(s1, s2)` can compute the private key for any `V_i`

## 5. Protocol Flow

### 5.1 Setup Phase (Out-of-Band)

Alice and Bob exchange via QR code:
```
{
  identity_key: Ed25519_public_key,
  epoch_params: {
    A: point_bytes,
    B: point_bytes,
    valid_from: timestamp,
    valid_until: timestamp
  }
}
```

### 5.2 0-RTT Message (Alice → Bob)

Alice sends:
```
{
  ephemeral: E = e·G,
  cap_point: V_i,
  ciphertext: Enc(key=KDF(DH(e,V_i)), data),
  signature: Sign(IK_alice, E || V_i || ciphertext || i),
  index: i
}
```

**Sender steps:**
1. Choose index `i` (random, timestamp-based, or counter)
2. Generate ephemeral keypair `(e, E)`
3. Compute `V_i = A + H_to_scalar(domain || i || A || B)·B`
4. Compute shared secret: `ss = DH(e, V_i)`
5. Derive key: `k = KDF(ss || E || V_i)`
6. Encrypt message: `ciphertext = Enc(k, plaintext)`
7. Sign everything with identity key

### 5.3 Message Reception (Bob)

**Receiver steps:**
1. Verify signature using Alice's `IK_pub`
2. Recompute `V_i` using received index `i`
3. Verify `V_i` matches received value
4. Compute private scalar: `v_i = s1 + t_i·s2`
5. Compute shared secret: `ss = DH(v_i, E)`
6. Derive key: `k = KDF(ss || E || V_i)`
7. Decrypt message
8. Initialize Double Ratchet with root key from `ss`

## 6. Security Properties

### 6.1 Forward Secrecy
- After epoch end and `s2` erasure:
  - Adversary with `IK_alice`, `IK_bob`, `s1` cannot decrypt
  - Would require either `s2` (erased) or `e` (ephemeral)
  - Breaking requires solving discrete log

### 6.2 Authentication
- Signature prevents message forgery
- Separate from encryption (clean security model)

### 6.3 Replay Protection
- Within epoch: Application-level handling required
- Across epochs: Old `V_i` values become invalid

## 7. Implementation Requirements

### 7.1 Dependencies
```json
{
  "dependencies": {
    "tweetnacl": "^1.0.3",
    "@noble/ed25519": "^2.0.0"
  }
}
```

### 7.2 Core Functions

```typescript
interface EpochParams {
  A: Uint8Array;      // 32 bytes, public
  B: Uint8Array;      // 32 bytes, public
  s1: Uint8Array;     // 32 bytes, secret (semi-static)
  s2: Uint8Array;     // 32 bytes, secret (erased at epoch end)
  validFrom: number;  // Unix timestamp
  validUntil: number; // Unix timestamp
}

interface InitialMessage {
  ephemeralPublic: Uint8Array;  // 32 bytes
  V_i: Uint8Array;              // 32 bytes
  encryptedData: Uint8Array;    // Variable length
  signature: Uint8Array;        // 64 bytes
  index: number;                // 32-bit or 64-bit integer
}

// Key generation
function generateEpochParams(): EpochParams;

// PRP-cap computation
function computePRPCap(
  A: Uint8Array,
  B: Uint8Array,
  index: number,
  domain?: string
): Uint8Array;

// Message creation (sender)
function createInitialMessage(
  recipientEpochA: Uint8Array,
  recipientEpochB: Uint8Array,
  senderIdentityKey: Uint8Array,
  senderSigningKey: Uint8Array,
  messageData: Uint8Array,
  index?: number
): InitialMessage;

// Message reception (receiver)
function receiveInitialMessage(
  message: InitialMessage,
  epochS1: Uint8Array,
  epochS2: Uint8Array,
  epochA: Uint8Array,
  epochB: Uint8Array,
  senderVerifyKey: Uint8Array
): Uint8Array | null;
```

### 7.3 Critical Security Requirements

1. **Secure Erasure**: `s2` MUST be cryptographically erased at epoch end
2. **Domain Separation**: Hash inputs MUST include protocol/version prefix
3. **Index Binding**: Index MUST be included in signature
4. **Signature First**: Verify signature BEFORE any decryption attempts

## 8. Integration with Double Ratchet

After successful 0-RTT exchange:
```typescript
// Derive root key for Double Ratchet
const rootKey = KDF(sharedSecret, "MyProtocol.v1.RatchetInit");

// Initialize Double Ratchet state
const ratchetState = {
  rootKey: rootKey,
  sendingChainKey: KDF(rootKey, "sending"),
  receivingChainKey: KDF(rootKey, "receiving"),
  // ... continue with standard Double Ratchet
};
```

## 9. Epoch Rotation

### 9.1 Manual Rotation Triggers
- Suspected key compromise
- Device changes  
- Pre-planned security events
- Regular schedule (e.g., monthly)

### 9.2 In-Band Announcement
```typescript
interface EpochRotation {
  newEpoch: {
    A: Uint8Array;
    B: Uint8Array;
    validFrom: number;
  };
  oldEpochId: Uint8Array;  // Hash of old A||B
  signature: Uint8Array;    // Sign(IK, newA || newB || validFrom || oldEpochId)
}
```

Send via existing Double Ratchet sessions before `s2_old` erasure.

## 10. Security Considerations

### 10.1 Index Selection
- **Random**: Best for privacy, no patterns
- **Counter**: Enables replay detection
- **Timestamp**: Natural expiration, rough ordering

### 10.2 Epoch Duration Trade-offs
- **Shorter** (days): Better forward secrecy, more rotations
- **Longer** (months): Fewer out-of-band updates, larger exposure window

### 10.3 Implementation Pitfalls
- Test secure erasure on target platforms
- Avoid side channels in scalar operations  
- Validate all points are on curve
- Never reuse indices within an epoch

## 11. Test Vectors

```typescript
// Example test vector (simplified)
{
  epoch: {
    s1: "0x1234...",  // 32 bytes hex
    s2: "0x5678...",  // 32 bytes hex
    A: "0xabcd...",   // 32 bytes hex
    B: "0xef01...",   // 32 bytes hex
  },
  index: 42,
  V_42: "0x2345...",  // Expected V_i output
  
  message: {
    ephemeral_secret: "0x3456...",
    ephemeral_public: "0x7890...",
    shared_secret: "0xbcde...",
    plaintext: "Hello, 0-RTT!",
    ciphertext: "0xf012..."
  }
}
```

## 12. References

- [Signal Double Ratchet](https://signal.org/docs/specifications/doubleratchet/)
- [X3DH Key Agreement](https://signal.org/docs/specifications/x3dh/)
- [Ed25519 and X25519](https://cr.yp.to/ecdh.html)
- NaCl/TweetNaCl documentation

This specification provides a complete foundation for implementing the PRP-cap 0-RTT key exchange. The protocol achieves forward-secure 0-RTT without servers, making it suitable for high-security peer-to-peer applications.
