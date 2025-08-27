# PRP-Cap Protocol: Forward-Secure 0-RTT Key Exchange

## Executive Summary

PRP-Cap is a novel key exchange protocol that achieves true forward-secure zero round-trip time (0-RTT) message delivery in fully asynchronous, serverless environments. By combining pseudorandom permutation capabilities with epoch-based key erasure, it enables immediate encrypted communication while guaranteeing that past messages remain secure even after complete key compromise.

### Key Advantages
- **True 0-RTT**: Send encrypted messages immediately without any prior round trips
- **Forward Secrecy**: Past messages remain secure even if all long-term keys are compromised
- **Serverless**: No infrastructure required - works in pure peer-to-peer mode
- **Unlimited Scale**: No pre-key exhaustion or storage requirements
- **Opportunistic Security**: Automatically upgrades to stronger "double ladder" when simultaneous initiation occurs

---

# Technical Specification

## 1. Cryptographic Foundation

### 1.1 Primitives
- **Curve**: Ed25519 for point arithmetic, X25519 for Diffie-Hellman
- **Hash**: SHA-512
- **KDF**: HKDF-SHA512
- **Signatures**: Ed25519
- **AEAD**: XSalsa20-Poly1305

### 1.2 Core Innovation: PRP Capabilities

Instead of storing individual pre-keys, recipients publish epoch parameters that enable senders to derive unlimited ephemeral keys:

```
For epoch parameters (A, B) where:
  A = s1·G  (s1 retained during epoch)
  B = s2·G  (s2 deleted at epoch end)

Any sender can compute for any index i:
  t_i = H_to_scalar("PRP-CAP" || i || A || B)
  V_i = A + t_i·B

The recipient can derive the private key:
  v_i = s1 + t_i·s2
```

This construction ensures:
- Each `V_i` appears uniformly random
- Only the recipient can compute `v_i` (requires `s1` and `s2`)
- After `s2` deletion, even the recipient cannot recover `v_i`

## 2. Protocol Architecture

### 2.1 Key Hierarchy

```
Identity Keys (Long-term)
    ├── Signing Key (Ed25519)
    └── Identity Public Key
    
Epoch Keys (Per time period, e.g., monthly)
    ├── s1 (semi-static, retained during epoch)
    ├── s2 (deleted at epoch end - provides forward secrecy)
    ├── A = s1·G (public)
    └── B = s2·G (public)
    
Session Keys (Per conversation)
    ├── Single/Double Ladder Shared Secret(s)
    └── Double Ratchet State
```

### 2.2 Trust Establishment

Initial trust is established out-of-band via QR code exchange containing:

```json
{
  "identity_key": "ed25519_public_key_base64",
  "verification_key": "ed25519_verify_key_base64",
  "epoch": {
    "A": "point_base64",
    "B": "point_base64",
    "valid_from": 1234567890,
    "valid_until": 1237159890,
    "epoch_id": "hash_of_A_B"
  }
}
```

## 3. Message Exchange Protocols

### 3.1 Single Ladder (Standard 0-RTT)

When one party initiates communication:

```
Initial Message Structure:
{
  ephemeral: E = e·G,
  capability: V_i,
  ciphertext: AEAD(key=KDF(DH(e,V_i)), plaintext),
  signature: Sign(SK, E || V_i || ciphertext || i),
  index: i,
  message_id: random_bytes(16)
}
```

**Sender Protocol:**
1. Generate ephemeral keypair `(e, E)`
2. Select index `i` (random or timestamp-based)
3. Compute `V_i = A + H_to_scalar(domain || i || A || B)·B`
4. Derive shared secret: `SS = DH(e, V_i)`
5. Encrypt: `CT = AEAD(KDF(SS), plaintext)`
6. Sign entire message

**Receiver Protocol:**
1. Verify signature
2. Recompute and verify `V_i`
3. Compute private key: `v_i = s1 + t_i·s2`
4. Derive shared secret: `SS = DH(v_i, E)`
5. Decrypt message
6. Initialize Double Ratchet with `RootKey = KDF(SS, "SingleLadder")`

### 3.2 Double Ladder (Simultaneous Initiation)

When both parties initiate simultaneously, the protocol automatically upgrades to a stronger double ladder configuration:

```
Simultaneous Detection:
- Messages cross in transit
- Both parties receive an initial message while having sent one
- Detection window: ~30 seconds
```

**Merge Protocol:**
1. Both parties compute two shared secrets:
   - `Ladder1 = DH(e_alice, V_j_bob)`
   - `Ladder2 = DH(e_bob, V_i_alice)`

2. Deterministic merge:
   ```
   sorted = sort([Ladder1, Ladder2], [E_alice, E_bob])
   RootKey = KDF(sorted[0] || sorted[1], "DoubleLadder")
   ```

3. Initialize Double Ratchet with merged `RootKey`

### 3.3 State Machine

```
States:
┌──────┐ initiate  ┌───────────┐ timeout  ┌────────────────┐
│ IDLE ├──────────>│ INITIATED ├─────────>│ SINGLE_LADDER  │───┐
└──┬───┘           └─────┬─────┘          └────────────────┘   │
   │                     │ receive_init                        │
   │ receive_init        v                                     │ ratchet
   │               ┌────────────────┐                          │
   └──────────────>│ DOUBLE_LADDER  │                          │
                   └────────────────┘                          │
                           │                                   │
                           └───────────────────────────────────┘
                                           │
                                           v
                                   ┌──────────────┐
                                   │  RATCHETING  │
                                   └──────────────┘
```

## 4. Security Analysis

### 4.1 Forward Secrecy

The protocol achieves forward secrecy through two mechanisms:

1. **Ephemeral keys**: Sender's `e` is never stored
2. **Epoch erasure**: Deleting `s2` makes past `V_i` private keys unrecoverable

Even with complete compromise of:
- All identity keys
- Current epoch key `s1`
- All message transcripts

An adversary cannot decrypt past messages without either:
- The deleted `s2` value, or
- Solving the discrete logarithm problem

### 4.2 Security Properties

| Property | Single Ladder | Double Ladder |
|----------|--------------|---------------|
| Forward Secrecy | ✓ (via s2 deletion) | ✓✓ (requires both s2 values) |
| 0-RTT | ✓ | ✓ |
| Authentication | ✓ (signatures) | ✓ (signatures) |
| Post-Compromise Security | ✓ (via Double Ratchet) | ✓ (via Double Ratchet) |
| Replay Protection | Application-level | Application-level |
| Key Exhaustion Resistance | ✓ (unlimited indices) | ✓ (unlimited indices) |

### 4.3 Threat Model

**Assumptions:**
- Discrete logarithm problem is hard
- Hash functions are collision-resistant
- Signatures are unforgeable
- Initial key exchange (QR code) is authentic

**Protected Against:**
- Future key compromise
- Server compromise (no servers)
- Network adversaries
- Replay attacks (with app-level deduplication)

**Not Protected Against:**
- Active adversary during QR exchange
- Compromise of both `s1` and `s2` during active epoch
- Side-channel attacks on implementations

## 5. Implementation Guidelines

### 5.1 Critical Requirements

1. **Secure Erasure**: `s2` must be cryptographically erased
   ```typescript
   // Overwrite memory multiple times
   crypto.randomFillSync(s2);
   crypto.randomFillSync(s2);
   s2.fill(0);
   ```

2. **Domain Separation**: All hash inputs must include context
   ```typescript
   const domain = "PRP-CAP-v1";
   const input = concat(domain, index, A, B);
   ```

3. **Index Management**: Prevent replay within epoch
   ```typescript
   const usedIndices = new Set<string>();
   if (usedIndices.has(indexKey)) throw new Error("Replay");
   usedIndices.add(indexKey);
   ```

### 5.2 Recommended Parameters

- **Epoch Duration**: 30 days (balance between forward secrecy and usability)
- **Index Space**: 64-bit unsigned integers
- **Detection Window**: 30 seconds for simultaneous initiation
- **Message ID**: 128-bit random values

### 5.3 Library Requirements

```typescript
// Minimal implementation requires:
import * as nacl from 'tweetnacl';        // For X25519, signatures
import * as ed from '@noble/ed25519';     // For point arithmetic
import { hkdf } from '@noble/hashes/hkdf'; // For key derivation
```

## 6. Protocol Extensions

### 6.1 Multi-Device Support

Each device maintains separate epoch keys but shares identity keys:
```
User Alice:
  ├── Identity Key (shared)
  ├── Device 1: (A1, B1, s1_1, s2_1)
  ├── Device 2: (A2, B2, s1_2, s2_2)
  └── Device 3: (A3, B3, s1_3, s2_3)
```

### 6.2 Epoch Rotation

In-band epoch rotation for established sessions:
```typescript
interface EpochRotation {
  newEpoch: { A: Uint8Array, B: Uint8Array },
  validFrom: number,
  signature: Uint8Array  // Sign(IK, newA || newB || validFrom || oldEpochId)
}
```

### 6.3 Group Messaging

Extend to groups using:
- Sender keys for efficient fanout
- Per-group epoch parameters
- Tree-based ratcheting for large groups

## 7. Comparison with Existing Protocols

| Feature | PRP-Cap | Signal X3DH | TLS 1.3 0-RTT | WireGuard |
|---------|---------|-------------|---------------|-----------|
| True 0-RTT | ✓ | ✗ | ✓ | ✗ |
| Forward Secrecy for 0-RTT | ✓ | N/A | ✗ | N/A |
| Serverless | ✓ | ✗ | ✗ | ✓ |
| No Pre-key Exhaustion | ✓ | ✗ | ✓ | ✓ |
| Post-Compromise Security | ✓ | ✓ | ✗ | ✗ |
| Automatic Security Upgrade | ✓ | ✗ | ✗ | ✗ |

## 8. Reference Implementation

A complete implementation should provide:

```typescript
class PRPCapProtocol {
  // Core operations
  generateEpochParams(): EpochParams
  computePRPCap(A: Uint8Array, B: Uint8Array, index: number): Uint8Array
  
  // Message operations
  createInitialMessage(params: InitParams): InitialMessage
  processInitialMessage(msg: InitialMessage): Session
  
  // Session management
  detectSimultaneous(msg: InitialMessage): boolean
  mergeLadders(ladder1: Uint8Array, ladder2: Uint8Array): Uint8Array
  upgradeToDoubleRatchet(session: Session): DoubleRatchetSession
}
```

## Conclusion

PRP-Cap provides a cryptographically robust solution for forward-secure 0-RTT key exchange in serverless environments. By combining pseudorandom permutation capabilities with epoch-based key erasure and opportunistic security upgrades, it achieves security properties previously thought incompatible in fully asynchronous systems. The protocol is particularly suited for high-security messaging applications where infrastructure independence and forward secrecy are paramount.
