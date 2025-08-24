# Ladder Protocol Implementation Plan

**Lightweight Asynchronous Deterministic Double-Ratchet**

## Executive Summary

Ladder is a serverless protocol for establishing end-to-end encrypted sessions with forward secrecy from the first message. It uses a deterministic one-time prekey (OPK) ladder to enable asynchronous session initialization without requiring a server or round-trip communication.

## 1. Protocol Overview

### 1.1 Core Concepts

- **Deterministic OPK Ladder**: Instead of random prekeys stored on a server, Bob shares a secret seed with Alice once. Alice can then deterministically generate one-time prekeys using HKDF with an incrementing index.
- **One-Way Start**: Alice can begin sending encrypted messages immediately without waiting for Bob's response.
- **Replay Resistance**: Monotonic counters prevent replay attacks.
- **Forward Secrecy**: Each session uses a unique OPK, providing immediate forward secrecy.

### 1.2 Advantages Over Current Implementation

| Feature | Current (Simple DH) | Ladder Protocol |
|---------|-------------------|-----------------|
| Forward Secrecy | After 1st exchange | From message 1 |
| Async Messaging | No | Yes |
| Server Required | No | No |
| Setup Overhead | None | One-time seed exchange |
| Replay Protection | Nonce only | Index + nonce |

## 2. Cryptographic Primitives

- **Curve**: X25519 (32-byte keys) for Diffie-Hellman
- **AEAD**: XSalsa20-Poly1305 (TweetNaCl `secretbox`), 24-byte nonce
- **KDF**: HKDF-SHA256
- **Hash**: SHA-256
- **Encoding**: Base32 Crockford for keys, little-endian for u32

## 3. Protocol Specification

### 3.1 Seed Exchange (One-Time Setup)

When establishing a relationship, Bob generates and shares with Alice:
```
seed_BA: 32 random bytes
LadderSig_B = Sign(IK_B, 
    "ladder-v1" || FPR(IK_A) || SHA256(seed_BA) || "hkdf-sha256/x25519"
)
```

### 3.2 OPK Derivation

Alice derives OPK for index `i`:
```
PRK = HKDF-Extract(salt="ladder-seed-v1", IKM=seed_BA)
info = "ladder-opk" || FPR(IK_A) || LE32(i)
SK_i = HKDF-Expand(PRK, info, L=32)
PK_i = X25519(SK_i, BasePoint)
```

### 3.3 Session Initialization

Alice computes:
```
DH1 = X25519(IK_A.secret, IK_B.public)
DH2 = X25519(EK_A.secret, IK_B.public)
DH3 = X25519(EK_A.secret, PK_i)

SK = HKDF-Extract(salt="ladder-v1", IKM=DH1||DH2||DH3)
RK0, CKs0 = HKDF-Expand(SK, info="dr-init-v1"||..., L=64)
```

### 3.4 Message Format

```typescript
interface PreKeyInit {
  version: 1;
  opk_index: number;      // i
  ik_a_pub: Uint8Array;   // 32 bytes
  ek_a_pub: Uint8Array;   // 32 bytes
  first_msgs: EncryptedMessage[];
}
```

## 4. Implementation Plan

### Phase 1: Cryptographic Foundation (Week 1)

#### 4.1 HKDF Implementation
**File**: `src/utils/hkdf.ts`
```typescript
export async function hkdfExtract(salt: Uint8Array, ikm: Uint8Array): Promise<Uint8Array>
export async function hkdfExpand(prk: Uint8Array, info: Uint8Array, length: number): Promise<Uint8Array>
```

#### 4.2 Ladder Core Functions
**File**: `src/utils/ladder.ts`
```typescript
export function deriveOPK(seed: Uint8Array, peerFpr: Uint8Array, index: number): KeyPair
export function generateLadderSeed(): { seed: Uint8Array, signature: Uint8Array }
export function verifyLadderSignature(seed: Uint8Array, signature: Uint8Array, peerPublicKey: Uint8Array): boolean
```

### Phase 2: Protocol Implementation (Week 1-2)

#### 4.3 Types
**File**: `src/types/ladder.ts`
```typescript
interface LadderSeed {
  seed: Uint8Array;
  signature: Uint8Array;
  peerPublicKey: Uint8Array;
  createdAt: number;
}

interface LadderState {
  seeds: Map<string, LadderSeed>;  // Keyed by peer FPR
  nextIndex: Map<string, number>;   // Alice's counter
  maxSpent: Map<string, number>;    // Bob's counter
}

interface PreKeyInit {
  version: number;
  opkIndex: number;
  aliceIdentityKey: Uint8Array;
  aliceEphemeralKey: Uint8Array;
  firstMessages: EncryptedPayload[];
}
```

#### 4.4 Ladder Protocol
**File**: `src/utils/ladderProtocol.ts`
```typescript
export function initiateLadderSession(
  myIdentity: KeyPair,
  theirIdentity: Uint8Array,
  ladderSeed: LadderSeed,
  messages: Uint8Array[]
): PreKeyInit

export function receiveLadderSession(
  myIdentity: KeyPair,
  ladderSeed: LadderSeed,
  preKeyInit: PreKeyInit
): { sharedSecret: Uint8Array; messages: Uint8Array[] }
```

### Phase 3: Integration (Week 2)

#### 4.5 Update Ratchet Initialization
**File**: `src/utils/ratchet.ts`
```typescript
export function initializeRatchetFromLadder(
  myIdentityKeyPair: KeyPair,
  theirIdentityPublicKey: Uint8Array,
  ladderSecret: Uint8Array,
  isInitiator: boolean
): RatchetState
```

#### 4.6 Key Management Updates
**File**: `src/hooks/useKeyManagement.ts`
- Add ladder seed storage in URL fragment
- Track indices in localStorage
- Add seed exchange flow

### Phase 4: UI Components (Week 2-3)

#### 4.7 Seed Exchange Component
**File**: `src/components/LadderSeedExchange.tsx`
- Generate and display seed + signature
- QR code generation for seed
- Import seed from QR/text
- Verify imported seeds

#### 4.8 Update Message Flow
**Files**: `src/hooks/useCrypto.ts`, `src/components/EncryptDecryptCard.tsx`
- Detect if ladder seed exists for recipient
- Use Ladder for first message if available
- Fall back to simple DH if no seed

### Phase 5: Testing (Week 3)

#### 4.9 Test Suite
**File**: `tests/ladder.test.ts`
```typescript
describe('Ladder Protocol', () => {
  describe('Deterministic OPK', () => {
    test('derives consistent keys')
    test('different indices produce different keys')
  })
  
  describe('Session Establishment', () => {
    test('Alice initiates session')
    test('Bob receives and decrypts')
    test('shared secrets match')
  })
  
  describe('Replay Protection', () => {
    test('rejects reused indices')
    test('accepts increasing indices')
  })
  
  describe('Integration', () => {
    test('seeds Double Ratchet correctly')
    test('falls back to simple DH without seed')
  })
})
```

## 5. Storage Schema

### 5.1 URL Fragment (Encrypted)
```json
{
  "privateKey": "...",
  "ladderSeeds": {
    "recipientId": {
      "seed": "base32...",
      "signature": "base32...",
      "createdAt": 1234567890
    }
  }
}
```

### 5.2 LocalStorage
```json
{
  "ladder_indices": {
    "recipientId": {
      "next": 5,      // Alice's next index to use
      "maxSpent": 3   // Bob's highest accepted
    }
  }
}
```

## 6. Security Considerations

### 6.1 Threat Model
- **Forward Secrecy**: Achieved through ephemeral keys and unique OPKs
- **Replay Attacks**: Prevented by monotonic index counter
- **Key Compromise**:
  - Seed compromise: Rotate to new seed, maintain old `maxSpent` temporarily
  - Identity compromise: Full reset required

### 6.2 Security Properties
- ✅ Asynchronous start (no round trips)
- ✅ Forward secrecy from first message
- ✅ Replay resistance
- ✅ Post-compromise security (from Double Ratchet)
- ✅ No server dependency

### 6.3 Limitations
- Requires one-time seed exchange per relationship
- Index synchronization issues in multi-device scenarios
- No perfect forward secrecy if seed is compromised before use

## 7. Migration Strategy

### 7.1 Backward Compatibility
1. Detect message format (Ladder vs simple DH)
2. Support both protocols during transition
3. Prompt users to upgrade relationships with seed exchange

### 7.2 Rollout Plan
1. **Phase 1**: Deploy with feature flag (opt-in)
2. **Phase 2**: Default for new conversations
3. **Phase 3**: Prompt existing users to add seeds
4. **Phase 4**: Deprecate simple DH (with legacy support)

## 8. Performance Metrics

### 8.1 Computational Cost
- OPK derivation: ~1ms (HKDF + X25519)
- Session init: ~3ms (3 DH operations + HKDF)
- Negligible compared to Double Ratchet operations

### 8.2 Storage Cost
- Per relationship: 32 bytes (seed) + 64 bytes (signature) + 8 bytes (indices)
- Total: ~104 bytes per contact

## 9. Implementation Checklist

- [ ] Core cryptographic primitives
  - [ ] HKDF implementation
  - [ ] X25519 scalar multiplication
  - [ ] SHA-256 hashing
  
- [ ] Ladder protocol
  - [ ] OPK derivation
  - [ ] Seed generation and signing
  - [ ] Session initialization
  - [ ] Message format encoding/decoding
  
- [ ] Integration
  - [ ] Ratchet initialization from Ladder
  - [ ] Key management updates
  - [ ] Storage layer updates
  
- [ ] UI Components
  - [ ] Seed exchange flow
  - [ ] QR code generation/scanning
  - [ ] Status indicators
  
- [ ] Testing
  - [ ] Unit tests for each component
  - [ ] Integration tests
  - [ ] Security property verification
  - [ ] Backward compatibility tests
  
- [ ] Documentation
  - [ ] User guide for seed exchange
  - [ ] Developer documentation
  - [ ] Security audit checklist

## 10. Future Enhancements

### 10.1 Multi-Device Support
- Index range allocation per device
- Sync mechanism for indices
- Device-specific seeds

### 10.2 Advanced Features
- Seed rotation scheduling
- Automatic fallback negotiation
- Session binding tokens
- Post-quantum preparedness

## Appendix A: Constants

```typescript
// Protocol version and identifiers
const LADDER_VERSION = 1;
const LADDER_SALT = "ladder-v1";
const SEED_SALT = "ladder-seed-v1";
const OPK_INFO = "ladder-opk";
const DR_INIT_INFO = "dr-init-v1";

// Limits
const MAX_BURST_MESSAGES = 8;
const MAX_INDEX_GAP = 100;
const SEED_ROTATION_DAYS = 90;
```

## Appendix B: Reference Implementation

```typescript
// Example OPK derivation (simplified)
async function deriveOPK(
  seed: Uint8Array,
  peerFpr: Uint8Array,
  index: number
): Promise<{ secretKey: Uint8Array; publicKey: Uint8Array }> {
  const prk = await hkdfExtract(
    new TextEncoder().encode(SEED_SALT),
    seed
  );
  
  const info = concat(
    new TextEncoder().encode(OPK_INFO),
    peerFpr,
    encodeLE32(index)
  );
  
  const secretKey = await hkdfExpand(prk, info, 32);
  const publicKey = nacl.scalarMult.base(clamp25519(secretKey));
  
  return { secretKey, publicKey };
}
```
