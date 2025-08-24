# Ladder Protocol - Simplified Implementation
**Lightweight Asynchronous Deterministic Double-Ratchet**

## Executive Summary

Ladder achieves forward secrecy from the first message by bundling an ephemeral public key with the identity public key during initial key exchange. This eliminates the need for a separate seed exchange step while maintaining all security properties.

## 1. Simplified Key Exchange

### 1.1 Key Bundle Format

Instead of sharing just the identity public key, users share a concatenated bundle:

```
KeyBundle = IdentityPublicKey || EphemeralPublicKey
           (32 bytes)           (32 bytes)
           Total: 64 bytes
```

No delimiter needed since both keys are fixed 32-byte X25519 keys.

### 1.2 UI Changes

- **Share button**: "Share Key (Public+Ephemeral)"
- **Display**: Show both components or combined format
- **Import**: Parse 64-byte bundle into two keys
- **Backward compatibility**: Detect 32 vs 64 byte format

## 2. Protocol Flow

### 2.1 Alice Shares Her Key Bundle
```
Alice_Bundle = IK_A.public || EK_A.public
```

### 2.2 Bob Shares His Key Bundle
```
Bob_Bundle = IK_B.public || EK_B.public
```

### 2.3 First Message (Alice → Bob)

Alice computes:
```
DH1 = X25519(IK_A.secret, IK_B.public)    // Identity DH
DH2 = X25519(IK_A.secret, EK_B.public)    // Cross DH
DH3 = X25519(EK_A.secret, IK_B.public)    // Cross DH
DH4 = X25519(EK_A.secret, EK_B.public)    // Ephemeral DH

SharedSecret = KDF(DH1 || DH2 || DH3 || DH4)
```

Bob computes the same using his secret keys.

### 2.4 Subsequent Messages

After the first exchange, the Double Ratchet takes over with its own ephemeral key rotation.

## 3. Implementation Plan

### Phase 1: Update Key Encoding (Day 1)

#### 3.1 Encoding Functions
**File**: `src/utils/encoding.ts`
```typescript
// Detect key format (32 bytes = legacy, 64 bytes = with ephemeral)
export function isExtendedKeyFormat(key: string): boolean {
  const bytes = base32CrockfordToUint8Array(key);
  return bytes.length === 64;
}

// Split extended key into components
export function splitExtendedKey(extendedKey: Uint8Array): {
  identityKey: Uint8Array;
  ephemeralKey: Uint8Array;
} {
  return {
    identityKey: extendedKey.slice(0, 32),
    ephemeralKey: extendedKey.slice(32, 64)
  };
}

// Combine keys into extended format
export function combineKeys(identityKey: Uint8Array, ephemeralKey: Uint8Array): Uint8Array {
  const combined = new Uint8Array(64);
  combined.set(identityKey, 0);
  combined.set(ephemeralKey, 32);
  return combined;
}
```

### Phase 2: Update Key Management (Day 1-2)

#### 3.2 Key Generation
**File**: `src/hooks/useKeyManagement.ts`
```typescript
interface ExtendedKeyPair {
  identity: KeyPair;
  ephemeral: KeyPair;
}

// Generate both keys on initialization
const generateExtendedKeyPair = (): ExtendedKeyPair => {
  return {
    identity: nacl.box.keyPair(),
    ephemeral: nacl.box.keyPair()
  };
};

// Store both in URL fragment
const saveExtendedKeys = (extended: ExtendedKeyPair, masterKey: string) => {
  const data = {
    identitySecret: extended.identity.secretKey,
    ephemeralSecret: extended.ephemeral.secretKey,
    // ... other data
  };
  // Encrypt and save to URL
};
```

### Phase 3: Update Ratchet Initialization (Day 2)

#### 3.3 Enhanced Ratchet Init
**File**: `src/utils/ratchet.ts`
```typescript
export function initializeRatchetWithEphemeral(
  myIdentity: KeyPair,
  myEphemeral: KeyPair,
  theirIdentityPublic: Uint8Array,
  theirEphemeralPublic: Uint8Array
): RatchetState {
  // Compute 4 DH operations
  const dh1 = dh(myIdentity.secretKey, theirIdentityPublic);
  const dh2 = dh(myIdentity.secretKey, theirEphemeralPublic);
  const dh3 = dh(myEphemeral.secretKey, theirIdentityPublic);
  const dh4 = dh(myEphemeral.secretKey, theirEphemeralPublic);
  
  // Combine and derive initial keys
  const combined = concat(dh1, dh2, dh3, dh4);
  const hashedSecret = nacl.hash(combined);
  const rootKey = hashedSecret.slice(0, 32);
  const chainKey = hashedSecret.slice(32, 64);
  
  // Clear sensitive data
  dh1.fill(0);
  dh2.fill(0);
  dh3.fill(0);
  dh4.fill(0);
  combined.fill(0);
  
  // Return initialized state (reuse existing structure)
  return {
    // ... standard ratchet state with derived keys
  };
}
```

### Phase 4: Update UI Components (Day 2-3)

#### 3.4 Key Display Component
**File**: `src/components/KeysDisplay.tsx`
```typescript
// Update to show extended format
const KeysDisplay = ({ extendedKeypair, userId }) => {
  const publicKeyBundle = combineKeys(
    extendedKeypair.identity.publicKey,
    extendedKeypair.ephemeral.publicKey
  );
  
  const displayValue = displayFormat === 'base32' 
    ? uint8ArrayToBase32Crockford(publicKeyBundle)
    : uint8ArrayToWords(publicKeyBundle); // 48 words instead of 24
    
  return (
    <div>
      <h3>Your Public Key (Identity + Ephemeral)</h3>
      <div className="key-display">
        {displayValue}
      </div>
      <button onClick={copyToClipboard}>
        Copy Key Bundle
      </button>
    </div>
  );
};
```

#### 3.5 Key Import
**File**: `src/components/RecipientKeyInput.tsx`
```typescript
const handleKeyImport = (input: string) => {
  try {
    const keyBytes = parseKeyInput(input); // Base32 or BIP39
    
    if (keyBytes.length === 32) {
      // Legacy format - identity only
      setRecipientIdentityKey(keyBytes);
      setRecipientEphemeralKey(null);
      showWarning("Legacy key format - limited forward secrecy");
    } else if (keyBytes.length === 64) {
      // Extended format
      const { identityKey, ephemeralKey } = splitExtendedKey(keyBytes);
      setRecipientIdentityKey(identityKey);
      setRecipientEphemeralKey(ephemeralKey);
    } else {
      throw new Error("Invalid key length");
    }
  } catch (error) {
    showError("Invalid key format");
  }
};
```

### Phase 5: Update Crypto Hook (Day 3)

#### 3.6 Enhanced Encryption
**File**: `src/hooks/useCrypto.ts`
```typescript
const handleEncrypt = async () => {
  // Check if we have ephemeral keys for both parties
  const hasEphemeralKeys = myEphemeral && recipientEphemeralKey;
  
  if (hasEphemeralKeys && !ratchetInitialized) {
    // Initialize with enhanced forward secrecy
    const ratchetState = initializeRatchetWithEphemeral(
      myIdentity,
      myEphemeral,
      recipientIdentityKey,
      recipientEphemeralKey
    );
    setRatchetState(ratchetState);
  } else if (!hasEphemeralKeys) {
    // Fall back to legacy initialization
    const ratchetState = initializeRatchet(
      myIdentity,
      recipientIdentityKey
    );
    setRatchetState(ratchetState);
  }
  
  // Continue with ratchet encryption...
};
```

## 4. Testing Strategy

### 4.1 Unit Tests
```typescript
describe('Extended Key Format', () => {
  test('combines and splits keys correctly');
  test('maintains backward compatibility with 32-byte keys');
  test('generates different ephemeral keys each time');
});

describe('Enhanced Ratchet', () => {
  test('4 DH operations produce correct shared secret');
  test('provides different initial keys than legacy');
  test('maintains forward secrecy from first message');
});
```

### 4.2 Integration Tests
```typescript
describe('End-to-End with Extended Keys', () => {
  test('Alice and Bob with extended keys');
  test('Alice (extended) to Bob (legacy)');
  test('Message flow with forward secrecy');
});
```

## 5. Migration Path

### 5.1 Detection Logic
```typescript
function detectKeyFormat(key: Uint8Array): 'legacy' | 'extended' {
  return key.length === 32 ? 'legacy' : 'extended';
}
```

### 5.2 Compatibility Matrix

| Alice | Bob | Result |
|-------|-----|--------|
| Extended | Extended | Full forward secrecy |
| Extended | Legacy | Partial forward secrecy |
| Legacy | Extended | Partial forward secrecy |
| Legacy | Legacy | No initial forward secrecy |

### 5.3 User Prompts
- When importing legacy key: "This contact uses an older key format. Consider asking them to regenerate their keys for better security."
- When both have extended: "✓ Full forward secrecy enabled"

## 6. Security Properties

### 6.1 Achieved
- ✅ **Forward Secrecy**: From the first message (with extended keys)
- ✅ **No Additional Round Trips**: Keys shared once
- ✅ **No Server Required**: Fully peer-to-peer
- ✅ **Backward Compatible**: Works with legacy keys

### 6.2 Trade-offs
- Ephemeral key can't be rotated without resharing
- No replay protection beyond nonces (could add counters later)
- Multi-device requires sharing same ephemeral

## 7. Future Enhancements

### 7.1 Phase 2: Deterministic Ladder
Once basic ephemeral keys work, add deterministic OPK derivation:
- Use shared ephemeral as seed
- Derive new OPKs with HKDF and counters
- Add replay protection with indices

### 7.2 Phase 3: Multi-Device
- Device-specific ephemeral keys
- Key bundle includes device ID
- Routing based on device

## 8. Implementation Checklist

### Day 1
- [ ] Update encoding functions for 64-byte keys
- [ ] Modify key generation to create ephemeral pairs
- [ ] Update key storage structure

### Day 2
- [ ] Implement `initializeRatchetWithEphemeral`
- [ ] Update key display components
- [ ] Modify key import/export

### Day 3
- [ ] Update encryption/decryption flow
- [ ] Add compatibility detection
- [ ] Implement fallback logic

### Day 4
- [ ] Write comprehensive tests
- [ ] Update documentation
- [ ] Test backward compatibility

### Day 5
- [ ] UI polish and error messages
- [ ] Performance testing
- [ ] Security review

## 9. Code Examples

### 9.1 Complete Key Bundle Generation
```typescript
function generateKeyBundle(): string {
  const identity = nacl.box.keyPair();
  const ephemeral = nacl.box.keyPair();
  
  const bundle = new Uint8Array(64);
  bundle.set(identity.publicKey, 0);
  bundle.set(ephemeral.publicKey, 32);
  
  return uint8ArrayToBase32Crockford(bundle);
}
```

### 9.2 Complete Import Handler
```typescript
function importKeyBundle(input: string): ExtendedPublicKey {
  const bytes = base32CrockfordToUint8Array(input);
  
  if (bytes.length === 64) {
    return {
      identity: bytes.slice(0, 32),
      ephemeral: bytes.slice(32, 64),
      format: 'extended'
    };
  } else if (bytes.length === 32) {
    return {
      identity: bytes,
      ephemeral: null,
      format: 'legacy'
    };
  }
  
  throw new Error('Invalid key bundle size');
}
```

## 10. Summary

This simplified Ladder implementation:
1. Bundles ephemeral key with identity key (64 bytes total)
2. Shares both in one step - no separate seed exchange
3. Provides forward secrecy from first message
4. Maintains full backward compatibility
5. Requires minimal changes to existing codebase

The implementation can be completed in ~5 days and provides immediate security benefits without protocol complexity.
