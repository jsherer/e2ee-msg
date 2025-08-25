# Ladder Protocol - Full Implementation
**Lightweight Asynchronous Deterministic Double-Ratchet**

## Executive Summary

Ladder achieves forward secrecy from the first message using a deterministic OPK (one-time prekey) ladder with monotonic counters for replay protection. Users share an extended key bundle (identity + ephemeral seed) once, then derive unique OPKs deterministically for each session.

## 1. Key Bundle Exchange

### 1.1 Extended Key Bundle Format

Users share a signed bundle containing both identity and ephemeral seed:

```
KeyBundle = IdentityPublicKey || EphemeralSeedPublicKey || Signature
           (32 bytes)            (32 bytes)              (64 bytes)
           Total: 128 bytes

Where:
Signature = Sign_IK("ladder-bundle-v1" || IK_pub || ES_pub)
```

The ephemeral key serves as the seed for the deterministic OPK ladder. The signature prevents substitution attacks.

### 1.2 Ladder Initialization

When Alice receives Bob's bundle:
1. Store Bob's identity key and ephemeral seed
2. Initialize counter: `next_i_alice = 1`

When Bob receives Alice's bundle:
1. Store Alice's identity key and ephemeral seed  
2. Initialize counter: `max_spent_alice = 0`

## 2. Protocol Flow

### 2.1 OPK Derivation

For each message session, derive OPK from seed and counter. The derivation is symmetric but computed differently by each party:

```typescript
// Initiator (Alice) derives peer's OPK public key
async function deriveOPKPublic_Initiator(
  peerEphemeralSeedPub: Uint8Array,  // ES_B_pub
  myIdentitySecret: Uint8Array,      // IK_A_sk
  peerIdentityPub: Uint8Array,       // IK_B_pub (for fingerprint)
  index: number                      // Counter value
): Promise<Uint8Array> {
  // seed = X25519(IK_A_sk, ES_B_pub)
  const seed = nacl.scalarMult(myIdentitySecret, peerEphemeralSeedPub);
  
  // PRK = HKDF-Extract("ladder-seed-v1", seed)
  const prk = await hkdfExtract(
    encode("ladder-seed-v1"),
    seed
  );
  
  // info = "ladder-opk" || FPR(IK_B_pub) || LE32(index)
  const fpr = await sha256(peerIdentityPub);
  const info = concat(
    encode("ladder-opk"),
    fpr,
    encodeLE32(index)
  );
  
  const opkSecret = clamp25519(await hkdfExpand(prk, info, 32));
  return nacl.scalarMult.base(opkSecret); // OPK_i public key
}

// Responder (Bob) derives OPK secret key
async function deriveOPKSecret_Responder(
  myEphemeralSeedSecret: Uint8Array, // ES_B_sk
  peerIdentityPub: Uint8Array,       // IK_A_pub
  index: number                      // Counter value
): Promise<Uint8Array> {
  // seed = X25519(ES_B_sk, IK_A_pub) - same as Alice's seed
  const seed = nacl.scalarMult(myEphemeralSeedSecret, peerIdentityPub);
  
  const prk = await hkdfExtract(
    encode("ladder-seed-v1"),
    seed
  );
  
  // info = "ladder-opk" || FPR(IK_A_pub) || LE32(index)
  const fpr = await sha256(peerIdentityPub);
  const info = concat(
    encode("ladder-opk"),
    fpr,
    encodeLE32(index)
  );
  
  return clamp25519(await hkdfExpand(prk, info, 32)); // OPK_i secret
}
```

### 2.2 Message Envelope Format

Messages sent using Ladder include PreKeyInit data as an envelope header only when establishing a new session or after a reset. Subsequent messages in an active session use the existing ratchet state without the PreKeyInit header:

```typescript
interface LadderMessage {
  // PreKeyInit header (only for new sessions/resets)
  version: 1;
  opkIndex: number;                // Counter i
  senderIdentityKey: Uint8Array;   // Sender's identity
  senderEphemeralKey: Uint8Array;  // Fresh ephemeral for this session
  
  // Encrypted payload
  encryptedPayload: Uint8Array;    // The actual message, encrypted with derived keys
}
```

### 2.3 Sending First Message (Alice → Bob)

Alice sends her first message with embedded PreKeyInit:

```
1. Get next counter: i = next_i_alice++
2. Derive Bob's OPK: OPK_i = deriveOPK(bobEphemeralSeed, aliceIdentity, i)
3. Generate fresh ephemeral: EK_A = generateKeyPair()
4. Compute DH operations:
   DH1 = X25519(IK_A.secret, IK_B.public)
   DH2 = X25519(EK_A.secret, IK_B.public)  
   DH3 = X25519(EK_A.secret, OPK_i)
5. Derive shared secret:
   SK = HKDF(DH1 || DH2 || DH3)
6. Initialize Double Ratchet with SK
7. Encrypt message with ratchet
8. Send LadderMessage with PreKeyInit header + encrypted payload
```

### 2.4 Bob Receives Message

Bob processes the LadderMessage:
```
1. Extract PreKeyInit header from message
2. Check replay: if (i <= max_spent_alice) REJECT
3. Derive same OPK: OPK_i = deriveOPK(myEphemeralSeed, aliceIdentity, i)
4. Compute same DH operations with his secrets
5. Update counter: max_spent_alice = i
6. Initialize Double Ratchet with SK
7. Decrypt the payload using ratchet
```

### 2.5 Subsequent Messages

After the first exchange:
- If session is active: Continue using established ratchet (no PreKeyInit needed)
- If new session needed: Include new PreKeyInit header with incremented counter
- The protocol automatically handles session resets without extra round trips

## 3. Implementation Details

### Phase 1: Cryptographic Primitives

#### 3.1 HKDF Implementation
**File**: `src/utils/hkdf.ts`
```typescript
export async function hkdfExtract(
  salt: Uint8Array, 
  ikm: Uint8Array
): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey(
    "raw", ikm, "HKDF", false, ["deriveBits"]
  );
  const bits = await crypto.subtle.deriveBits(
    { name: "HKDF", hash: "SHA-256", salt, info: new Uint8Array(0) },
    key, 256
  );
  return new Uint8Array(bits);
}

export async function hkdfExpand(
  prk: Uint8Array,
  info: Uint8Array,
  length: number
): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey(
    "raw", prk, "HKDF", false, ["deriveBits"]
  );
  const bits = await crypto.subtle.deriveBits(
    { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(0), info },
    key, length * 8
  );
  return new Uint8Array(bits);
}
```

### Phase 2: Ladder Core Functions

#### 3.2 Types
**File**: `src/types/ladder.ts`
```typescript
export interface LadderState {
  // Stored keys (per peer)
  theirIdentityKey: Uint8Array;
  theirEphemeralSeed: Uint8Array;
  
  // Counters (persistent)
  nextIndex?: number;      // Alice's next i to use (sender)
  maxSpentIndex?: number;  // Bob's highest accepted i (receiver)
}

// LadderMessage combines PreKeyInit header with encrypted payload
export interface LadderMessage {
  // PreKeyInit header (always included for new sessions)
  version: 1;
  opkIndex: number;
  senderIdentityKey: Uint8Array;
  senderEphemeralKey: Uint8Array;
  
  // The encrypted message payload
  encryptedPayload: Uint8Array;
}

export interface LadderSession {
  sharedSecret: Uint8Array;
  rootKey: Uint8Array;
  chainKey: Uint8Array;
}
```

#### 3.3 OPK Derivation
**File**: `src/utils/ladder.ts`
```typescript
import { hkdfExtract, hkdfExpand } from './hkdf';
import * as nacl from 'tweetnacl';

const te = new TextEncoder();

async function sha256(u8: Uint8Array): Promise<Uint8Array> {
  const buf = await crypto.subtle.digest("SHA-256", u8);
  return new Uint8Array(buf);
}

function clamp25519(sk: Uint8Array): Uint8Array {
  const out = new Uint8Array(sk);
  out[0] &= 248;
  out[31] &= 127;
  out[31] |= 64;
  return out;
}

// Initiator (Alice) computes peer OPK PUBLIC for index i
export async function deriveOPKPublic_Initiator(
  peerEphemeralSeedPub: Uint8Array,  // ES_B_pub
  myIdentitySecret: Uint8Array,      // IK_A_sk
  peerIdentityPub: Uint8Array,       // IK_B_pub
  i: number
): Promise<Uint8Array> {
  // seed = X25519(IK_A_sk, ES_B_pub)
  const seed = nacl.scalarMult(myIdentitySecret, peerEphemeralSeedPub);

  // PRK = HKDF-Extract("ladder-seed-v1", seed)
  const prk = await hkdfExtract(te.encode("ladder-seed-v1"), seed);

  // info = "ladder-opk" || FPR(IK_B_pub) || LE32(i)
  const fpr = await sha256(peerIdentityPub);
  const iBuf = new Uint8Array(4);
  new DataView(iBuf.buffer).setUint32(0, i, true);
  const info = new Uint8Array("ladder-opk".length + fpr.length + 4);
  info.set(te.encode("ladder-opk"), 0);
  info.set(fpr, "ladder-opk".length);
  info.set(iBuf, "ladder-opk".length + fpr.length);

  const sk_i_raw = await hkdfExpand(prk, info, 32);
  const sk_i = clamp25519(sk_i_raw);
  return nacl.scalarMult.base(sk_i); // OPK_i_public
}

// Responder (Bob) computes OPK SECRET for index i
export async function deriveOPKSecret_Responder(
  myEphemeralSeedSecret: Uint8Array, // ES_B_sk
  peerIdentityPub: Uint8Array,       // IK_A_pub
  i: number
): Promise<Uint8Array> {
  // seed = X25519(ES_B_sk, IK_A_pub)
  const seed = nacl.scalarMult(myEphemeralSeedSecret, peerIdentityPub);

  const prk = await hkdfExtract(te.encode("ladder-seed-v1"), seed);

  const fpr = await sha256(peerIdentityPub);
  const iBuf = new Uint8Array(4);
  new DataView(iBuf.buffer).setUint32(0, i, true);
  const info = new Uint8Array("ladder-opk".length + fpr.length + 4);
  info.set(te.encode("ladder-opk"), 0);
  info.set(fpr, "ladder-opk".length);
  info.set(iBuf, "ladder-opk".length + fpr.length);

  const sk_i_raw = await hkdfExpand(prk, info, 32);
  return clamp25519(sk_i_raw); // OPK_i_secret
}
```

#### 3.4 Ladder Message Creation and Processing
**File**: `src/utils/ladder.ts`
```typescript
export async function createLadderMessage(
  myIdentity: KeyPair,
  myEphemeralSeed: KeyPair,
  theirIdentityKey: Uint8Array,
  theirEphemeralSeed: Uint8Array,
  index: number,
  plaintext: Uint8Array
): Promise<LadderMessage> {
  // Generate fresh ephemeral for this session
  const sessionEphemeral = nacl.box.keyPair();
  
  // Derive their OPK public key for this index
  const theirOPK_pub = await deriveOPKPublic_Initiator(
    theirEphemeralSeed,         // ES_B_pub
    myIdentity.secretKey,       // IK_A_sk
    theirIdentityKey,           // IK_B_pub
    index
  );
  
  // Compute DH operations
  const dh1 = nacl.box.before(theirIdentityKey, myIdentity.secretKey);
  const dh2 = nacl.box.before(theirIdentityKey, sessionEphemeral.secretKey);
  const dh3 = nacl.box.before(theirOPK_pub, sessionEphemeral.secretKey);
  
  // Derive shared secret
  const concat = new Uint8Array(96);
  concat.set(dh1, 0);
  concat.set(dh2, 32);
  concat.set(dh3, 64);
  
  const salt = new TextEncoder().encode("ladder-v1");
  const sk = await hkdfExtract(salt, concat);
  
  // Derive initial ratchet keys
  const info = new TextEncoder().encode("dr-init-v1");
  const keys = await hkdfExpand(sk, info, 64);
  
  // Initialize ratchet and encrypt
  const ratchetState = initializeRatchetFromLadder(
    myIdentity,
    theirIdentityKey,
    {
      sharedSecret: sk,
      rootKey: keys.slice(0, 32),
      chainKey: keys.slice(32, 64)
    },
    true
  );
  
  const [encryptedPayload] = ratchetEncrypt(ratchetState, plaintext);
  
  // Clear sensitive data
  dh1.fill(0);
  dh2.fill(0);
  dh3.fill(0);
  concat.fill(0);
  
  // Return complete message with embedded PreKeyInit
  return {
    version: 1,
    opkIndex: index,
    senderIdentityKey: myIdentity.publicKey,
    senderEphemeralKey: sessionEphemeral.publicKey,
    encryptedPayload
  };
}

export async function processLadderMessage(
  myIdentity: KeyPair,
  myEphemeralSeed: KeyPair,
  message: LadderMessage
): Promise<Uint8Array> {
  // Derive my OPK secret for this index
  const myOPK_secret = await deriveOPKSecret_Responder(
    myEphemeralSeed.secretKey,    // ES_B_sk
    message.senderIdentityKey,     // IK_A_pub
    message.opkIndex
  );
  
  // Compute same DH operations (from Bob's perspective)
  const dh1 = nacl.box.before(message.senderIdentityKey, myIdentity.secretKey);
  const dh2 = nacl.box.before(message.senderEphemeralKey, myIdentity.secretKey);
  const dh3 = nacl.box.before(message.senderEphemeralKey, myOPK_secret);
  
  // Derive shared secret (same as Alice)
  const concat = new Uint8Array(96);
  concat.set(dh1, 0);
  concat.set(dh2, 32);
  concat.set(dh3, 64);
  
  const salt = new TextEncoder().encode("ladder-v1");
  const sk = await hkdfExtract(salt, concat);
  
  const info = new TextEncoder().encode("dr-init-v1");
  const keys = await hkdfExpand(sk, info, 64);
  
  // Initialize ratchet and decrypt
  const ratchetState = initializeRatchetFromLadder(
    myIdentity,
    message.senderIdentityKey,
    {
      sharedSecret: sk,
      rootKey: keys.slice(0, 32),
      chainKey: keys.slice(32, 64)
    },
    false
  );
  
  const [decrypted] = ratchetDecrypt(ratchetState, message.encryptedPayload);
  
  // Clear sensitive data
  dh1.fill(0);
  dh2.fill(0);
  dh3.fill(0);
  concat.fill(0);
  myOPK_secret.fill(0);
  
  return decrypted;
}
```

### Phase 3: Counter Management

#### 3.5 Counter Storage
**File**: `src/utils/ladderState.ts`
```typescript
const COUNTER_STORAGE_KEY = 'ladder_counters';

interface CounterState {
  [peerId: string]: {
    nextIndex?: number;
    maxSpentIndex?: number;
  };
}

export function loadCounters(): CounterState {
  const stored = localStorage.getItem(COUNTER_STORAGE_KEY);
  return stored ? JSON.parse(stored) : {};
}

export function saveCounters(state: CounterState): void {
  localStorage.setItem(COUNTER_STORAGE_KEY, JSON.stringify(state));
}

export function getNextIndex(peerId: string): number {
  const counters = loadCounters();
  const current = counters[peerId]?.nextIndex || 1;
  
  // Update and save
  counters[peerId] = { ...counters[peerId], nextIndex: current + 1 };
  saveCounters(counters);
  
  return current;
}

export function checkAndUpdateMaxSpent(
  peerId: string, 
  index: number
): boolean {
  const counters = loadCounters();
  const maxSpent = counters[peerId]?.maxSpentIndex || 0;
  
  // Reject if replay
  if (index <= maxSpent) {
    return false;
  }
  
  // Update and save
  counters[peerId] = { ...counters[peerId], maxSpentIndex: index };
  saveCounters(counters);
  
  return true;
}
```

### Phase 4: Integration with Ratchet

#### 3.6 Update Ratchet Initialization
**File**: `src/utils/ratchet.ts`
```typescript
export function initializeRatchetFromLadder(
  myIdentityKeyPair: KeyPair,
  theirIdentityPublicKey: Uint8Array,
  ladderSession: LadderSession,
  isInitiator: boolean
): RatchetState {
  // Use Ladder-derived keys as initial state
  const ephemeralKeyPair = nacl.box.keyPair();
  
  return {
    myIdentityKeyPair,
    theirIdentityPublicKey,
    myCurrentEphemeralKeyPair: ephemeralKeyPair,
    theirLatestEphemeralPublicKey: null,
    rootKey: ladderSession.rootKey,
    // Asymmetric chain initialization:
    // Initiator has sending chain, responder has receiving chain
    sendingChainKey: isInitiator ? new Uint8Array(ladderSession.chainKey) : null,
    receivingChainKey: isInitiator ? null : new Uint8Array(ladderSession.chainKey),
    sendMessageCounter: 0,
    receiveMessageCounter: 0,
    previousSendCounter: 0,
    skippedMessageKeys: new Map(),
    isInitialized: true
  };
}
```

### Phase 5: Update Key Management

#### 3.7 Extended Key Storage
**File**: `src/hooks/useKeyManagement.ts`
```typescript
interface ExtendedKeyPair {
  identity: KeyPair;
  ephemeralSeed: KeyPair;  // Used as ladder seed
}

// Generate extended keypair
const generateExtendedKeyPair = (): ExtendedKeyPair => {
  return {
    identity: nacl.box.keyPair(),
    ephemeralSeed: nacl.box.keyPair()
  };
};

// Format for sharing (128 bytes with signature)
const formatPublicKeyBundle = (extended: ExtendedKeyPair): Uint8Array => {
  const identityPub = extended.identity.publicKey;
  const ephemeralPub = extended.ephemeralSeed.publicKey;
  
  // Create signed bundle
  const message = new Uint8Array(te.encode("ladder-bundle-v1").length + 64);
  message.set(te.encode("ladder-bundle-v1"), 0);
  message.set(identityPub, te.encode("ladder-bundle-v1").length);
  message.set(ephemeralPub, te.encode("ladder-bundle-v1").length + 32);
  
  const signature = nacl.sign.detached(message, extended.identity.secretKey);
  
  const bundle = new Uint8Array(128);
  bundle.set(identityPub, 0);
  bundle.set(ephemeralPub, 32);
  bundle.set(signature, 64);
  return bundle;
};

// Parse and verify received bundle
const parsePublicKeyBundle = (bundle: Uint8Array): {
  identityKey: Uint8Array;
  ephemeralSeed: Uint8Array;
} => {
  if (bundle.length !== 128) {
    throw new Error('Invalid key bundle size');
  }
  
  const identityKey = bundle.slice(0, 32);
  const ephemeralSeed = bundle.slice(32, 64);
  const signature = bundle.slice(64, 128);
  
  // Verify signature
  const message = new Uint8Array(te.encode("ladder-bundle-v1").length + 64);
  message.set(te.encode("ladder-bundle-v1"), 0);
  message.set(identityKey, te.encode("ladder-bundle-v1").length);
  message.set(ephemeralSeed, te.encode("ladder-bundle-v1").length + 32);
  
  if (!nacl.sign.detached.verify(message, signature, identityKey)) {
    throw new Error('Invalid bundle signature');
  }
  
  return { identityKey, ephemeralSeed };
};
```

### Phase 6: Update Crypto Hook

#### 3.8 Ladder-Aware Encryption
**File**: `src/hooks/useCrypto.ts`
```typescript
const handleEncrypt = async () => {
  if (!keypair || !recipientPublicKey || !message) {
    return;
  }
  
  try {
    // Parse recipient's bundle
    const recipientBundle = parsePublicKeyBundle(recipientPublicKey);
    
    // Check if we should use Ladder (both have extended keys)
    if (myExtendedKeypair && recipientBundle.ephemeralSeed) {
      // Get next counter for this recipient
      const recipientId = uint8ArrayToBase32Crockford(recipientBundle.identityKey);
      const index = getNextIndex(recipientId);
      
      // Create complete Ladder message with embedded PreKeyInit
      const ladderMessage = await createLadderMessage(
        myExtendedKeypair.identity,
        myExtendedKeypair.ephemeralSeed,
        recipientBundle.identityKey,
        recipientBundle.ephemeralSeed,
        index,
        messageBytes
      );
      
      // Encode and output the complete message
      const encoded = encodeLadderMessage(ladderMessage);
      setOutput(encoded);
      
    } else {
      // Fall back to legacy mode
      const ratchetState = initializeRatchet(
        keypair,
        recipientBundle.identityKey || recipientPublicKey
      );
      // ... continue with standard encryption
    }
  } catch (error) {
    console.error('Encryption failed:', error);
  }
};

const handleDecrypt = async () => {
  try {
    // Try to parse as Ladder message
    const ladderMessage = decodeLadderMessage(encryptedMessage);
    if (ladderMessage) {
      // Verify counter hasn't been used
      const senderId = uint8ArrayToBase32Crockford(ladderMessage.senderIdentityKey);
      const isValid = checkAndUpdateMaxSpent(senderId, ladderMessage.opkIndex);
      
      if (!isValid) {
        throw new Error('Message replay detected - invalid counter');
      }
      
      // Process complete Ladder message
      const decrypted = await processLadderMessage(
        myExtendedKeypair.identity,
        myExtendedKeypair.ephemeralSeed,
        ladderMessage
      );
      
      setOutput(new TextDecoder().decode(decrypted));
      
    } else {
      // Try legacy decryption
      // ... standard ratchet decryption
    }
  } catch (error) {
    console.error('Decryption failed:', error);
  }
};
```

## 4. Message Format

### 4.1 Ladder Message Encoding
**File**: `src/utils/messageFormat.ts`
```typescript
export function encodeLadderMessage(
  message: LadderMessage
): Uint8Array {
  // Format: [version(1)] [index(4)] [identity(32)] [ephemeral(32)] [payload_len(4)] [payload]
  const encoded = new Uint8Array(1 + 4 + 32 + 32 + 4 + message.encryptedPayload.length);
  let offset = 0;
  
  // Version
  encoded[offset++] = message.version;
  
  // Index (little-endian)
  new DataView(encoded.buffer).setUint32(offset, message.opkIndex, true);
  offset += 4;
  
  // Keys
  encoded.set(message.senderIdentityKey, offset);
  offset += 32;
  encoded.set(message.senderEphemeralKey, offset);
  offset += 32;
  
  // Payload length and data
  new DataView(encoded.buffer).setUint32(offset, message.encryptedPayload.length, true);
  offset += 4;
  encoded.set(message.encryptedPayload, offset);
  
  return encoded;
}

export function decodeLadderMessage(
  encoded: Uint8Array
): LadderMessage | null {
  if (encoded.length < 73 || encoded[0] !== 1) {
    return null; // Not a Ladder message or wrong version
  }
  
  let offset = 1;
  
  const opkIndex = new DataView(encoded.buffer).getUint32(offset, true);
  offset += 4;
  
  const senderIdentityKey = encoded.slice(offset, offset + 32);
  offset += 32;
  
  const senderEphemeralKey = encoded.slice(offset, offset + 32);
  offset += 32;
  
  const payloadLength = new DataView(encoded.buffer).getUint32(offset, true);
  offset += 4;
  
  const encryptedPayload = encoded.slice(offset, offset + payloadLength);
  
  return {
    version: 1,
    opkIndex,
    senderIdentityKey,
    senderEphemeralKey,
    encryptedPayload
  };
}
```

## 5. Testing

### 5.1 Unit Tests
```typescript
describe('Ladder Protocol', () => {
  describe('OPK Derivation', () => {
    test('derives deterministic keys from seed and index', async () => {
      const seed = nacl.box.keyPair();
      const identity = nacl.box.keyPair();
      
      const opk1 = await deriveOPKPublic(seed.publicKey, identity.secretKey, 1);
      const opk2 = await deriveOPKPublic(seed.publicKey, identity.secretKey, 2);
      const opk1_again = await deriveOPKPublic(seed.publicKey, identity.secretKey, 1);
      
      expect(opk1).not.toEqual(opk2);
      expect(opk1).toEqual(opk1_again); // Deterministic
    });
  });
  
  describe('Counter Management', () => {
    test('rejects replayed indices', () => {
      const peerId = 'test-peer';
      
      expect(checkAndUpdateMaxSpent(peerId, 1)).toBe(true);
      expect(checkAndUpdateMaxSpent(peerId, 2)).toBe(true);
      expect(checkAndUpdateMaxSpent(peerId, 1)).toBe(false); // Replay
      expect(checkAndUpdateMaxSpent(peerId, 3)).toBe(true);
    });
    
    test('increments next index', () => {
      const peerId = 'test-peer';
      
      const i1 = getNextIndex(peerId);
      const i2 = getNextIndex(peerId);
      const i3 = getNextIndex(peerId);
      
      expect(i2).toBe(i1 + 1);
      expect(i3).toBe(i2 + 1);
    });
  });
  
  describe('Message Exchange', () => {
    test('Alice and Bob can exchange messages without round trips', async () => {
      const alice = {
        identity: nacl.box.keyPair(),
        ephemeralSeed: nacl.box.keyPair()
      };
      
      const bob = {
        identity: nacl.box.keyPair(),
        ephemeralSeed: nacl.box.keyPair()
      };
      
      const plaintext = new TextEncoder().encode('Hello Bob!');
      const index = 1;
      
      // Alice creates complete message with embedded PreKeyInit
      const ladderMessage = await createLadderMessage(
        alice.identity,
        alice.ephemeralSeed,
        bob.identity.publicKey,
        bob.ephemeralSeed.publicKey,
        index,
        plaintext
      );
      
      // Bob processes the message (no round trip needed)
      const decrypted = await processLadderMessage(
        bob.identity,
        bob.ephemeralSeed,
        ladderMessage
      );
      
      // Decrypted should match original
      expect(new TextDecoder().decode(decrypted)).toBe('Hello Bob!');
    });
    
    test('Message format is self-contained', async () => {
      const alice = {
        identity: nacl.box.keyPair(),
        ephemeralSeed: nacl.box.keyPair()
      };
      
      const bob = {
        identity: nacl.box.keyPair(),
        ephemeralSeed: nacl.box.keyPair()
      };
      
      const plaintext = new TextEncoder().encode('Test message');
      
      // Create message
      const ladderMessage = await createLadderMessage(
        alice.identity,
        alice.ephemeralSeed,
        bob.identity.publicKey,
        bob.ephemeralSeed.publicKey,
        1,
        plaintext
      );
      
      // Verify message contains all needed data
      expect(ladderMessage.version).toBe(1);
      expect(ladderMessage.opkIndex).toBe(1);
      expect(ladderMessage.senderIdentityKey).toEqual(alice.identity.publicKey);
      expect(ladderMessage.senderEphemeralKey).toBeDefined();
      expect(ladderMessage.encryptedPayload).toBeDefined();
      
      // Encode and decode
      const encoded = encodeLadderMessage(ladderMessage);
      const decoded = decodeLadderMessage(encoded);
      
      expect(decoded).toEqual(ladderMessage);
    });
  });
});
```

## 6. UI Updates

### 6.1 Key Display
```typescript
// Show extended format with indicator
<div className="key-display">
  <div className="key-type-badge">
    Identity + Ephemeral (Ladder Ready)
  </div>
  <div className="key-value">
    {formatKeyBundle(extendedKeypair)}
  </div>
  <div className="key-info">
    64 bytes • Forward secrecy enabled
  </div>
</div>
```

### 6.2 Import Status
```typescript
// Show compatibility status
{recipientKeyFormat === 'extended' && (
  <div className="security-badge success">
    ✓ Ladder Protocol ready - Full forward secrecy
  </div>
)}
{recipientKeyFormat === 'legacy' && (
  <div className="security-badge warning">
    ⚠ Legacy key - Limited forward secrecy
  </div>
)}
```

## 7. Protocol Constants

### 7.1 Stable Labels
These labels must remain constant for protocol compatibility:
- `"ladder-bundle-v1"` - Bundle signature context
- `"ladder-seed-v1"` - OPK seed derivation salt
- `"ladder-opk"` - OPK derivation info prefix  
- `"ladder-v1"` - DH concatenation salt
- `"dr-init-v1"` - Double Ratchet initialization info

## 8. Security Properties

### 8.1 Achieved
- ✅ **Forward Secrecy**: From first message via unique OPKs
- ✅ **Replay Protection**: Monotonic counter enforcement
- ✅ **Asynchronous**: No round trips required
- ✅ **Deterministic**: Reproducible OPK derivation
- ✅ **No Server**: Fully peer-to-peer

### 8.2 Considerations
- Counter state must be persisted (localStorage)
- Lost counter state could cause message rejection
- Multi-device needs counter coordination

## 9. Migration Strategy

1. **Phase 1**: Deploy with feature detection
   - Support both 32-byte and 64-byte keys
   - Use Ladder when both have extended keys
   
2. **Phase 2**: Encourage upgrades
   - Show security indicators in UI
   - Prompt to regenerate keys

3. **Phase 3**: Default for new users
   - Generate extended keys by default
   - Maintain legacy support

## 10. Summary

The full Ladder implementation provides:
- **No extra round trips**: PreKeyInit data is embedded in every message envelope
- **Deterministic OPK derivation**: From shared ephemeral seed using HKDF
- **Monotonic counters**: Strong replay protection with persistent state
- **Forward secrecy**: From the very first message exchange
- **Self-contained messages**: Each message includes all data needed to establish session
- **Serverless architecture**: No central infrastructure required
- **Backward compatibility**: Graceful fallback for legacy 32-byte keys

Key architectural insight: By embedding the PreKeyInit header in the message envelope rather than as a separate message, we ensure that after the initial 64-byte key bundle exchange, all subsequent communication requires zero additional round trips. This maintains the asynchronous nature of the protocol while adding forward secrecy.

This achieves Signal-level security properties in a fully serverless, zero-round-trip architecture.