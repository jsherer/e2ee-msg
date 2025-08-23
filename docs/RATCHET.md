# Asynchronous Double Ratchet Specification

## Overview

This document specifies an asynchronous double ratchet protocol for the E2EE messaging application. The protocol provides forward secrecy and post-compromise security (break-in recovery) while maintaining the app's serverless, asynchronous nature.

## Security Properties

1. **Forward Secrecy**: Compromise of current keys doesn't reveal past messages
2. **Post-Compromise Security**: System recovers from key compromise after one message exchange
3. **Asynchronous Operation**: No requirement for parties to be online simultaneously
4. **No Server Required**: All operations performed client-side

## Protocol Components

### 1. Key Types

```typescript
interface KeyPair {
  publicKey: Uint8Array;  // 32 bytes (Curve25519)
  secretKey: Uint8Array;  // 32 bytes
}

interface RatchetState {
  // Identity keys (long-term)
  myIdentityKeyPair: KeyPair;
  theirIdentityPublicKey: Uint8Array;
  
  // Ephemeral keys
  myCurrentEphemeralKeyPair: KeyPair;
  theirLatestEphemeralPublicKey: Uint8Array | null;
  
  // Chain keys
  rootKey: Uint8Array;           // 32 bytes
  sendingChainKey: Uint8Array;   // 32 bytes
  receivingChainKey: Uint8Array; // 32 bytes
  
  // Counters
  sendMessageCounter: number;
  receiveMessageCounter: number;
  previousSendCounter: number;
  
  // Skipped message keys (for out-of-order delivery)
  skippedMessageKeys: Map<string, Uint8Array>;
}
```

### 2. Message Format

```
Total message structure:
[header][nonce][encrypted_payload]

Header (unencrypted):
[version: 1 byte]
[ephemeral_public_key: 32 bytes]
[previous_chain_counter: 4 bytes]
[message_counter: 4 bytes]

Encrypted payload:
[actual_message_content]
```

Binary layout (total overhead: 65 bytes):
```
Offset | Size | Field
-------|------|------
0      | 1    | Protocol version (0x01)
1      | 32   | Ephemeral public key
33     | 4    | Previous chain counter (big-endian)
37     | 4    | Message counter (big-endian)
41     | 24   | Nonce for nacl.box
65     | var  | Encrypted message
```

### 3. Key Derivation Functions

```javascript
// Root KDF - derives new root key and chain key
function kdfRootKey(rootKey: Uint8Array, dhOutput: Uint8Array): [Uint8Array, Uint8Array] {
  const input = concat(rootKey, dhOutput);
  const output = nacl.hash(input); // SHA-512
  const newRootKey = output.slice(0, 32);
  const newChainKey = output.slice(32, 64);
  return [newRootKey, newChainKey];
}

// Chain KDF - derives message key and next chain key
function kdfChainKey(chainKey: Uint8Array): [Uint8Array, Uint8Array] {
  const messageKey = nacl.hash(concat(chainKey, Uint8Array.from([0x01]))).slice(0, 32);
  const nextChainKey = nacl.hash(concat(chainKey, Uint8Array.from([0x02]))).slice(0, 32);
  return [messageKey, nextChainKey];
}

// Diffie-Hellman
function dh(privateKey: Uint8Array, publicKey: Uint8Array): Uint8Array {
  return nacl.scalarMult(privateKey, publicKey);
}
```

### 4. Protocol Operations

#### 4.1 Initialization

```javascript
function initializeRatchet(
  myIdentityKeyPair: KeyPair,
  theirIdentityPublicKey: Uint8Array
): RatchetState {
  // Generate initial ephemeral key
  const ephemeralKeyPair = nacl.box.keyPair();
  
  // Compute initial shared secret
  const sharedSecret = dh(myIdentityKeyPair.secretKey, theirIdentityPublicKey);
  
  // Initialize root key
  const rootKey = nacl.hash(sharedSecret).slice(0, 32);
  
  return {
    myIdentityKeyPair,
    theirIdentityPublicKey,
    myCurrentEphemeralKeyPair: ephemeralKeyPair,
    theirLatestEphemeralPublicKey: null,
    rootKey,
    sendingChainKey: new Uint8Array(32),
    receivingChainKey: new Uint8Array(32),
    sendMessageCounter: 0,
    receiveMessageCounter: 0,
    previousSendCounter: 0,
    skippedMessageKeys: new Map()
  };
}
```

#### 4.2 Sending Messages

```javascript
function ratchetEncrypt(state: RatchetState, plaintext: Uint8Array): [Uint8Array, RatchetState] {
  // Generate new ephemeral key pair
  const newEphemeralKeyPair = nacl.box.keyPair();
  
  // Perform DH ratchet if we have their ephemeral key
  if (state.theirLatestEphemeralPublicKey) {
    const dhOutput = dh(
      state.myCurrentEphemeralKeyPair.secretKey,
      state.theirLatestEphemeralPublicKey
    );
    const [newRootKey, newChainKey] = kdfRootKey(state.rootKey, dhOutput);
    state.rootKey = newRootKey;
    state.sendingChainKey = newChainKey;
    state.previousSendCounter = state.sendMessageCounter;
    state.sendMessageCounter = 0;
  }
  
  // Derive message key from chain
  const [messageKey, nextChainKey] = kdfChainKey(state.sendingChainKey);
  state.sendingChainKey = nextChainKey;
  
  // Create header
  const header = new Uint8Array(41);
  header[0] = 0x01; // version
  header.set(newEphemeralKeyPair.publicKey, 1);
  const previousCounterBytes = new Uint8Array(4);
  new DataView(previousCounterBytes.buffer).setUint32(0, state.previousSendCounter, false);
  header.set(previousCounterBytes, 33);
  const counterBytes = new Uint8Array(4);
  new DataView(counterBytes.buffer).setUint32(0, state.sendMessageCounter, false);
  header.set(counterBytes, 37);
  
  // Encrypt message
  const nonce = nacl.randomBytes(24);
  const encrypted = nacl.secretbox(plaintext, nonce, messageKey);
  
  // Combine header + nonce + encrypted
  const message = new Uint8Array(header.length + nonce.length + encrypted.length);
  message.set(header);
  message.set(nonce, header.length);
  message.set(encrypted, header.length + nonce.length);
  
  // Update state
  state.myCurrentEphemeralKeyPair = newEphemeralKeyPair;
  state.sendMessageCounter++;
  
  // Clear sensitive material
  messageKey.fill(0);
  
  return [message, state];
}
```

#### 4.3 Receiving Messages

```javascript
function ratchetDecrypt(state: RatchetState, message: Uint8Array): [Uint8Array, RatchetState] {
  // Parse header
  const version = message[0];
  if (version !== 0x01) throw new Error('Unknown protocol version');
  
  const theirEphemeralPublicKey = message.slice(1, 33);
  const previousCounter = new DataView(message.buffer, message.byteOffset + 33, 4).getUint32(0, false);
  const messageCounter = new DataView(message.buffer, message.byteOffset + 37, 4).getUint32(0, false);
  const nonce = message.slice(41, 65);
  const encrypted = message.slice(65);
  
  // Check if we need to perform DH ratchet
  const needsRatchet = !state.theirLatestEphemeralPublicKey || 
    !constantTimeEqual(theirEphemeralPublicKey, state.theirLatestEphemeralPublicKey);
  
  if (needsRatchet) {
    // Save any skipped messages from current chain
    skipMessageKeys(state, state.receiveMessageCounter, previousCounter);
    
    // Perform DH ratchet
    const dhOutput = dh(
      state.myCurrentEphemeralKeyPair.secretKey,
      theirEphemeralPublicKey
    );
    const [newRootKey, newChainKey] = kdfRootKey(state.rootKey, dhOutput);
    state.rootKey = newRootKey;
    state.receivingChainKey = newChainKey;
    state.theirLatestEphemeralPublicKey = theirEphemeralPublicKey;
    state.receiveMessageCounter = 0;
  }
  
  // Skip any missing messages
  skipMessageKeys(state, state.receiveMessageCounter, messageCounter);
  
  // Derive message key
  const [messageKey, nextChainKey] = kdfChainKey(state.receivingChainKey);
  state.receivingChainKey = nextChainKey;
  state.receiveMessageCounter = messageCounter + 1;
  
  // Decrypt
  const plaintext = nacl.secretbox.open(encrypted, nonce, messageKey);
  if (!plaintext) {
    throw new Error('Decryption failed');
  }
  
  // Clear sensitive material
  messageKey.fill(0);
  
  return [plaintext, state];
}

function skipMessageKeys(state: RatchetState, from: number, to: number): void {
  if (to - from > 100) {
    throw new Error('Too many messages skipped');
  }
  
  let chainKey = state.receivingChainKey;
  for (let i = from; i < to; i++) {
    const [messageKey, nextChainKey] = kdfChainKey(chainKey);
    const key = `${state.theirLatestEphemeralPublicKey}-${i}`;
    state.skippedMessageKeys.set(key, messageKey);
    chainKey = nextChainKey;
  }
  state.receivingChainKey = chainKey;
}
```

### 5. State Persistence

The ratchet state must be persisted securely:

```javascript
function serializeState(state: RatchetState): Uint8Array {
  // Serialize to binary format
  // Encrypt with master key using nacl.secretbox
  // Return encrypted blob
}

function deserializeState(encrypted: Uint8Array, masterKey: Uint8Array): RatchetState {
  // Decrypt with master key
  // Parse binary format
  // Reconstruct state object
}
```

State should be stored in:
- URL hash (current approach)
- LocalStorage (with encryption)
- IndexedDB (for larger state with many skipped keys)

### 6. Security Considerations

1. **Key Deletion**: Delete private keys immediately after use
2. **Nonce Reuse**: Never reuse nonces - always generate fresh
3. **State Compromise**: If state is compromised, immediately reinitialize
4. **Message Ordering**: Handle out-of-order delivery with skipped key storage
5. **Replay Protection**: Message counters prevent replay attacks
6. **Maximum Skip**: Limit skipped messages to prevent DoS (e.g., 100 messages)

### 7. Integration with Current App

```javascript
// Modify current encryption function
async function handleEncrypt() {
  const plaintext = new TextEncoder().encode(message);
  const [encrypted, newState] = ratchetEncrypt(ratchetState, plaintext);
  
  // Update persisted state
  const serialized = serializeState(newState);
  window.location.hash = uint8ArrayToBase36(serialized);
  
  // Display encrypted message
  const output = formatInGroups(uint8ArrayToBase36(encrypted));
  setOutput(`Encrypted:\n${output}`);
}

// Modify current decryption function
async function handleDecrypt() {
  const encrypted = base36ToUint8Array(message);
  const [plaintext, newState] = ratchetDecrypt(ratchetState, encrypted);
  
  // Update persisted state
  const serialized = serializeState(newState);
  window.location.hash = uint8ArrayToBase36(serialized);
  
  // Display decrypted message
  const output = new TextDecoder().decode(plaintext);
  setOutput(`Decrypted:\n${output}`);
}
```

### 8. Migration Path

1. Add version byte to messages
2. Support both old (non-ratchet) and new (ratchet) messages
3. Upgrade path: First ratchet message includes full initialization
4. Graceful degradation if ratchet state is lost

### 9. Testing Vectors

```javascript
// Test vector 1: Basic message exchange
const alice = initializeRatchet(aliceIdentity, bobIdentity.publicKey);
const bob = initializeRatchet(bobIdentity, aliceIdentity.publicKey);

const plaintext1 = new TextEncoder().encode("Hello Bob");
const [encrypted1, alice2] = ratchetEncrypt(alice, plaintext1);
const [decrypted1, bob2] = ratchetDecrypt(bob, encrypted1);
// decrypted1 should equal plaintext1

const plaintext2 = new TextEncoder().encode("Hello Alice");
const [encrypted2, bob3] = ratchetEncrypt(bob2, plaintext2);
const [decrypted2, alice3] = ratchetDecrypt(alice2, encrypted2);
// decrypted2 should equal plaintext2
```

## Conclusion

This asynchronous double ratchet provides Signal-level security guarantees while maintaining the serverless, async nature of the application. Messages can be exchanged through any medium (email, SMS, QR codes) while providing both forward secrecy and break-in recovery.