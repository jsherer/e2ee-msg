# Simple Hash Ratchet Specification

## Overview

This document specifies a simplified one-way hash ratchet protocol for the E2EE messaging application. This protocol provides forward secrecy through hash chain advancement but does not provide post-compromise security. It's significantly simpler to implement than the full double ratchet.

## Security Properties

1. **Forward Secrecy**: Past messages cannot be decrypted even if current keys are compromised
2. **Simple Implementation**: Uses only hash functions, no ephemeral key generation
3. **Asynchronous Operation**: Works without parties being online simultaneously  
4. **Low Overhead**: Minimal additional data in messages (only 4-byte counter)
5. **Deterministic**: Given same initial state, produces same key sequence

## Limitations

- **No Break-in Recovery**: If current state is compromised, all future messages are compromised
- **One-Way Only**: Cannot go backwards in the chain to recover lost keys
- **No Out-of-Order Support**: Messages must be processed sequentially

## Protocol Components

### 1. State Structure

```typescript
interface SimpleRatchetState {
  // Root key derived from initial key exchange
  rootKey: Uint8Array;           // 32 bytes
  
  // Current chain keys
  sendingChainKey: Uint8Array;   // 32 bytes
  receivingChainKey: Uint8Array; // 32 bytes
  
  // Message counters
  sendCounter: number;
  receiveCounter: number;
  
  // Their public key (for chain initialization)
  theirPublicKey: Uint8Array;    // 32 bytes
}
```

### 2. Message Format

```
Message structure:
[counter: 4 bytes][nonce: 24 bytes][encrypted_payload: variable]
```

Total overhead: 28 bytes (vs 65 bytes for full ratchet)

Binary layout:
```
Offset | Size | Field
-------|------|------
0      | 4    | Message counter (big-endian)
4      | 24   | Nonce for nacl.secretbox
28     | var  | Encrypted message
```

### 3. Key Derivation

```javascript
// Simple hash ratchet - advances key by one step
function ratchetKey(key: Uint8Array): Uint8Array {
  return nacl.hash(key).slice(0, 32);
}

// Advance key by N steps
function ratchetKeyN(key: Uint8Array, steps: number): Uint8Array {
  let current = key;
  for (let i = 0; i < steps; i++) {
    current = ratchetKey(current);
  }
  return current;
}

// Derive message key from chain key
function deriveMessageKey(chainKey: Uint8Array, counter: number): Uint8Array {
  const input = new Uint8Array(36);
  input.set(chainKey);
  new DataView(input.buffer).setUint32(32, counter, false);
  return nacl.hash(input).slice(0, 32);
}
```

### 4. Protocol Operations

#### 4.1 Initialization

```javascript
function initializeSimpleRatchet(
  myKeyPair: KeyPair,
  theirPublicKey: Uint8Array
): SimpleRatchetState {
  // Compute shared secret via Diffie-Hellman
  const sharedSecret = nacl.box.before(theirPublicKey, myKeyPair.secretKey);
  
  // Derive root key
  const rootKey = nacl.hash(sharedSecret).slice(0, 32);
  
  // Initialize separate chains for sending and receiving
  const sendingChainKey = nacl.hash(concat(rootKey, Uint8Array.from([0x01]))).slice(0, 32);
  const receivingChainKey = nacl.hash(concat(rootKey, Uint8Array.from([0x02]))).slice(0, 32);
  
  return {
    rootKey,
    sendingChainKey,
    receivingChainKey,
    sendCounter: 0,
    receiveCounter: 0,
    theirPublicKey
  };
}
```

#### 4.2 Encrypting Messages

```javascript
function simpleRatchetEncrypt(
  state: SimpleRatchetState,
  plaintext: Uint8Array
): [Uint8Array, SimpleRatchetState] {
  // Derive message key for current counter
  const messageKey = deriveMessageKey(state.sendingChainKey, state.sendCounter);
  
  // Create message header with counter
  const counterBytes = new Uint8Array(4);
  new DataView(counterBytes.buffer).setUint32(0, state.sendCounter, false);
  
  // Encrypt with nacl.secretbox
  const nonce = nacl.randomBytes(24);
  const encrypted = nacl.secretbox(plaintext, nonce, messageKey);
  
  // Combine counter + nonce + encrypted
  const message = new Uint8Array(4 + 24 + encrypted.length);
  message.set(counterBytes, 0);
  message.set(nonce, 4);
  message.set(encrypted, 28);
  
  // Advance the sending chain
  state.sendingChainKey = ratchetKey(state.sendingChainKey);
  state.sendCounter++;
  
  // Clear sensitive material
  messageKey.fill(0);
  
  return [message, state];
}
```

#### 4.3 Decrypting Messages

```javascript
function simpleRatchetDecrypt(
  state: SimpleRatchetState,
  message: Uint8Array
): [Uint8Array, SimpleRatchetState] {
  // Parse message
  const counter = new DataView(message.buffer, message.byteOffset, 4).getUint32(0, false);
  const nonce = message.slice(4, 28);
  const encrypted = message.slice(28);
  
  // Check if we need to catch up
  if (counter < state.receiveCounter) {
    throw new Error('Message replay detected');
  }
  
  if (counter > state.receiveCounter) {
    // Fast-forward the chain to catch up
    const steps = counter - state.receiveCounter;
    if (steps > 100) {
      throw new Error('Too many messages skipped');
    }
    state.receivingChainKey = ratchetKeyN(state.receivingChainKey, steps);
    state.receiveCounter = counter;
  }
  
  // Derive message key
  const messageKey = deriveMessageKey(state.receivingChainKey, counter);
  
  // Decrypt
  const plaintext = nacl.secretbox.open(encrypted, nonce, messageKey);
  if (!plaintext) {
    throw new Error('Decryption failed');
  }
  
  // Advance receiving chain
  state.receivingChainKey = ratchetKey(state.receivingChainKey);
  state.receiveCounter++;
  
  // Clear sensitive material
  messageKey.fill(0);
  
  return [plaintext, state];
}
```

### 5. Optional: Periodic Key Rotation

For additional security, implement periodic full key rotation:

```javascript
interface RotatingRatchetState extends SimpleRatchetState {
  epochCounter: number;
  messagesInEpoch: number;
  maxMessagesPerEpoch: number; // e.g., 100
}

function checkRotation(state: RotatingRatchetState): RotatingRatchetState {
  if (state.messagesInEpoch >= state.maxMessagesPerEpoch) {
    // Generate new epoch keys
    const epochSeed = nacl.hash(
      concat(state.rootKey, Uint8Array.from([state.epochCounter]))
    );
    
    state.sendingChainKey = epochSeed.slice(0, 32);
    state.receivingChainKey = epochSeed.slice(32, 64);
    state.epochCounter++;
    state.messagesInEpoch = 0;
    state.sendCounter = 0;
    state.receiveCounter = 0;
  }
  return state;
}
```

### 6. State Persistence

```javascript
function serializeSimpleState(state: SimpleRatchetState): string {
  const buffer = new Uint8Array(136);
  buffer.set(state.rootKey, 0);
  buffer.set(state.sendingChainKey, 32);
  buffer.set(state.receivingChainKey, 64);
  buffer.set(state.theirPublicKey, 96);
  new DataView(buffer.buffer).setUint32(128, state.sendCounter, false);
  new DataView(buffer.buffer).setUint32(132, state.receiveCounter, false);
  
  // Encrypt with master key
  const nonce = nacl.randomBytes(24);
  const encrypted = nacl.secretbox(buffer, nonce, masterKey);
  
  // Combine nonce + encrypted and encode
  const combined = new Uint8Array(24 + encrypted.length);
  combined.set(nonce, 0);
  combined.set(encrypted, 24);
  
  return uint8ArrayToBase36(combined);
}

function deserializeSimpleState(encoded: string, masterKey: Uint8Array): SimpleRatchetState {
  const combined = base36ToUint8Array(encoded);
  const nonce = combined.slice(0, 24);
  const encrypted = combined.slice(24);
  
  const buffer = nacl.secretbox.open(encrypted, nonce, masterKey);
  if (!buffer) throw new Error('Invalid state');
  
  return {
    rootKey: buffer.slice(0, 32),
    sendingChainKey: buffer.slice(32, 64),
    receivingChainKey: buffer.slice(64, 96),
    theirPublicKey: buffer.slice(96, 128),
    sendCounter: new DataView(buffer.buffer, 128, 4).getUint32(0, false),
    receiveCounter: new DataView(buffer.buffer, 132, 4).getUint32(0, false)
  };
}
```

### 7. Integration Example

```javascript
// Modified encrypt function
async function handleEncrypt() {
  const plaintext = new TextEncoder().encode(message);
  const [encrypted, newState] = simpleRatchetEncrypt(ratchetState, plaintext);
  
  // Persist state
  window.location.hash = serializeSimpleState(newState);
  
  // Display encrypted message
  const output = formatInGroups(uint8ArrayToBase36(encrypted));
  setOutput(`Encrypted (ratchet #${newState.sendCounter}):\n${output}`);
}

// Modified decrypt function  
async function handleDecrypt() {
  const encrypted = base36ToUint8Array(message);
  const [plaintext, newState] = simpleRatchetDecrypt(ratchetState, encrypted);
  
  // Persist state
  window.location.hash = serializeSimpleState(newState);
  
  // Display decrypted message
  const output = new TextDecoder().decode(plaintext);
  setOutput(`Decrypted (ratchet #${newState.receiveCounter}):\n${output}`);
}
```

### 8. UI Indicators

Add visual feedback for ratchet state:

```jsx
<div style={{ fontSize: '12px', color: '#666' }}>
  🔐 Ratchet Position: Send #{sendCounter} | Receive #{receiveCounter}
  {messagesInEpoch && ` | Epoch: ${epochCounter} (${messagesInEpoch}/${maxMessagesPerEpoch})`}
</div>
```

### 9. Advantages Over Full Ratchet

1. **Simplicity**: ~100 lines of code vs ~500 for full ratchet
2. **Performance**: Only hash operations, no DH computations per message
3. **Smaller Messages**: 28 bytes overhead vs 65 bytes
4. **Predictable**: Deterministic key derivation
5. **Easier Debugging**: Simpler state, fewer edge cases

### 10. When to Use Simple vs Full Ratchet

**Use Simple Ratchet when:**
- Forward secrecy is sufficient
- Implementation simplicity is priority
- Message size constraints exist
- Devices have limited computational power
- Trust model assumes secure endpoints

**Use Full Ratchet when:**
- Break-in recovery is required
- Handling potentially compromised devices
- Long-lived conversations
- High-security requirements
- Following Signal protocol standards

### 11. Migration Path

Support both protocols with version byte:

```javascript
function encryptMessage(plaintext: Uint8Array, useFullRatchet: boolean) {
  if (useFullRatchet) {
    // Version 0x01 = full ratchet
    return fullRatchetEncrypt(plaintext);
  } else {
    // Version 0x00 = simple ratchet
    const [encrypted, newState] = simpleRatchetEncrypt(state, plaintext);
    // Prepend version byte
    const versioned = new Uint8Array(1 + encrypted.length);
    versioned[0] = 0x00;
    versioned.set(encrypted, 1);
    return versioned;
  }
}
```

### 12. Testing

```javascript
// Test: Basic encryption/decryption
const state1 = initializeSimpleRatchet(aliceKeyPair, bobPublicKey);
const state2 = initializeSimpleRatchet(bobKeyPair, alicePublicKey);

const msg1 = new TextEncoder().encode("Hello");
const [enc1, newState1] = simpleRatchetEncrypt(state1, msg1);
const [dec1, newState2] = simpleRatchetDecrypt(state2, enc1);
assert(dec1.equals(msg1));

// Test: Multiple messages
for (let i = 0; i < 10; i++) {
  const msg = new TextEncoder().encode(`Message ${i}`);
  const [enc, s1] = simpleRatchetEncrypt(newState1, msg);
  const [dec, s2] = simpleRatchetDecrypt(newState2, enc);
  assert(dec.equals(msg));
  newState1 = s1;
  newState2 = s2;
}

// Test: Out of order rejection
const [enc2] = simpleRatchetEncrypt(state1, msg1); // Counter = 0
const [enc3] = simpleRatchetEncrypt(state1, msg1); // Counter = 1
simpleRatchetDecrypt(state2, enc3); // Process counter 1
assertThrows(() => simpleRatchetDecrypt(state2, enc2)); // Reject counter 0
```

## Conclusion

The simple hash ratchet provides forward secrecy with minimal complexity and overhead. While it lacks the break-in recovery of the full double ratchet, it's an excellent choice for applications prioritizing simplicity and efficiency while still providing strong forward secrecy guarantees.