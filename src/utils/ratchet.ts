/**
 * Double Ratchet Protocol Implementation
 */

import * as nacl from 'tweetnacl';
import { RatchetState, RatchetMessage, SerializedRatchetState } from '../types/ratchet';
import { KeyPair } from '../types';
import { deriveKeyFromMasterKey } from './crypto';

const MAX_SKIP = 100; // Maximum number of messages that can be skipped

/**
 * Concatenate two Uint8Arrays
 */
function concat(a: Uint8Array, b: Uint8Array): Uint8Array {
  const result = new Uint8Array(a.length + b.length);
  result.set(a, 0);
  result.set(b, a.length);
  return result;
}

/**
 * Constant-time comparison of two Uint8Arrays
 */
function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a[i] ^ b[i];
  }
  return result === 0;
}

/**
 * Diffie-Hellman key exchange using Curve25519
 */
function dh(privateKey: Uint8Array, publicKey: Uint8Array): Uint8Array {
  // Use nacl.box.before which performs the DH operation
  // This is the proper way to get a shared secret from box keypairs
  return nacl.box.before(publicKey, privateKey);
}

/**
 * Root KDF - derives new root key and chain key
 */
function kdfRootKey(rootKey: Uint8Array, dhOutput: Uint8Array): [Uint8Array, Uint8Array] {
  const input = concat(rootKey, dhOutput);
  const output = nacl.hash(input); // SHA-512
  const newRootKey = output.slice(0, 32);
  const newChainKey = output.slice(32, 64);
  
  // Clear sensitive data
  input.fill(0);
  
  return [newRootKey, newChainKey];
}

/**
 * Chain KDF - derives message key and next chain key
 */
function kdfChainKey(chainKey: Uint8Array): [Uint8Array, Uint8Array] {
  const messageKeyInput = concat(chainKey, new Uint8Array([0x01]));
  const chainKeyInput = concat(chainKey, new Uint8Array([0x02]));
  
  const messageKey = nacl.hash(messageKeyInput).slice(0, 32);
  const nextChainKey = nacl.hash(chainKeyInput).slice(0, 32);
  
  // Clear sensitive data
  messageKeyInput.fill(0);
  chainKeyInput.fill(0);
  
  return [messageKey, nextChainKey];
}

/**
 * Initialize a new ratchet session
 */
export function initializeRatchet(
  myIdentityKeyPair: KeyPair,
  theirIdentityPublicKey: Uint8Array
): RatchetState {
  // Generate initial ephemeral key
  const ephemeralKeyPair = nacl.box.keyPair();
  
  // Compute initial shared secret
  const sharedSecret = dh(myIdentityKeyPair.secretKey, theirIdentityPublicKey);
  
  // Initialize root key and chain keys from shared secret
  const hashedSecret = nacl.hash(sharedSecret);
  const rootKey = hashedSecret.slice(0, 32);
  // Initially, both chains use the same key
  // The actual chain separation happens after the first DH ratchet
  const initialChainKey = hashedSecret.slice(32, 64);
  const sendingChainKey = new Uint8Array(initialChainKey);
  const receivingChainKey = new Uint8Array(initialChainKey);
  
  // Clear sensitive data
  sharedSecret.fill(0);
  
  return {
    myIdentityKeyPair,
    theirIdentityPublicKey,
    myCurrentEphemeralKeyPair: ephemeralKeyPair,
    theirLatestEphemeralPublicKey: null,
    rootKey,
    sendingChainKey,
    receivingChainKey,
    sendMessageCounter: 0,
    receiveMessageCounter: 0,
    previousSendCounter: 0,
    skippedMessageKeys: new Map(),
    isInitialized: true
  };
}

/**
 * Skip message keys for out-of-order messages
 */
function skipMessageKeys(state: RatchetState, from: number, to: number): void {
  if (to - from > MAX_SKIP) {
    throw new Error(`Too many messages skipped (${to - from} > ${MAX_SKIP})`);
  }
  
  let chainKey = state.receivingChainKey;
  for (let i = from; i < to; i++) {
    const [messageKey, nextChainKey] = kdfChainKey(chainKey);
    const key = state.theirLatestEphemeralPublicKey ? 
      `${Array.from(state.theirLatestEphemeralPublicKey).join(',')}-${i}` : 
      `null-${i}`;
    state.skippedMessageKeys.set(key, messageKey);
    chainKey = nextChainKey;
  }
  state.receivingChainKey = chainKey;
}

/**
 * Encrypt a message using the ratchet
 */
export function ratchetEncrypt(state: RatchetState, plaintext: Uint8Array): [Uint8Array, RatchetState] {
  // Clone state to avoid mutations
  const newState = { ...state };
  
  // Perform DH ratchet if we have their ephemeral key
  // This means we're sending AFTER having received at least one message from them
  if (newState.theirLatestEphemeralPublicKey) {
    
    // Save the current send counter as previous before ratcheting
    newState.previousSendCounter = newState.sendMessageCounter;
    
    // Generate new ephemeral key pair for this ratchet step
    const newEphemeralKeyPair = nacl.box.keyPair();
    
    // Perform DH: my_new_ephemeral_private with their_ephemeral_public
    const dhOutput = dh(
      newEphemeralKeyPair.secretKey,
      newState.theirLatestEphemeralPublicKey
    );
    
    // Update root key via KDF
    const [newRootKey, newSendingChainKey] = kdfRootKey(newState.rootKey, dhOutput);
    
    
    // Update state with new ephemeral, root key, and reset sending chain
    newState.myCurrentEphemeralKeyPair = newEphemeralKeyPair;
    newState.rootKey = newRootKey;
    newState.sendingChainKey = newSendingChainKey;
    newState.sendMessageCounter = 0; // Reset counter for new chain
    
    // Clear sensitive data
    dhOutput.fill(0);
  }
  // If we don't have their ephemeral yet (first message), just use our initial ephemeral
  
  // Derive message key from chain
  const [messageKey, nextChainKey] = kdfChainKey(newState.sendingChainKey);
  
  // Update chain key (don't clear the old one as it's part of newState)
  newState.sendingChainKey = nextChainKey;
  
  // Create header
  const header = new Uint8Array(41);
  header[0] = 0x01; // version
  header.set(newState.myCurrentEphemeralKeyPair.publicKey, 1);
  const previousCounterBytes = new Uint8Array(4);
  new DataView(previousCounterBytes.buffer).setUint32(0, newState.previousSendCounter, false);
  header.set(previousCounterBytes, 33);
  const counterBytes = new Uint8Array(4);
  new DataView(counterBytes.buffer).setUint32(0, newState.sendMessageCounter, false);
  header.set(counterBytes, 37);
  
  // Encrypt message
  const nonce = nacl.randomBytes(24);
  
  // Create fresh copies to ensure proper Uint8Array type
  const messageKeyCopy = new Uint8Array(messageKey);
  const plaintextCopy = new Uint8Array(plaintext);
  
  const encrypted = nacl.secretbox(plaintextCopy, nonce, messageKeyCopy);
  
  // Combine header + nonce + encrypted
  const message = new Uint8Array(header.length + nonce.length + encrypted.length);
  message.set(header);
  message.set(nonce, header.length);
  message.set(encrypted, header.length + nonce.length);
  
  // Update state
  newState.sendMessageCounter++;
  
  // Clear sensitive material
  messageKey.fill(0);
  
  return [message, newState];
}

/**
 * Decrypt a message using the ratchet
 */
export function ratchetDecrypt(state: RatchetState, message: Uint8Array): [Uint8Array, RatchetState] {
  // Clone state to avoid mutations
  const newState = { 
    ...state,
    skippedMessageKeys: new Map(state.skippedMessageKeys)
  };
  // Parse header
  if (message.length < 65) {
    throw new Error('Message too short');
  }
  
  const version = message[0];
  if (version !== 0x01) {
    throw new Error(`Unknown protocol version: ${version}`);
  }
  
  const theirEphemeralPublicKey = message.slice(1, 33);
  const previousCounter = new DataView(message.buffer, message.byteOffset + 33, 4).getUint32(0, false);
  const messageCounter = new DataView(message.buffer, message.byteOffset + 37, 4).getUint32(0, false);
  const nonce = message.slice(41, 65);
  const encrypted = message.slice(65);
  
  // Check if we have a new ephemeral key from them
  const hasNewEphemeral = !newState.theirLatestEphemeralPublicKey || 
    !constantTimeEqual(theirEphemeralPublicKey, newState.theirLatestEphemeralPublicKey);
  
  if (hasNewEphemeral) {
    // Save any skipped messages from the old chain before ratcheting  
    if (newState.theirLatestEphemeralPublicKey && previousCounter > 0) {
      skipMessageKeys(newState, newState.receiveMessageCounter, previousCounter);
    }
    
    // Check if we need to perform a DH ratchet
    // The only time we DON'T ratchet is for the very first message of the conversation
    // This happens when:
    // 1. We've never seen their ephemeral before (first message from them)
    // 2. AND we haven't sent them any messages (so they don't have our ephemeral)
    const isFirstMessageFromThem = newState.theirLatestEphemeralPublicKey === null;
    const weHaveSentMessages = newState.sendMessageCounter > 0;
    
    // If this is their first message but we've already sent messages,
    // they must have our ephemeral and have ratcheted
    const shouldRatchet = !isFirstMessageFromThem || weHaveSentMessages;
    
    // Store their new ephemeral
    newState.theirLatestEphemeralPublicKey = new Uint8Array(theirEphemeralPublicKey);
    
    // Perform DH ratchet if needed
    if (shouldRatchet) {
      
      // They performed a ratchet before sending, so we must too
      // Perform DH: my_current_ephemeral_private with their_new_ephemeral_public
      const dhOutput = dh(
        newState.myCurrentEphemeralKeyPair.secretKey,
        theirEphemeralPublicKey
      );
      
      // Update root key via KDF - this gives us the new receiving chain
      const [newRootKey, newReceivingChainKey] = kdfRootKey(newState.rootKey, dhOutput);
      
      // Update state
      newState.rootKey = newRootKey;
      newState.receivingChainKey = newReceivingChainKey;
      newState.receiveMessageCounter = 0;
      
      // Clear sensitive data
      dhOutput.fill(0);
    }
  }
  
  // Skip any missing messages in the current chain
  skipMessageKeys(newState, newState.receiveMessageCounter, messageCounter);
  
  // Try to find the message key in skipped keys first
  const skippedKey = `${Array.from(theirEphemeralPublicKey).join(',')}-${messageCounter}`;
  
  let messageKey: Uint8Array;
  if (newState.skippedMessageKeys.has(skippedKey)) {
    messageKey = newState.skippedMessageKeys.get(skippedKey)!;
    newState.skippedMessageKeys.delete(skippedKey);
  } else {
    // Derive message key from current receiving chain
    const [derivedKey, nextChainKey] = kdfChainKey(newState.receivingChainKey);
    messageKey = derivedKey;
    newState.receivingChainKey = nextChainKey;
    newState.receiveMessageCounter = messageCounter + 1;
  }
  
  // Decrypt
  const plaintext = nacl.secretbox.open(encrypted, nonce, messageKey);
  if (!plaintext) {
    // Clear sensitive material
    messageKey.fill(0);
    throw new Error('Decryption failed');
  }
  
  // Clear sensitive material
  messageKey.fill(0);
  
  return [plaintext, newState];
}

/**
 * Serialize ratchet state for storage
 */
export function serializeRatchetState(state: RatchetState, masterKey: string): string {
  // Create a serializable version of the state
  const stateObj = {
    myIdentityKeyPair: {
      publicKey: Array.from(state.myIdentityKeyPair.publicKey),
      secretKey: Array.from(state.myIdentityKeyPair.secretKey)
    },
    theirIdentityPublicKey: Array.from(state.theirIdentityPublicKey),
    myCurrentEphemeralKeyPair: {
      publicKey: Array.from(state.myCurrentEphemeralKeyPair.publicKey),
      secretKey: Array.from(state.myCurrentEphemeralKeyPair.secretKey)
    },
    theirLatestEphemeralPublicKey: state.theirLatestEphemeralPublicKey ? 
      Array.from(state.theirLatestEphemeralPublicKey) : null,
    rootKey: Array.from(state.rootKey),
    sendingChainKey: Array.from(state.sendingChainKey),
    receivingChainKey: Array.from(state.receivingChainKey),
    sendMessageCounter: state.sendMessageCounter,
    receiveMessageCounter: state.receiveMessageCounter,
    previousSendCounter: state.previousSendCounter,
    skippedMessageKeys: Array.from(state.skippedMessageKeys.entries()).map(([k, v]) => [k, Array.from(v)]),
    isInitialized: state.isInitialized
  };
  
  const stateJson = JSON.stringify(stateObj);
  const stateBytes = new TextEncoder().encode(stateJson);
  
  // Encrypt with master key
  const derivedKey = deriveKeyFromMasterKey(masterKey);
  const nonce = nacl.randomBytes(24);
  // Ensure stateBytes is a proper Uint8Array
  const stateBytesArray = new Uint8Array(stateBytes);
  const encrypted = nacl.secretbox(stateBytesArray, nonce, derivedKey);
  
  // Combine nonce + encrypted
  const combined = new Uint8Array(nonce.length + encrypted.length);
  combined.set(nonce, 0);
  combined.set(encrypted, nonce.length);
  
  // Clear sensitive data
  derivedKey.fill(0);
  
  // Return base64 encoded
  return btoa(String.fromCharCode(...combined));
}

/**
 * Deserialize ratchet state from storage
 */
export function deserializeRatchetState(serialized: string, masterKey: string): RatchetState | null {
  try {
    // Decode from base64
    const combined = new Uint8Array(atob(serialized).split('').map(c => c.charCodeAt(0)));
    
    if (combined.length < 24) {
      return null;
    }
    
    const nonce = combined.slice(0, 24);
    const encrypted = combined.slice(24);
    
    // Decrypt with master key
    const derivedKey = deriveKeyFromMasterKey(masterKey);
    const decrypted = nacl.secretbox.open(encrypted, nonce, derivedKey);
    
    // Clear sensitive data
    derivedKey.fill(0);
    
    if (!decrypted) {
      return null;
    }
    
    const stateJson = new TextDecoder().decode(decrypted);
    const stateObj = JSON.parse(stateJson);
    
    // Reconstruct the state
    return {
      myIdentityKeyPair: {
        publicKey: new Uint8Array(stateObj.myIdentityKeyPair.publicKey),
        secretKey: new Uint8Array(stateObj.myIdentityKeyPair.secretKey)
      },
      theirIdentityPublicKey: new Uint8Array(stateObj.theirIdentityPublicKey),
      myCurrentEphemeralKeyPair: {
        publicKey: new Uint8Array(stateObj.myCurrentEphemeralKeyPair.publicKey),
        secretKey: new Uint8Array(stateObj.myCurrentEphemeralKeyPair.secretKey)
      },
      theirLatestEphemeralPublicKey: stateObj.theirLatestEphemeralPublicKey ? 
        new Uint8Array(stateObj.theirLatestEphemeralPublicKey) : null,
      rootKey: new Uint8Array(stateObj.rootKey),
      sendingChainKey: new Uint8Array(stateObj.sendingChainKey),
      receivingChainKey: new Uint8Array(stateObj.receivingChainKey),
      sendMessageCounter: stateObj.sendMessageCounter,
      receiveMessageCounter: stateObj.receiveMessageCounter,
      previousSendCounter: stateObj.previousSendCounter,
      skippedMessageKeys: new Map(stateObj.skippedMessageKeys.map(([k, v]: [string, number[]]) => 
        [k, new Uint8Array(v)])),
      isInitialized: stateObj.isInitialized
    };
  } catch (error) {
    console.error('Failed to deserialize ratchet state:', error);
    return null;
  }
}

/**
 * Create a storage key for a ratchet session
 */
export function getRatchetStorageKey(myPublicKey: Uint8Array, theirPublicKey: Uint8Array): string {
  const combined = concat(myPublicKey, theirPublicKey);
  const hash = nacl.hash(combined);
  combined.fill(0);
  return `ratchet_${btoa(String.fromCharCode(...hash.slice(0, 16)))}`;
}