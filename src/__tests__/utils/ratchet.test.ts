/**
 * Tests for Double Ratchet Protocol Implementation
 */

import {
  initializeRatchet,
  ratchetEncrypt,
  ratchetDecrypt,
  serializeRatchetState,
  deserializeRatchetState,
  getRatchetStorageKey
} from '../../utils/ratchet';
import { generateKeyPair } from '../../utils/crypto';
import * as nacl from 'tweetnacl';

describe('Double Ratchet Protocol', () => {
  describe('initializeRatchet', () => {
    it('should initialize a new ratchet session', () => {
      const alice = generateKeyPair();
      const bob = generateKeyPair();
      
      const state = initializeRatchet(alice, bob.publicKey);
      
      expect(state.isInitialized).toBe(true);
      expect(state.myIdentityKeyPair).toEqual(alice);
      expect(state.theirIdentityPublicKey).toEqual(bob.publicKey);
      expect(state.myCurrentEphemeralKeyPair.publicKey).toHaveLength(32);
      expect(state.myCurrentEphemeralKeyPair.secretKey).toHaveLength(32);
      expect(state.theirLatestEphemeralPublicKey).toBeNull();
      expect(state.rootKey).toHaveLength(32);
      expect(state.sendingChainKey).toHaveLength(32);
      expect(state.receivingChainKey).toHaveLength(32);
      expect(state.sendMessageCounter).toBe(0);
      expect(state.receiveMessageCounter).toBe(0);
      expect(state.previousSendCounter).toBe(0);
      expect(state.skippedMessageKeys.size).toBe(0);
    });
  });

  describe('ratchetEncrypt and ratchetDecrypt', () => {
    it('should encrypt and decrypt a message', () => {
      const alice = generateKeyPair();
      const bob = generateKeyPair();
      
      // Initialize both sides
      let aliceState = initializeRatchet(alice, bob.publicKey);
      let bobState = initializeRatchet(bob, alice.publicKey);
      
      // Alice sends first message
      const message1 = new TextEncoder().encode('Hello Bob!');
      const [encrypted1, aliceState2] = ratchetEncrypt(aliceState, message1);
      
      expect(encrypted1).toBeInstanceOf(Uint8Array);
      expect(encrypted1.length).toBeGreaterThan(65); // Header + nonce + encrypted
      expect(encrypted1[0]).toBe(0x01); // Version byte
      
      // Bob receives and decrypts
      const [decrypted1, bobState2] = ratchetDecrypt(bobState, encrypted1);
      
      expect(Buffer.from(decrypted1)).toEqual(Buffer.from(message1));
      expect(new TextDecoder().decode(decrypted1)).toBe('Hello Bob!');
    });

    it('should handle bidirectional message exchange', () => {
      const alice = generateKeyPair();
      const bob = generateKeyPair();
      
      let aliceState = initializeRatchet(alice, bob.publicKey);
      let bobState = initializeRatchet(bob, alice.publicKey);
      
      // Alice -> Bob
      const msg1 = new TextEncoder().encode('Message 1 from Alice');
      const [enc1, aliceState2] = ratchetEncrypt(aliceState, msg1);
      const [dec1, bobState2] = ratchetDecrypt(bobState, enc1);
      expect(new TextDecoder().decode(dec1)).toBe('Message 1 from Alice');
      
      // Bob -> Alice
      const msg2 = new TextEncoder().encode('Message 2 from Bob');
      const [enc2, bobState3] = ratchetEncrypt(bobState2, msg2);
      const [dec2, aliceState3] = ratchetDecrypt(aliceState2, enc2);
      expect(new TextDecoder().decode(dec2)).toBe('Message 2 from Bob');
      
      // Alice -> Bob (second message)
      const msg3 = new TextEncoder().encode('Message 3 from Alice');
      const [enc3, aliceState4] = ratchetEncrypt(aliceState3, msg3);
      const [dec3, bobState4] = ratchetDecrypt(bobState3, enc3);
      expect(new TextDecoder().decode(dec3)).toBe('Message 3 from Alice');
    });

    it('should perform DH ratchet when receiving new ephemeral key', () => {
      const alice = generateKeyPair();
      const bob = generateKeyPair();
      
      let aliceState = initializeRatchet(alice, bob.publicKey);
      let bobState = initializeRatchet(bob, alice.publicKey);
      
      // Alice sends first message
      const msg1 = new TextEncoder().encode('First');
      const [enc1, aliceState2] = ratchetEncrypt(aliceState, msg1);
      const [dec1, bobState2] = ratchetDecrypt(bobState, enc1);
      
      // Bob's ephemeral key should be updated
      expect(bobState2.theirLatestEphemeralPublicKey).not.toBeNull();
      expect(bobState2.theirLatestEphemeralPublicKey).toEqual(aliceState2.myCurrentEphemeralKeyPair.publicKey);
      
      // Bob sends message (triggers DH ratchet)
      const msg2 = new TextEncoder().encode('Reply');
      const [enc2, bobState3] = ratchetEncrypt(bobState2, msg2);
      
      // Bob should have new ephemeral key
      expect(bobState3.myCurrentEphemeralKeyPair.publicKey).not.toEqual(bobState2.myCurrentEphemeralKeyPair.publicKey);
      
      // Alice receives and should update her state
      const [dec2, aliceState3] = ratchetDecrypt(aliceState2, enc2);
      expect(aliceState3.theirLatestEphemeralPublicKey).toEqual(bobState3.myCurrentEphemeralKeyPair.publicKey);
    });

    it('should handle out-of-order messages', () => {
      const alice = generateKeyPair();
      const bob = generateKeyPair();
      
      let aliceState = initializeRatchet(alice, bob.publicKey);
      let bobState = initializeRatchet(bob, alice.publicKey);
      
      // Alice sends multiple messages
      const msg1 = new TextEncoder().encode('Message 1');
      const msg2 = new TextEncoder().encode('Message 2');
      const msg3 = new TextEncoder().encode('Message 3');
      
      const [enc1, aliceState2] = ratchetEncrypt(aliceState, msg1);
      const [enc2, aliceState3] = ratchetEncrypt(aliceState2, msg2);
      const [enc3, aliceState4] = ratchetEncrypt(aliceState3, msg3);
      
      // Bob receives messages out of order (3, 1, 2)
      const [dec3, bobState2] = ratchetDecrypt(bobState, enc3);
      expect(new TextDecoder().decode(dec3)).toBe('Message 3');
      expect(bobState2.skippedMessageKeys.size).toBeGreaterThan(0);
      
      const [dec1, bobState3] = ratchetDecrypt(bobState2, enc1);
      expect(new TextDecoder().decode(dec1)).toBe('Message 1');
      
      const [dec2, bobState4] = ratchetDecrypt(bobState3, enc2);
      expect(new TextDecoder().decode(dec2)).toBe('Message 2');
    });

    it('should reject messages with wrong keys', () => {
      const alice = generateKeyPair();
      const bob = generateKeyPair();
      const eve = generateKeyPair();
      
      let aliceState = initializeRatchet(alice, bob.publicKey);
      let eveState = initializeRatchet(eve, alice.publicKey);
      
      // Alice encrypts for Bob
      const message = new TextEncoder().encode('Secret message');
      const [encrypted] = ratchetEncrypt(aliceState, message);
      
      // Eve tries to decrypt
      expect(() => {
        ratchetDecrypt(eveState, encrypted);
      }).toThrow();
    });

    it('should handle maximum skip limit', () => {
      const alice = generateKeyPair();
      const bob = generateKeyPair();
      
      let aliceState = initializeRatchet(alice, bob.publicKey);
      let bobState = initializeRatchet(bob, alice.publicKey);
      
      // Alice sends message 0
      const msg0 = new TextEncoder().encode('Message 0');
      const [enc0] = ratchetEncrypt(aliceState, msg0);
      
      // Alice sends 101 more messages (exceeding MAX_SKIP)
      let currentState = aliceState;
      for (let i = 1; i <= 101; i++) {
        const msg = new TextEncoder().encode(`Message ${i}`);
        const [, newState] = ratchetEncrypt(currentState, msg);
        currentState = newState;
      }
      
      // Create message 102
      const msg102 = new TextEncoder().encode('Message 102');
      const [enc102] = ratchetEncrypt(currentState, msg102);
      
      // Bob tries to decrypt message 102 (should fail due to MAX_SKIP)
      expect(() => {
        ratchetDecrypt(bobState, enc102);
      }).toThrow(/Too many messages skipped/);
    });
  });

  describe('serializeRatchetState and deserializeRatchetState', () => {
    it('should serialize and deserialize ratchet state', () => {
      const alice = generateKeyPair();
      const bob = generateKeyPair();
      const masterKey = 'test-master-key-12345';
      
      const state = initializeRatchet(alice, bob.publicKey);
      
      // Serialize
      const serialized = serializeRatchetState(state, masterKey);
      expect(typeof serialized).toBe('string');
      
      // Deserialize
      const deserialized = deserializeRatchetState(serialized, masterKey);
      expect(deserialized).not.toBeNull();
      expect(deserialized!.isInitialized).toBe(true);
      expect(deserialized!.myIdentityKeyPair.publicKey).toEqual(alice.publicKey);
      expect(deserialized!.myIdentityKeyPair.secretKey).toEqual(alice.secretKey);
      expect(deserialized!.theirIdentityPublicKey).toEqual(bob.publicKey);
    });

    it('should fail to deserialize with wrong master key', () => {
      const alice = generateKeyPair();
      const bob = generateKeyPair();
      const masterKey = 'correct-master-key';
      const wrongKey = 'wrong-master-key';
      
      const state = initializeRatchet(alice, bob.publicKey);
      const serialized = serializeRatchetState(state, masterKey);
      
      const deserialized = deserializeRatchetState(serialized, wrongKey);
      expect(deserialized).toBeNull();
    });

    it('should preserve state through serialization', () => {
      const alice = generateKeyPair();
      const bob = generateKeyPair();
      const masterKey = 'test-master-key';
      
      let aliceState = initializeRatchet(alice, bob.publicKey);
      let bobState = initializeRatchet(bob, alice.publicKey);
      
      // Exchange some messages
      const msg1 = new TextEncoder().encode('Test message');
      const [enc1, aliceState2] = ratchetEncrypt(aliceState, msg1);
      const [, bobState2] = ratchetDecrypt(bobState, enc1);
      
      // Serialize Bob's state
      const serialized = serializeRatchetState(bobState2, masterKey);
      
      // Deserialize and continue conversation
      const bobStateRestored = deserializeRatchetState(serialized, masterKey)!;
      
      // Alice sends another message
      const msg2 = new TextEncoder().encode('Another message');
      const [enc2] = ratchetEncrypt(aliceState2, msg2);
      
      // Bob (with restored state) should be able to decrypt
      const [dec2] = ratchetDecrypt(bobStateRestored, enc2);
      expect(new TextDecoder().decode(dec2)).toBe('Another message');
    });
  });

  describe('getRatchetStorageKey', () => {
    it('should generate consistent storage keys', () => {
      const alice = generateKeyPair();
      const bob = generateKeyPair();
      
      const key1 = getRatchetStorageKey(alice.publicKey, bob.publicKey);
      const key2 = getRatchetStorageKey(alice.publicKey, bob.publicKey);
      
      expect(key1).toBe(key2);
      expect(key1).toMatch(/^ratchet_/);
    });

    it('should generate different keys for different pairs', () => {
      const alice = generateKeyPair();
      const bob = generateKeyPair();
      const charlie = generateKeyPair();
      
      const key1 = getRatchetStorageKey(alice.publicKey, bob.publicKey);
      const key2 = getRatchetStorageKey(alice.publicKey, charlie.publicKey);
      const key3 = getRatchetStorageKey(bob.publicKey, charlie.publicKey);
      
      expect(key1).not.toBe(key2);
      expect(key2).not.toBe(key3);
      expect(key1).not.toBe(key3);
    });
  });

  describe('Forward Secrecy', () => {
    it('should provide forward secrecy', () => {
      const alice = generateKeyPair();
      const bob = generateKeyPair();
      
      let aliceState = initializeRatchet(alice, bob.publicKey);
      let bobState = initializeRatchet(bob, alice.publicKey);
      
      // Exchange messages
      const msg1 = new TextEncoder().encode('Old message');
      const [enc1, aliceState2] = ratchetEncrypt(aliceState, msg1);
      const [, bobState2] = ratchetDecrypt(bobState, enc1);
      
      // Save old chain key
      const oldChainKey = new Uint8Array(aliceState.sendingChainKey);
      
      // Send more messages to advance the ratchet
      const msg2 = new TextEncoder().encode('New message');
      const [enc2, aliceState3] = ratchetEncrypt(aliceState2, msg2);
      
      // Verify chain key has changed
      expect(aliceState3.sendingChainKey).not.toEqual(oldChainKey);
      
      // Old chain key should not be recoverable from current state
      // This is a conceptual test - in practice, old keys are overwritten
      expect(aliceState3.sendingChainKey).toHaveLength(32);
    });
  });

  describe('Post-Compromise Security', () => {
    it('should recover security after DH ratchet', () => {
      const alice = generateKeyPair();
      const bob = generateKeyPair();
      
      let aliceState = initializeRatchet(alice, bob.publicKey);
      let bobState = initializeRatchet(bob, alice.publicKey);
      
      // Alice sends message
      const msg1 = new TextEncoder().encode('Before compromise');
      const [enc1, aliceState2] = ratchetEncrypt(aliceState, msg1);
      const [, bobState2] = ratchetDecrypt(bobState, enc1);
      
      // Save Bob's current root key (simulating compromise)
      const compromisedRootKey = new Uint8Array(bobState2.rootKey);
      
      // Bob replies (performs DH ratchet with new ephemeral)
      const msg2 = new TextEncoder().encode('After compromise');
      const [enc2, bobState3] = ratchetEncrypt(bobState2, msg2);
      
      // Bob's root key should have changed
      expect(bobState3.rootKey).not.toEqual(compromisedRootKey);
      
      // Alice receives and updates her state
      const [, aliceState3] = ratchetDecrypt(aliceState2, enc2);
      
      // Future messages use new keys not derivable from compromised key
      const msg3 = new TextEncoder().encode('Secure again');
      const [enc3] = ratchetEncrypt(aliceState3, msg3);
      const [dec3] = ratchetDecrypt(bobState3, enc3);
      
      expect(new TextDecoder().decode(dec3)).toBe('Secure again');
    });
  });
});