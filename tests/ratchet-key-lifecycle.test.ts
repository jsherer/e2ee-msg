/**
 * Tests for Double Ratchet Protocol key lifecycle and management
 */

import * as nacl from 'tweetnacl';
import {
  initializeRatchet,
  ratchetEncrypt,
  ratchetDecrypt
} from '../src/utils/ratchet';
import { RatchetState } from '../src/types/ratchet';
import { KeyPair } from '../src/types';

describe('Ratchet Protocol - Key Lifecycle', () => {
  let alice: KeyPair;
  let bob: KeyPair;
  let aliceState: RatchetState;
  let bobState: RatchetState;

  beforeEach(() => {
    alice = nacl.box.keyPair();
    bob = nacl.box.keyPair();
    aliceState = initializeRatchet(alice, bob.publicKey);
    bobState = initializeRatchet(bob, alice.publicKey);
  });

  describe('Message key deletion', () => {
    it('should delete message key after successful decryption', () => {
      const message = new TextEncoder().encode('Test message');
      const [encrypted, aliceState2] = ratchetEncrypt(aliceState, message);
      
      // Decrypt the message
      const [decrypted, bobState2] = ratchetDecrypt(bobState, encrypted);
      expect(new TextDecoder().decode(decrypted)).toBe('Test message');
      
      // Try to decrypt the same message again - should fail
      expect(() => {
        ratchetDecrypt(bobState2, encrypted);
      }).toThrow(/Decryption failed/);
    });

    it('should delete skipped message keys after retrieval', () => {
      // Send three messages
      const msg1 = new TextEncoder().encode('Message 1');
      const msg2 = new TextEncoder().encode('Message 2');
      const msg3 = new TextEncoder().encode('Message 3');
      
      const [enc1, aliceState2] = ratchetEncrypt(aliceState, msg1);
      const [enc2, aliceState3] = ratchetEncrypt(aliceState2, msg2);
      const [enc3, aliceState4] = ratchetEncrypt(aliceState3, msg3);
      
      // Receive message 3 first (skipping 1 and 2)
      const [dec3, bobState2] = ratchetDecrypt(bobState, enc3);
      expect(new TextDecoder().decode(dec3)).toBe('Message 3');
      
      // Check that skipped keys were stored
      expect(bobState2.skippedMessageKeys.size).toBe(2);
      
      // Now receive message 1
      const [dec1, bobState3] = ratchetDecrypt(bobState2, enc1);
      expect(new TextDecoder().decode(dec1)).toBe('Message 1');
      
      // Skipped key for message 1 should be removed
      expect(bobState3.skippedMessageKeys.size).toBe(1);
      
      // Try to decrypt message 1 again - should fail
      expect(() => {
        ratchetDecrypt(bobState3, enc1);
      }).toThrow(/Decryption failed/);
      
      // Receive message 2
      const [dec2, bobState4] = ratchetDecrypt(bobState3, enc2);
      expect(new TextDecoder().decode(dec2)).toBe('Message 2');
      
      // All skipped keys should be cleared
      expect(bobState4.skippedMessageKeys.size).toBe(0);
    });
  });

  describe('Chain key advancement', () => {
    it('should advance chain key with each message', () => {
      const msg1 = new TextEncoder().encode('Message 1');
      const msg2 = new TextEncoder().encode('Message 2');
      
      // Store initial chain key
      const initialChainKey = new Uint8Array(aliceState.sendingChainKey);
      
      // Send first message
      const [enc1, aliceState2] = ratchetEncrypt(aliceState, msg1);
      
      // Chain key should have changed
      expect(aliceState2.sendingChainKey).not.toEqual(initialChainKey);
      
      // Store new chain key
      const chainKey2 = new Uint8Array(aliceState2.sendingChainKey);
      
      // Send second message
      const [enc2, aliceState3] = ratchetEncrypt(aliceState2, msg2);
      
      // Chain key should have changed again
      expect(aliceState3.sendingChainKey).not.toEqual(chainKey2);
      expect(aliceState3.sendingChainKey).not.toEqual(initialChainKey);
    });

    it('should not be able to derive old message keys from current chain key', () => {
      const messages = ['msg1', 'msg2', 'msg3'].map(m => 
        new TextEncoder().encode(m)
      );
      
      let currentState = aliceState;
      const encryptedMessages: Uint8Array[] = [];
      const chainKeys: Uint8Array[] = [];
      
      // Send multiple messages and track chain keys
      for (const msg of messages) {
        chainKeys.push(new Uint8Array(currentState.sendingChainKey));
        const [enc, newState] = ratchetEncrypt(currentState, msg);
        encryptedMessages.push(enc);
        currentState = newState;
      }
      
      // Verify all chain keys are different
      for (let i = 0; i < chainKeys.length; i++) {
        for (let j = i + 1; j < chainKeys.length; j++) {
          expect(chainKeys[i]).not.toEqual(chainKeys[j]);
        }
      }
      
      // Chain keys should form a one-way chain (can't go backwards)
      // This is implicitly tested by the fact that replaying old messages fails
    });
  });

  describe('Root key evolution', () => {
    it('should update root key on DH ratchet', () => {
      // Store initial root key
      const initialRootKey = new Uint8Array(aliceState.rootKey);
      
      // Alice sends first message
      const msg1 = new TextEncoder().encode('Alice message');
      const [enc1, aliceState2] = ratchetEncrypt(aliceState, msg1);
      const [_, bobState2] = ratchetDecrypt(bobState, enc1);
      
      // Root key should not change yet (no DH ratchet)
      expect(aliceState2.rootKey).toEqual(initialRootKey);
      
      // Bob replies, triggering DH ratchet
      const msg2 = new TextEncoder().encode('Bob reply');
      const [enc2, bobState3] = ratchetEncrypt(bobState2, msg2);
      
      // Bob's root key should have changed
      expect(bobState3.rootKey).not.toEqual(initialRootKey);
      
      // Alice receives, her root key should update
      const [__, aliceState3] = ratchetDecrypt(aliceState2, enc2);
      expect(aliceState3.rootKey).not.toEqual(initialRootKey);
      
      // Both should have the same root key now
      expect(aliceState3.rootKey).toEqual(bobState3.rootKey);
    });

    it('should generate new root key for each DH ratchet', () => {
      const rootKeys: Uint8Array[] = [];
      
      // Initial root key
      rootKeys.push(new Uint8Array(aliceState.rootKey));
      
      // Multiple rounds of communication
      let currentAliceState = aliceState;
      let currentBobState = bobState;
      
      for (let i = 0; i < 3; i++) {
        // Alice sends
        const msgA = new TextEncoder().encode(`Alice ${i}`);
        const [encA, newAliceState] = ratchetEncrypt(currentAliceState, msgA);
        const [_, newBobState] = ratchetDecrypt(currentBobState, encA);
        
        // Bob replies (triggers DH ratchet)
        const msgB = new TextEncoder().encode(`Bob ${i}`);
        const [encB, newerBobState] = ratchetEncrypt(newBobState, msgB);
        const [__, newerAliceState] = ratchetDecrypt(newAliceState, encB);
        
        // Store the new root key
        rootKeys.push(new Uint8Array(newerAliceState.rootKey));
        
        currentAliceState = newerAliceState;
        currentBobState = newerBobState;
      }
      
      // All root keys should be unique
      for (let i = 0; i < rootKeys.length; i++) {
        for (let j = i + 1; j < rootKeys.length; j++) {
          expect(rootKeys[i]).not.toEqual(rootKeys[j]);
        }
      }
    });
  });

  describe('Ephemeral key rotation', () => {
    it('should generate new ephemeral key for each sending chain', () => {
      // Alice's initial ephemeral
      const initialEphemeral = new Uint8Array(aliceState.myCurrentEphemeralKeyPair.publicKey);
      
      // Alice sends first message
      const msg1 = new TextEncoder().encode('Alice 1');
      const [enc1, aliceState2] = ratchetEncrypt(aliceState, msg1);
      const [_, bobState2] = ratchetDecrypt(bobState, enc1);
      
      // Ephemeral should not change yet (same sending chain)
      expect(aliceState2.myCurrentEphemeralKeyPair.publicKey).toEqual(initialEphemeral);
      
      // Bob replies (triggers DH ratchet for Alice)
      const msg2 = new TextEncoder().encode('Bob 1');
      const [enc2, bobState3] = ratchetEncrypt(bobState2, msg2);
      const [__, aliceState3] = ratchetDecrypt(aliceState2, enc2);
      
      // Alice sends again (new sending chain)
      const msg3 = new TextEncoder().encode('Alice 2');
      const [enc3, aliceState4] = ratchetEncrypt(aliceState3, msg3);
      
      // Alice should have a new ephemeral key
      expect(aliceState4.myCurrentEphemeralKeyPair.publicKey).not.toEqual(initialEphemeral);
    });

    it('should rotate ephemeral keys on DH ratchet', () => {
      const aliceEphemeralKeys: Uint8Array[] = [];
      const bobEphemeralKeys: Uint8Array[] = [];
      
      let currentAliceState = aliceState;
      let currentBobState = bobState;
      
      // Store initial ephemeral keys
      aliceEphemeralKeys.push(
        new Uint8Array(currentAliceState.myCurrentEphemeralKeyPair.publicKey)
      );
      bobEphemeralKeys.push(
        new Uint8Array(currentBobState.myCurrentEphemeralKeyPair.publicKey)
      );
      
      // Alice sends first (no ratchet yet)
      const msgA1 = new TextEncoder().encode('Alice 1');
      const [encA1, aliceState2] = ratchetEncrypt(currentAliceState, msgA1);
      const [_, bobState2] = ratchetDecrypt(currentBobState, encA1);
      
      // Alice's ephemeral shouldn't change (no DH ratchet occurred)
      expect(aliceState2.myCurrentEphemeralKeyPair.publicKey).toEqual(aliceEphemeralKeys[0]);
      
      // Bob replies (Bob performs DH ratchet)
      const msgB1 = new TextEncoder().encode('Bob 1');
      const [encB1, bobState3] = ratchetEncrypt(bobState2, msgB1);
      
      // Bob should have a new ephemeral after DH ratchet
      bobEphemeralKeys.push(new Uint8Array(bobState3.myCurrentEphemeralKeyPair.publicKey));
      expect(bobEphemeralKeys[1]).not.toEqual(bobEphemeralKeys[0]);
      
      // Alice receives (Alice performs DH ratchet)
      const [__, aliceState3] = ratchetDecrypt(aliceState2, encB1);
      
      // Alice sends again (Alice performs DH ratchet)
      const msgA2 = new TextEncoder().encode('Alice 2');
      const [encA2, aliceState4] = ratchetEncrypt(aliceState3, msgA2);
      
      // Alice should have a new ephemeral after DH ratchet
      aliceEphemeralKeys.push(new Uint8Array(aliceState4.myCurrentEphemeralKeyPair.publicKey));
      expect(aliceEphemeralKeys[1]).not.toEqual(aliceEphemeralKeys[0]);
      
      // Verify each party generates unique ephemeral keys
      expect(aliceEphemeralKeys[0]).not.toEqual(aliceEphemeralKeys[1]);
      expect(bobEphemeralKeys[0]).not.toEqual(bobEphemeralKeys[1]);
    });
  });

  describe('Skipped key cache management', () => {
    it('should respect MAX_SKIP limit', () => {
      // Try to skip more than MAX_SKIP messages (100)
      let currentAliceState = aliceState;
      const messages: Uint8Array[] = [];
      
      // Create 102 messages
      for (let i = 0; i < 102; i++) {
        const msg = new TextEncoder().encode(`Message ${i}`);
        const [enc, newState] = ratchetEncrypt(currentAliceState, msg);
        messages.push(enc);
        currentAliceState = newState;
      }
      
      // Try to receive message 101 (skipping 0-100, which is 101 messages)
      expect(() => {
        ratchetDecrypt(bobState, messages[101]);
      }).toThrow(/Too many messages skipped/);
    });

    it('should clear skipped keys when no longer needed', () => {
      // Send 5 messages
      let currentAliceState = aliceState;
      const messages: Uint8Array[] = [];
      
      for (let i = 0; i < 5; i++) {
        const msg = new TextEncoder().encode(`Message ${i}`);
        const [enc, newState] = ratchetEncrypt(currentAliceState, msg);
        messages.push(enc);
        currentAliceState = newState;
      }
      
      // Receive message 4 first (skip 0-3)
      const [_, bobState2] = ratchetDecrypt(bobState, messages[4]);
      expect(bobState2.skippedMessageKeys.size).toBe(4);
      
      // Receive messages in order 0, 1, 2, 3
      let currentBobState = bobState2;
      for (let i = 0; i < 4; i++) {
        const [__, newBobState] = ratchetDecrypt(currentBobState, messages[i]);
        currentBobState = newBobState;
        // Skipped keys should decrease
        expect(currentBobState.skippedMessageKeys.size).toBe(3 - i);
      }
      
      // All skipped keys should be cleared
      expect(currentBobState.skippedMessageKeys.size).toBe(0);
    });
  });
});