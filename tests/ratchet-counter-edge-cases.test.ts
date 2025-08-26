/**
 * Tests for Double Ratchet Protocol message counter edge cases and skipping
 */

import * as nacl from 'tweetnacl';
import {
  initializeRatchet,
  ratchetEncrypt,
  ratchetDecrypt
} from '../src/utils/ratchet';
import { RatchetState } from '../src/types/ratchet';
import { KeyPair } from '../src/types';

describe('Ratchet Protocol - Counter Edge Cases', () => {
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

  describe('Duplicate detection', () => {
    it('should reject duplicate messages with same counter', () => {
      const message = new TextEncoder().encode('Test message');
      const [encrypted, aliceState2] = ratchetEncrypt(aliceState, message);
      
      // First decryption succeeds
      const [decrypted1, bobState2] = ratchetDecrypt(bobState, encrypted);
      expect(new TextDecoder().decode(decrypted1)).toBe('Test message');
      
      // Second decryption of same message should fail
      expect(() => {
        ratchetDecrypt(bobState2, encrypted);
      }).toThrow(/Decryption failed/);
    });

    it('should reject duplicate counters within same chain', () => {
      // Send three messages
      const msg1 = new TextEncoder().encode('Message 1');
      const msg2 = new TextEncoder().encode('Message 2');
      const msg3 = new TextEncoder().encode('Message 3');
      
      const [enc1, aliceState2] = ratchetEncrypt(aliceState, msg1);
      const [enc2, aliceState3] = ratchetEncrypt(aliceState2, msg2);
      const [enc3, aliceState4] = ratchetEncrypt(aliceState3, msg3);
      
      // Receive messages 1 and 3 (skipping 2)
      const [_, bobState2] = ratchetDecrypt(bobState, enc1);
      const [__, bobState3] = ratchetDecrypt(bobState2, enc3);
      
      // Receive message 2 (out of order but valid)
      const [dec2, bobState4] = ratchetDecrypt(bobState3, enc2);
      expect(new TextDecoder().decode(dec2)).toBe('Message 2');
      
      // Try to replay message 2 - should fail
      expect(() => {
        ratchetDecrypt(bobState4, enc2);
      }).toThrow(/Decryption failed/);
    });
  });

  describe('Large gap handling', () => {
    it('should handle large gap within MAX_SKIP (skip 50 messages)', () => {
      // Create 51 messages (0-50)
      let currentAliceState = aliceState;
      const messages: Uint8Array[] = [];
      
      for (let i = 0; i <= 50; i++) {
        const msg = new TextEncoder().encode(`Message ${i}`);
        const [enc, newState] = ratchetEncrypt(currentAliceState, msg);
        messages.push(enc);
        currentAliceState = newState;
      }
      
      // Receive message 50 first (skipping 0-49)
      const [dec50, bobState2] = ratchetDecrypt(bobState, messages[50]);
      expect(new TextDecoder().decode(dec50)).toBe('Message 50');
      
      // Should have cached 50 skipped keys (0-49)
      expect(bobState2.skippedMessageKeys.size).toBe(50);
      
      // Should be able to decrypt all skipped messages
      let currentBobState = bobState2;
      for (let i = 0; i < 50; i++) {
        const [dec, newState] = ratchetDecrypt(currentBobState, messages[i]);
        expect(new TextDecoder().decode(dec)).toBe(`Message ${i}`);
        currentBobState = newState;
        // Skipped keys should decrease
        expect(currentBobState.skippedMessageKeys.size).toBe(49 - i);
      }
      
      // All skipped keys should be cleared
      expect(currentBobState.skippedMessageKeys.size).toBe(0);
    });

    it('should handle gaps across chain boundaries', () => {
      // Alice sends messages
      const msg1 = new TextEncoder().encode('Alice 1');
      const msg2 = new TextEncoder().encode('Alice 2');
      const [enc1, aliceState2] = ratchetEncrypt(aliceState, msg1);
      const [enc2, aliceState3] = ratchetEncrypt(aliceState2, msg2);
      
      // Bob receives first message and replies (triggers DH ratchet)
      const [_, bobState2] = ratchetDecrypt(bobState, enc1);
      const msgB = new TextEncoder().encode('Bob reply');
      const [encB, bobState3] = ratchetEncrypt(bobState2, msgB);
      
      // Alice receives Bob's reply and sends more
      const [__, aliceState4] = ratchetDecrypt(aliceState3, encB);
      const msg3 = new TextEncoder().encode('Alice 3 (new chain)');
      const msg4 = new TextEncoder().encode('Alice 4 (new chain)');
      const [enc3, aliceState5] = ratchetEncrypt(aliceState4, msg3);
      const [enc4, aliceState6] = ratchetEncrypt(aliceState5, msg4);
      
      // Bob receives message 4 first (skipping 2 from old chain and 3 from new)
      const [dec4, bobState4] = ratchetDecrypt(bobState3, enc4);
      expect(new TextDecoder().decode(dec4)).toBe('Alice 4 (new chain)');
      
      // Should have skipped keys for both chains
      expect(bobState4.skippedMessageKeys.size).toBeGreaterThan(0);
      
      // Should be able to receive message 2 from old chain
      const [dec2, bobState5] = ratchetDecrypt(bobState4, enc2);
      expect(new TextDecoder().decode(dec2)).toBe('Alice 2');
      
      // Should be able to receive message 3 from new chain
      const [dec3, bobState6] = ratchetDecrypt(bobState5, enc3);
      expect(new TextDecoder().decode(dec3)).toBe('Alice 3 (new chain)');
    });
  });

  describe('MAX_SKIP boundary', () => {
    it('should accept exactly MAX_SKIP (100) skipped messages', () => {
      // Create 101 messages (0-100)
      let currentAliceState = aliceState;
      const messages: Uint8Array[] = [];
      
      for (let i = 0; i <= 100; i++) {
        const msg = new TextEncoder().encode(`Message ${i}`);
        const [enc, newState] = ratchetEncrypt(currentAliceState, msg);
        messages.push(enc);
        currentAliceState = newState;
      }
      
      // Receive message 100 (skipping exactly 100 messages: 0-99)
      const [dec100, bobState2] = ratchetDecrypt(bobState, messages[100]);
      expect(new TextDecoder().decode(dec100)).toBe('Message 100');
      
      // Should have exactly 100 skipped keys
      expect(bobState2.skippedMessageKeys.size).toBe(100);
    });

    it('should reject MAX_SKIP+1 (101) skipped messages', () => {
      // Create 102 messages
      let currentAliceState = aliceState;
      const messages: Uint8Array[] = [];
      
      for (let i = 0; i < 102; i++) {
        const msg = new TextEncoder().encode(`Message ${i}`);
        const [enc, newState] = ratchetEncrypt(currentAliceState, msg);
        messages.push(enc);
        currentAliceState = newState;
      }
      
      // Try to receive message 101 (would skip 101 messages: 0-100)
      expect(() => {
        ratchetDecrypt(bobState, messages[101]);
      }).toThrow(/Too many messages skipped/);
    });

    it('should handle MAX_SKIP across DH ratchet boundary', () => {
      // Alice sends 50 messages
      let currentAliceState = aliceState;
      const aliceMessages1: Uint8Array[] = [];
      
      for (let i = 0; i < 50; i++) {
        const msg = new TextEncoder().encode(`Alice chain 1 msg ${i}`);
        const [enc, newState] = ratchetEncrypt(currentAliceState, msg);
        aliceMessages1.push(enc);
        currentAliceState = newState;
      }
      
      // Bob receives first message only
      const [_, bobState2] = ratchetDecrypt(bobState, aliceMessages1[0]);
      
      // Bob replies (triggers DH ratchet)
      const msgB = new TextEncoder().encode('Bob reply');
      const [encB, bobState3] = ratchetEncrypt(bobState2, msgB);
      
      // Alice receives and sends 52 more messages in new chain
      const [__, aliceState2] = ratchetDecrypt(currentAliceState, encB);
      currentAliceState = aliceState2;
      const aliceMessages2: Uint8Array[] = [];
      
      for (let i = 0; i < 52; i++) {
        const msg = new TextEncoder().encode(`Alice chain 2 msg ${i}`);
        const [enc, newState] = ratchetEncrypt(currentAliceState, msg);
        aliceMessages2.push(enc);
        currentAliceState = newState;
      }
      
      // Bob tries to receive message 51 from chain 2
      // This would skip: 49 from chain 1 + 51 from chain 2 = 100 total
      const [dec, bobState4] = ratchetDecrypt(bobState3, aliceMessages2[51]);
      expect(new TextDecoder().decode(dec)).toBe('Alice chain 2 msg 51');
      
      // Should have skipped keys from both chains
      expect(bobState4.skippedMessageKeys.size).toBeLessThanOrEqual(100);
    });
  });

  describe('Counter monotonicity', () => {
    it('should ensure counters never decrease within a chain', () => {
      // Track counters as Alice sends messages
      const counters: number[] = [];
      let currentAliceState = aliceState;
      
      for (let i = 0; i < 10; i++) {
        counters.push(currentAliceState.sendMessageCounter);
        const msg = new TextEncoder().encode(`Message ${i}`);
        const [_, newState] = ratchetEncrypt(currentAliceState, msg);
        currentAliceState = newState;
      }
      
      // Verify strict monotonic increase
      for (let i = 1; i < counters.length; i++) {
        expect(counters[i]).toBe(counters[i - 1] + 1);
      }
      
      // Final counter should be 10
      expect(currentAliceState.sendMessageCounter).toBe(10);
    });

    it('should maintain independent counters for different chains', () => {
      // Alice sends messages
      const msg1 = new TextEncoder().encode('Alice 1');
      const msg2 = new TextEncoder().encode('Alice 2');
      const [enc1, aliceState2] = ratchetEncrypt(aliceState, msg1);
      const [enc2, aliceState3] = ratchetEncrypt(aliceState2, msg2);
      
      expect(aliceState3.sendMessageCounter).toBe(2);
      
      // Bob receives and replies
      const [_, bobState2] = ratchetDecrypt(bobState, enc1);
      const [__, bobState3] = ratchetDecrypt(bobState2, enc2);
      
      const msgB1 = new TextEncoder().encode('Bob 1');
      const msgB2 = new TextEncoder().encode('Bob 2');
      const [encB1, bobState4] = ratchetEncrypt(bobState3, msgB1);
      const [encB2, bobState5] = ratchetEncrypt(bobState4, msgB2);
      
      // Bob's counter should be independent
      expect(bobState5.sendMessageCounter).toBe(2);
      
      // Alice receives Bob's messages and sends in new chain
      const [___, aliceState4] = ratchetDecrypt(aliceState3, encB1);
      const [____, aliceState5] = ratchetDecrypt(aliceState4, encB2);
      
      const msg3 = new TextEncoder().encode('Alice 3 (new chain)');
      const [enc3, aliceState6] = ratchetEncrypt(aliceState5, msg3);
      
      // Alice's counter should reset for new chain
      expect(aliceState6.sendMessageCounter).toBe(1);
      expect(aliceState6.previousSendCounter).toBe(2);
    });
  });

  describe('Cache eviction', () => {
    it('should handle out-of-order delivery within cache limits', () => {
      // Send 10 messages
      let currentAliceState = aliceState;
      const messages: Uint8Array[] = [];
      
      for (let i = 0; i < 10; i++) {
        const msg = new TextEncoder().encode(`Message ${i}`);
        const [enc, newState] = ratchetEncrypt(currentAliceState, msg);
        messages.push(enc);
        currentAliceState = newState;
      }
      
      // Receive in random order: 5, 2, 8, 0, 9, 1, 3, 7, 4, 6
      const order = [5, 2, 8, 0, 9, 1, 3, 7, 4, 6];
      let currentBobState = bobState;
      
      for (const index of order) {
        const [dec, newState] = ratchetDecrypt(currentBobState, messages[index]);
        expect(new TextDecoder().decode(dec)).toBe(`Message ${index}`);
        currentBobState = newState;
      }
      
      // All messages should be received successfully
      expect(currentBobState.receiveMessageCounter).toBe(10);
      expect(currentBobState.skippedMessageKeys.size).toBe(0);
    });

    it('should properly track skipped keys during out-of-order delivery', () => {
      // Send 5 messages
      let currentAliceState = aliceState;
      const messages: Uint8Array[] = [];
      
      for (let i = 0; i < 5; i++) {
        const msg = new TextEncoder().encode(`Message ${i}`);
        const [enc, newState] = ratchetEncrypt(currentAliceState, msg);
        messages.push(enc);
        currentAliceState = newState;
      }
      
      // Receive message 4 first
      const [_, bobState2] = ratchetDecrypt(bobState, messages[4]);
      expect(bobState2.skippedMessageKeys.size).toBe(4);
      expect(bobState2.receiveMessageCounter).toBe(5);
      
      // Receive message 1
      const [__, bobState3] = ratchetDecrypt(bobState2, messages[1]);
      expect(bobState3.skippedMessageKeys.size).toBe(3);
      
      // Receive message 3
      const [___, bobState4] = ratchetDecrypt(bobState3, messages[3]);
      expect(bobState4.skippedMessageKeys.size).toBe(2);
      
      // Receive messages 0 and 2
      const [____, bobState5] = ratchetDecrypt(bobState4, messages[0]);
      const [_____, bobState6] = ratchetDecrypt(bobState5, messages[2]);
      
      // All skipped keys should be consumed
      expect(bobState6.skippedMessageKeys.size).toBe(0);
    });
  });
});