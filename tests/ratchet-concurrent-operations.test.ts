/**
 * Tests for Double Ratchet Protocol concurrent operations and complex ordering
 */

import * as nacl from 'tweetnacl';
import {
  initializeRatchet,
  ratchetEncrypt,
  ratchetDecrypt
} from '../src/utils/ratchet';
import { RatchetState } from '../src/types/ratchet';
import { KeyPair } from '../src/types';

describe('Ratchet Protocol - Concurrent Operations', () => {
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

  describe('Out-of-order across DH boundary', () => {
    it('should decrypt old chain message after receiving new DH', () => {
      // Alice sends 3 messages
      const msg1 = new TextEncoder().encode('Alice chain 1 msg 1');
      const msg2 = new TextEncoder().encode('Alice chain 1 msg 2');
      const msg3 = new TextEncoder().encode('Alice chain 1 msg 3');
      
      const [enc1, aliceState2] = ratchetEncrypt(aliceState, msg1);
      const [enc2, aliceState3] = ratchetEncrypt(aliceState2, msg2);
      const [enc3, aliceState4] = ratchetEncrypt(aliceState3, msg3);
      
      // Bob receives only message 1
      const [dec1, bobState2] = ratchetDecrypt(bobState, enc1);
      expect(new TextDecoder().decode(dec1)).toBe('Alice chain 1 msg 1');
      
      // Bob replies (triggers DH ratchet)
      const msgB = new TextEncoder().encode('Bob reply');
      const [encB, bobState3] = ratchetEncrypt(bobState2, msgB);
      
      // Alice receives Bob's reply and sends new chain message
      const [_, aliceState5] = ratchetDecrypt(aliceState4, encB);
      const msg4 = new TextEncoder().encode('Alice chain 2 msg 1');
      const [enc4, aliceState6] = ratchetEncrypt(aliceState5, msg4);
      
      // Bob receives new chain message first
      const [dec4, bobState4] = ratchetDecrypt(bobState3, enc4);
      expect(new TextDecoder().decode(dec4)).toBe('Alice chain 2 msg 1');
      
      // Bob can still receive old chain messages 2 and 3
      const [dec2, bobState5] = ratchetDecrypt(bobState4, enc2);
      expect(new TextDecoder().decode(dec2)).toBe('Alice chain 1 msg 2');
      
      const [dec3, bobState6] = ratchetDecrypt(bobState5, enc3);
      expect(new TextDecoder().decode(dec3)).toBe('Alice chain 1 msg 3');
      
      // Should have remaining skipped keys from the old chain
      // (Bob skipped message 2 and 3 initially, then received new chain, 
      // so they remain in the cache)
      expect(bobState6.skippedMessageKeys.size).toBeLessThanOrEqual(2);
    });

    it('should handle messages from multiple chains interleaved', () => {
      // Alice sends 2 messages
      const msgA1 = new TextEncoder().encode('Alice chain 1 msg 1');
      const msgA2 = new TextEncoder().encode('Alice chain 1 msg 2');
      const [encA1, aliceState2] = ratchetEncrypt(aliceState, msgA1);
      const [encA2, aliceState3] = ratchetEncrypt(aliceState2, msgA2);
      
      // Bob receives first message and replies
      const [_, bobState2] = ratchetDecrypt(bobState, encA1);
      const msgB1 = new TextEncoder().encode('Bob chain 1 msg 1');
      const [encB1, bobState3] = ratchetEncrypt(bobState2, msgB1);
      
      // Alice receives Bob's message and sends new chain
      const [__, aliceState4] = ratchetDecrypt(aliceState3, encB1);
      const msgA3 = new TextEncoder().encode('Alice chain 2 msg 1');
      const msgA4 = new TextEncoder().encode('Alice chain 2 msg 2');
      const [encA3, aliceState5] = ratchetEncrypt(aliceState4, msgA3);
      const [encA4, aliceState6] = ratchetEncrypt(aliceState5, msgA4);
      
      // Bob receives messages out of order: A4, A2, A3
      const [decA4, bobState4] = ratchetDecrypt(bobState3, encA4);
      expect(new TextDecoder().decode(decA4)).toBe('Alice chain 2 msg 2');
      
      const [decA2, bobState5] = ratchetDecrypt(bobState4, encA2);
      expect(new TextDecoder().decode(decA2)).toBe('Alice chain 1 msg 2');
      
      const [decA3, bobState6] = ratchetDecrypt(bobState5, encA3);
      expect(new TextDecoder().decode(decA3)).toBe('Alice chain 2 msg 1');
    });
  });

  describe('Concurrent send/receive', () => {
    it('should handle Alice sending while receiving Bob DH ratchet', () => {
      // Alice sends initial message
      const msgA1 = new TextEncoder().encode('Alice initial');
      const [encA1, aliceState2] = ratchetEncrypt(aliceState, msgA1);
      
      // Bob receives and prepares reply
      const [_, bobState2] = ratchetDecrypt(bobState, encA1);
      const msgB1 = new TextEncoder().encode('Bob reply with DH');
      const [encB1, bobState3] = ratchetEncrypt(bobState2, msgB1);
      
      // Alice sends second message before receiving Bob's reply
      const msgA2 = new TextEncoder().encode('Alice second (before DH)');
      const [encA2, aliceState3] = ratchetEncrypt(aliceState2, msgA2);
      
      // Now Alice receives Bob's reply (triggers her DH ratchet)
      const [decB1, aliceState4] = ratchetDecrypt(aliceState3, encB1);
      expect(new TextDecoder().decode(decB1)).toBe('Bob reply with DH');
      
      // Alice sends with new chain
      const msgA3 = new TextEncoder().encode('Alice after DH ratchet');
      const [encA3, aliceState5] = ratchetEncrypt(aliceState4, msgA3);
      
      // Bob receives Alice's messages
      const [decA2, bobState4] = ratchetDecrypt(bobState3, encA2);
      expect(new TextDecoder().decode(decA2)).toBe('Alice second (before DH)');
      
      const [decA3, bobState5] = ratchetDecrypt(bobState4, encA3);
      expect(new TextDecoder().decode(decA3)).toBe('Alice after DH ratchet');
    });

    it('should handle rapid back-and-forth exchanges', () => {
      let currentAliceState = aliceState;
      let currentBobState = bobState;
      const messages: string[] = [];
      
      // Simulate rapid exchanges
      for (let round = 0; round < 5; round++) {
        // Alice sends
        const msgA = `Alice round ${round}`;
        messages.push(msgA);
        const msgABytes = new TextEncoder().encode(msgA);
        const [encA, newAliceState] = ratchetEncrypt(currentAliceState, msgABytes);
        currentAliceState = newAliceState;
        
        // Bob receives immediately
        const [decA, newBobState] = ratchetDecrypt(currentBobState, encA);
        expect(new TextDecoder().decode(decA)).toBe(msgA);
        currentBobState = newBobState;
        
        // Bob replies immediately
        const msgB = `Bob round ${round}`;
        messages.push(msgB);
        const msgBBytes = new TextEncoder().encode(msgB);
        const [encB, newerBobState] = ratchetEncrypt(currentBobState, msgBBytes);
        currentBobState = newerBobState;
        
        // Alice receives immediately
        const [decB, newerAliceState] = ratchetDecrypt(currentAliceState, encB);
        expect(new TextDecoder().decode(decB)).toBe(msgB);
        currentAliceState = newerAliceState;
      }
      
      // Verify all messages were exchanged
      expect(messages.length).toBe(10);
    });
  });

  describe('Burst after ratchet', () => {
    it('should handle burst of messages immediately after DH ratchet', () => {
      // Alice sends initial
      const msgA1 = new TextEncoder().encode('Alice initial');
      const [encA1, aliceState2] = ratchetEncrypt(aliceState, msgA1);
      
      // Bob receives and replies (triggers DH)
      const [_, bobState2] = ratchetDecrypt(bobState, encA1);
      const msgB1 = new TextEncoder().encode('Bob reply');
      const [encB1, bobState3] = ratchetEncrypt(bobState2, msgB1);
      
      // Bob immediately sends burst of messages
      const bobBurst = ['Bob burst 1', 'Bob burst 2', 'Bob burst 3'];
      let currentBobState = bobState3;
      const bobEncrypted: Uint8Array[] = [];
      
      for (const msg of bobBurst) {
        const msgBytes = new TextEncoder().encode(msg);
        const [enc, newState] = ratchetEncrypt(currentBobState, msgBytes);
        bobEncrypted.push(enc);
        currentBobState = newState;
      }
      
      // Alice receives all messages
      let currentAliceState = aliceState2;
      
      // First Bob's reply (with DH)
      const [decB1, aliceState3] = ratchetDecrypt(currentAliceState, encB1);
      expect(new TextDecoder().decode(decB1)).toBe('Bob reply');
      currentAliceState = aliceState3;
      
      // Then the burst
      for (let i = 0; i < bobBurst.length; i++) {
        const [dec, newState] = ratchetDecrypt(currentAliceState, bobEncrypted[i]);
        expect(new TextDecoder().decode(dec)).toBe(bobBurst[i]);
        currentAliceState = newState;
      }
    });

    it('should handle overlapping bursts from both parties', () => {
      // Initial exchange to establish bidirectional communication
      const msgA1 = new TextEncoder().encode('Alice init');
      const [encA1, aliceState2] = ratchetEncrypt(aliceState, msgA1);
      const [_, bobState2] = ratchetDecrypt(bobState, encA1);
      
      const msgB1 = new TextEncoder().encode('Bob init');
      const [encB1, bobState3] = ratchetEncrypt(bobState2, msgB1);
      const [__, aliceState3] = ratchetDecrypt(aliceState2, encB1);
      
      // Both send bursts
      const aliceBurst = ['Alice burst 1', 'Alice burst 2', 'Alice burst 3'];
      const bobBurst = ['Bob burst 1', 'Bob burst 2'];
      
      let currentAliceState = aliceState3;
      const aliceEncrypted: Uint8Array[] = [];
      for (const msg of aliceBurst) {
        const msgBytes = new TextEncoder().encode(msg);
        const [enc, newState] = ratchetEncrypt(currentAliceState, msgBytes);
        aliceEncrypted.push(enc);
        currentAliceState = newState;
      }
      
      let currentBobState = bobState3;
      const bobEncrypted: Uint8Array[] = [];
      for (const msg of bobBurst) {
        const msgBytes = new TextEncoder().encode(msg);
        const [enc, newState] = ratchetEncrypt(currentBobState, msgBytes);
        bobEncrypted.push(enc);
        currentBobState = newState;
      }
      
      // Alice receives Bob's burst
      for (let i = 0; i < bobBurst.length; i++) {
        const [dec, newState] = ratchetDecrypt(currentAliceState, bobEncrypted[i]);
        expect(new TextDecoder().decode(dec)).toBe(bobBurst[i]);
        currentAliceState = newState;
      }
      
      // Bob receives Alice's burst
      for (let i = 0; i < aliceBurst.length; i++) {
        const [dec, newState] = ratchetDecrypt(currentBobState, aliceEncrypted[i]);
        expect(new TextDecoder().decode(dec)).toBe(aliceBurst[i]);
        currentBobState = newState;
      }
    });
  });

  describe('Race conditions', () => {
    it('should handle sequential operations', () => {
      // Alice sends first
      const msgA = new TextEncoder().encode('Alice message');
      const [encA, aliceState2] = ratchetEncrypt(aliceState, msgA);
      
      // Bob receives Alice's message
      const [decA, bobState2] = ratchetDecrypt(bobState, encA);
      expect(new TextDecoder().decode(decA)).toBe('Alice message');
      
      // Bob sends his message
      const msgB = new TextEncoder().encode('Bob message');
      const [encB, bobState3] = ratchetEncrypt(bobState2, msgB);
      
      // Alice receives Bob's message
      const [decB, aliceState3] = ratchetDecrypt(aliceState2, encB);
      expect(new TextDecoder().decode(decB)).toBe('Bob message');
      
      // They can continue communicating
      const msgA2 = new TextEncoder().encode('Alice follow-up');
      const [encA2, aliceState4] = ratchetEncrypt(aliceState3, msgA2);
      const [decA2, bobState4] = ratchetDecrypt(bobState3, encA2);
      expect(new TextDecoder().decode(decA2)).toBe('Alice follow-up');
    });

    it('should handle message reordering in network', () => {
      // Alice sends 5 messages
      const messages = Array.from({ length: 5 }, (_, i) => `Message ${i}`);
      let currentAliceState = aliceState;
      const encrypted: Uint8Array[] = [];
      
      for (const msg of messages) {
        const msgBytes = new TextEncoder().encode(msg);
        const [enc, newState] = ratchetEncrypt(currentAliceState, msgBytes);
        encrypted.push(enc);
        currentAliceState = newState;
      }
      
      // Bob receives in scrambled order: 2, 4, 0, 3, 1
      const order = [2, 4, 0, 3, 1];
      let currentBobState = bobState;
      
      for (const index of order) {
        const [dec, newState] = ratchetDecrypt(currentBobState, encrypted[index]);
        expect(new TextDecoder().decode(dec)).toBe(messages[index]);
        currentBobState = newState;
      }
      
      // All messages received successfully
      expect(currentBobState.receiveMessageCounter).toBe(5);
      expect(currentBobState.skippedMessageKeys.size).toBe(0);
    });
  });

  describe('Complex scenarios', () => {
    it('should handle complex multi-round exchange with out-of-order delivery', () => {
      const allMessages: Array<{ sender: string; content: string; encrypted: Uint8Array }> = [];
      let currentAliceState = aliceState;
      let currentBobState = bobState;
      
      // Round 1: Alice sends 2 messages
      for (let i = 0; i < 2; i++) {
        const msg = `Alice R1 M${i}`;
        const msgBytes = new TextEncoder().encode(msg);
        const [enc, newState] = ratchetEncrypt(currentAliceState, msgBytes);
        allMessages.push({ sender: 'Alice', content: msg, encrypted: enc });
        currentAliceState = newState;
      }
      
      // Bob receives only first message
      const [_, bobState2] = ratchetDecrypt(currentBobState, allMessages[0].encrypted);
      currentBobState = bobState2;
      
      // Round 2: Bob replies with 2 messages
      for (let i = 0; i < 2; i++) {
        const msg = `Bob R1 M${i}`;
        const msgBytes = new TextEncoder().encode(msg);
        const [enc, newState] = ratchetEncrypt(currentBobState, msgBytes);
        allMessages.push({ sender: 'Bob', content: msg, encrypted: enc });
        currentBobState = newState;
      }
      
      // Alice receives Bob's messages and sends more
      const [__, aliceState2] = ratchetDecrypt(currentAliceState, allMessages[2].encrypted);
      const [___, aliceState3] = ratchetDecrypt(aliceState2, allMessages[3].encrypted);
      currentAliceState = aliceState3;
      
      // Round 3: Alice sends 2 more messages (new chain)
      for (let i = 0; i < 2; i++) {
        const msg = `Alice R2 M${i}`;
        const msgBytes = new TextEncoder().encode(msg);
        const [enc, newState] = ratchetEncrypt(currentAliceState, msgBytes);
        allMessages.push({ sender: 'Alice', content: msg, encrypted: enc });
        currentAliceState = newState;
      }
      
      // Bob receives remaining messages out of order: 5, 1, 4
      const remaining = [5, 1, 4];
      for (const index of remaining) {
        const [dec, newState] = ratchetDecrypt(currentBobState, allMessages[index].encrypted);
        expect(new TextDecoder().decode(dec)).toBe(allMessages[index].content);
        currentBobState = newState;
      }
    });

    it('should maintain security properties under stress', () => {
      // Rapid fire exchange with multiple DH ratchets
      let currentAliceState = aliceState;
      let currentBobState = bobState;
      let totalMessages = 0;
      
      for (let round = 0; round < 3; round++) {
        // Alice burst
        for (let i = 0; i < 3; i++) {
          const msg = new TextEncoder().encode(`Alice R${round} M${i}`);
          const [enc, newAliceState] = ratchetEncrypt(currentAliceState, msg);
          const [dec, newBobState] = ratchetDecrypt(currentBobState, enc);
          expect(new TextDecoder().decode(dec)).toBe(`Alice R${round} M${i}`);
          currentAliceState = newAliceState;
          currentBobState = newBobState;
          totalMessages++;
        }
        
        // Bob burst (triggers DH ratchet)
        for (let i = 0; i < 2; i++) {
          const msg = new TextEncoder().encode(`Bob R${round} M${i}`);
          const [enc, newBobState] = ratchetEncrypt(currentBobState, msg);
          const [dec, newAliceState] = ratchetDecrypt(currentAliceState, enc);
          expect(new TextDecoder().decode(dec)).toBe(`Bob R${round} M${i}`);
          currentBobState = newBobState;
          currentAliceState = newAliceState;
          totalMessages++;
        }
      }
      
      expect(totalMessages).toBe(15);
      
      // Verify forward secrecy - old messages can't be decrypted
      const oldMsg = new TextEncoder().encode('Old message');
      const [oldEnc, _] = ratchetEncrypt(aliceState, oldMsg);
      expect(() => {
        ratchetDecrypt(currentBobState, oldEnc);
      }).toThrow(/Decryption failed/);
    });
  });
});