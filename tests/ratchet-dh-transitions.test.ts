/**
 * Tests for Double Ratchet Protocol DH transitions
 */

import * as nacl from 'tweetnacl';
import {
  initializeRatchet,
  ratchetEncrypt,
  ratchetDecrypt
} from '../src/utils/ratchet';
import { RatchetState } from '../src/types/ratchet';
import { KeyPair } from '../src/types';

describe('Ratchet Protocol - DH Transitions', () => {
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

  describe('Single DH per chain', () => {
    it('should include ephemeral key only on first message of new sending chain', () => {
      // Alice sends first message (includes ephemeral)
      const msg1 = new TextEncoder().encode('First in chain');
      const [enc1, aliceState2] = ratchetEncrypt(aliceState, msg1);
      
      // Check that ephemeral key is included (version byte = 0x01)
      expect(enc1[0]).toBe(0x01);
      
      // Extract the ephemeral key from first message
      const ephemeral1 = enc1.slice(1, 33);
      
      // Alice sends second message in same chain (should reuse ephemeral)
      const msg2 = new TextEncoder().encode('Second in chain');
      const [enc2, aliceState3] = ratchetEncrypt(aliceState2, msg2);
      
      // Check that same ephemeral key is included
      expect(enc2[0]).toBe(0x01);
      const ephemeral2 = enc2.slice(1, 33);
      expect(ephemeral2).toEqual(ephemeral1);
      
      // Alice sends third message in same chain
      const msg3 = new TextEncoder().encode('Third in chain');
      const [enc3, aliceState4] = ratchetEncrypt(aliceState3, msg3);
      
      // Should still have same ephemeral
      const ephemeral3 = enc3.slice(1, 33);
      expect(ephemeral3).toEqual(ephemeral1);
      
      // Verify counters are incrementing within the chain
      // Counter is at bytes 37-40 (after version + ephemeral + previous counter)
      const counter1 = new DataView(enc1.buffer, enc1.byteOffset + 37, 4).getUint32(0, false);
      const counter2 = new DataView(enc2.buffer, enc2.byteOffset + 37, 4).getUint32(0, false);
      const counter3 = new DataView(enc3.buffer, enc3.byteOffset + 37, 4).getUint32(0, false);
      
      expect(counter1).toBe(0);
      expect(counter2).toBe(1);
      expect(counter3).toBe(2);
    });

    it('should only perform DH ratchet on receiving new ephemeral key', () => {
      // Alice sends multiple messages
      const msg1 = new TextEncoder().encode('Alice 1');
      const msg2 = new TextEncoder().encode('Alice 2');
      const msg3 = new TextEncoder().encode('Alice 3');
      
      const [enc1, aliceState2] = ratchetEncrypt(aliceState, msg1);
      const [enc2, aliceState3] = ratchetEncrypt(aliceState2, msg2);
      const [enc3, aliceState4] = ratchetEncrypt(aliceState3, msg3);
      
      // Bob receives first message - should trigger DH setup
      const [_, bobState2] = ratchetDecrypt(bobState, enc1);
      const rootKeyAfterFirst = new Uint8Array(bobState2.rootKey);
      
      // Bob receives second message - no new DH, root key unchanged
      const [__, bobState3] = ratchetDecrypt(bobState2, enc2);
      expect(bobState3.rootKey).toEqual(rootKeyAfterFirst);
      
      // Bob receives third message - still no new DH
      const [___, bobState4] = ratchetDecrypt(bobState3, enc3);
      expect(bobState4.rootKey).toEqual(rootKeyAfterFirst);
      
      // Now Bob replies, which should trigger new DH
      const msgB = new TextEncoder().encode('Bob reply');
      const [encB, bobState5] = ratchetEncrypt(bobState4, msgB);
      
      // Bob's root key should change after his own DH ratchet
      expect(bobState5.rootKey).not.toEqual(rootKeyAfterFirst);
    });

    it('should reset message counter on new sending chain', () => {
      // Alice sends messages
      const msg1 = new TextEncoder().encode('Alice 1');
      const msg2 = new TextEncoder().encode('Alice 2');
      
      const [enc1, aliceState2] = ratchetEncrypt(aliceState, msg1);
      const [enc2, aliceState3] = ratchetEncrypt(aliceState2, msg2);
      
      // Check Alice's counter incremented
      expect(aliceState2.sendMessageCounter).toBe(1);
      expect(aliceState3.sendMessageCounter).toBe(2);
      
      // Bob receives and replies
      const [_, bobState2] = ratchetDecrypt(bobState, enc1);
      const [__, bobState3] = ratchetDecrypt(bobState2, enc2);
      
      const msgB = new TextEncoder().encode('Bob reply');
      const [encB, bobState4] = ratchetEncrypt(bobState3, msgB);
      
      // Bob's counter should start at 0 for his new chain
      expect(bobState4.sendMessageCounter).toBe(1);
      
      // Alice receives Bob's message
      const [___, aliceState4] = ratchetDecrypt(aliceState3, encB);
      
      // Alice sends new message (new sending chain after DH)
      const msg3 = new TextEncoder().encode('Alice 3');
      const [enc3, aliceState5] = ratchetEncrypt(aliceState4, msg3);
      
      // Alice's counter should reset to 1 (0 + 1 after sending)
      expect(aliceState5.sendMessageCounter).toBe(1);
      expect(aliceState5.previousSendCounter).toBe(2); // Previous chain had 2 messages
    });
  });

  describe('Simultaneous ratchets', () => {
    it('should handle sequential message exchange', () => {
      // Alice sends first message
      const msgA = new TextEncoder().encode('Alice initial');
      const [encA, aliceState2] = ratchetEncrypt(aliceState, msgA);
      
      // Bob receives Alice's message
      const [decA, bobState2] = ratchetDecrypt(bobState, encA);
      expect(new TextDecoder().decode(decA)).toBe('Alice initial');
      
      // Bob sends response (triggers DH ratchet)
      const msgB = new TextEncoder().encode('Bob response');
      const [encB, bobState3] = ratchetEncrypt(bobState2, msgB);
      
      // Alice receives Bob's message (triggers her DH ratchet)
      const [decB, aliceState3] = ratchetDecrypt(aliceState2, encB);
      expect(new TextDecoder().decode(decB)).toBe('Bob response');
      
      // Both should have performed DH ratchets
      expect(aliceState3.theirLatestEphemeralPublicKey).not.toBeNull();
      expect(bobState3.theirLatestEphemeralPublicKey).not.toBeNull();
      
      // Now they can continue with proper ratcheted communication
      const msgA2 = new TextEncoder().encode('Alice follow-up');
      const [encA2, aliceState4] = ratchetEncrypt(aliceState3, msgA2);
      
      const [decA2, bobState4] = ratchetDecrypt(bobState3, encA2);
      expect(new TextDecoder().decode(decA2)).toBe('Alice follow-up');
      
      const msgB2 = new TextEncoder().encode('Bob follow-up');
      const [encB2, bobState5] = ratchetEncrypt(bobState4, msgB2);
      
      const [decB2, aliceState5] = ratchetDecrypt(aliceState4, encB2);
      expect(new TextDecoder().decode(decB2)).toBe('Bob follow-up');
    });

    it('should maintain separate sending chains during burst communication', () => {
      // Alice sends multiple messages in a burst
      const aliceMessages = ['A1', 'A2', 'A3'];
      
      let currentAliceState = aliceState;
      const aliceEncrypted: Uint8Array[] = [];
      for (const msg of aliceMessages) {
        const msgBytes = new TextEncoder().encode(msg);
        const [enc, newState] = ratchetEncrypt(currentAliceState, msgBytes);
        aliceEncrypted.push(enc);
        currentAliceState = newState;
      }
      
      // Bob receives Alice's burst
      let currentBobState = bobState;
      for (let i = 0; i < aliceEncrypted.length; i++) {
        const [dec, newState] = ratchetDecrypt(currentBobState, aliceEncrypted[i]);
        expect(new TextDecoder().decode(dec)).toBe(aliceMessages[i]);
        currentBobState = newState;
      }
      
      // Bob sends his burst in response
      const bobMessages = ['B1', 'B2', 'B3'];
      const bobEncrypted: Uint8Array[] = [];
      for (const msg of bobMessages) {
        const msgBytes = new TextEncoder().encode(msg);
        const [enc, newState] = ratchetEncrypt(currentBobState, msgBytes);
        bobEncrypted.push(enc);
        currentBobState = newState;
      }
      
      // Alice receives Bob's burst
      for (let i = 0; i < bobEncrypted.length; i++) {
        const [dec, newState] = ratchetDecrypt(currentAliceState, bobEncrypted[i]);
        expect(new TextDecoder().decode(dec)).toBe(bobMessages[i]);
        currentAliceState = newState;
      }
      
      // Both should be able to continue
      const msgA4 = new TextEncoder().encode('A4');
      const [encA4, aliceState5] = ratchetEncrypt(currentAliceState, msgA4);
      const [decA4, bobState5] = ratchetDecrypt(currentBobState, encA4);
      expect(new TextDecoder().decode(decA4)).toBe('A4');
    });
  });

  describe('Old DH replay protection', () => {
    it('should reject messages with outdated ephemeral keys', () => {
      // Alice sends initial message
      const msg1 = new TextEncoder().encode('Message 1');
      const [enc1, aliceState2] = ratchetEncrypt(aliceState, msg1);
      const [_, bobState2] = ratchetDecrypt(bobState, enc1);
      
      // Bob replies (triggers DH ratchet)
      const msgB = new TextEncoder().encode('Bob reply');
      const [encB, bobState3] = ratchetEncrypt(bobState2, msgB);
      const [__, aliceState3] = ratchetDecrypt(aliceState2, encB);
      
      // Alice sends with new ephemeral
      const msg2 = new TextEncoder().encode('Message 2');
      const [enc2, aliceState4] = ratchetEncrypt(aliceState3, msg2);
      const [___, bobState4] = ratchetDecrypt(bobState3, enc2);
      
      // Try to replay the first message (old ephemeral)
      expect(() => {
        ratchetDecrypt(bobState4, enc1);
      }).toThrow(/Decryption failed/);
    });

    it('should reject reuse of old ephemeral keys after progression', () => {
      // Establish bidirectional communication
      const msg1 = new TextEncoder().encode('Alice 1');
      const [enc1, aliceState2] = ratchetEncrypt(aliceState, msg1);
      const [_, bobState2] = ratchetDecrypt(bobState, enc1);
      
      const msg2 = new TextEncoder().encode('Bob 1');
      const [enc2, bobState3] = ratchetEncrypt(bobState2, msg2);
      const [__, aliceState3] = ratchetDecrypt(aliceState2, enc2);
      
      const msg3 = new TextEncoder().encode('Alice 2');
      const [enc3, aliceState4] = ratchetEncrypt(aliceState3, msg3);
      const [___, bobState4] = ratchetDecrypt(bobState3, enc3);
      
      // Store Bob's current state
      const bobStateSnapshot = bobState4;
      
      // Bob sends more messages
      const msg4 = new TextEncoder().encode('Bob 2');
      const [enc4, bobState5] = ratchetEncrypt(bobState4, msg4);
      const [____, aliceState5] = ratchetDecrypt(aliceState4, enc4);
      
      // Try to replay an old message with old ephemeral
      expect(() => {
        ratchetDecrypt(aliceState5, enc2);
      }).toThrow(/Decryption failed/);
    });
  });

  describe('Chain continuity', () => {
    it('should maintain chain continuity across DH ratchets', () => {
      const messages: string[] = [];
      let currentAliceState = aliceState;
      let currentBobState = bobState;
      
      // Multiple rounds of back-and-forth
      for (let round = 0; round < 3; round++) {
        // Alice sends
        for (let i = 0; i < 2; i++) {
          const msg = `Alice R${round}M${i}`;
          messages.push(msg);
          const msgBytes = new TextEncoder().encode(msg);
          const [enc, newState] = ratchetEncrypt(currentAliceState, msgBytes);
          currentAliceState = newState;
          
          const [dec, newBobState] = ratchetDecrypt(currentBobState, enc);
          currentBobState = newBobState;
          expect(new TextDecoder().decode(dec)).toBe(msg);
        }
        
        // Bob sends
        for (let i = 0; i < 2; i++) {
          const msg = `Bob R${round}M${i}`;
          messages.push(msg);
          const msgBytes = new TextEncoder().encode(msg);
          const [enc, newState] = ratchetEncrypt(currentBobState, msgBytes);
          currentBobState = newState;
          
          const [dec, newAliceState] = ratchetDecrypt(currentAliceState, enc);
          currentAliceState = newAliceState;
          expect(new TextDecoder().decode(dec)).toBe(msg);
        }
      }
      
      // Verify all messages were sent and received
      expect(messages.length).toBe(12);
    });

    it('should track previous send counter across ratchets', () => {
      // Alice sends 3 messages
      let currentAliceState = aliceState;
      const aliceMessages: Uint8Array[] = [];
      for (let i = 0; i < 3; i++) {
        const msg = new TextEncoder().encode(`Alice ${i}`);
        const [enc, newState] = ratchetEncrypt(currentAliceState, msg);
        aliceMessages.push(enc);
        currentAliceState = newState;
      }
      
      expect(currentAliceState.sendMessageCounter).toBe(3);
      expect(currentAliceState.previousSendCounter).toBe(0);
      
      // Bob receives Alice's messages first
      let currentBobState = bobState;
      for (const enc of aliceMessages) {
        const [_, newState] = ratchetDecrypt(currentBobState, enc);
        currentBobState = newState;
      }
      
      // Bob sends a message (triggers Alice's DH ratchet when she receives it)
      const msgB = new TextEncoder().encode('Bob message');
      const [encB, bobState2] = ratchetEncrypt(currentBobState, msgB);
      
      // Alice receives and then sends again
      const [_, aliceState2] = ratchetDecrypt(currentAliceState, encB);
      const msgA = new TextEncoder().encode('Alice after ratchet');
      const [encA, aliceState3] = ratchetEncrypt(aliceState2, msgA);
      
      // Previous send counter should be 3 (from before the ratchet)
      expect(aliceState3.previousSendCounter).toBe(3);
      expect(aliceState3.sendMessageCounter).toBe(1);
    });
  });
});