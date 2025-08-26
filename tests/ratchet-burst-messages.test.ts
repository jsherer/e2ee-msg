/**
 * Tests for ratchet protocol handling of burst messages (multiple messages before reply)
 */

import * as nacl from 'tweetnacl';
import {
  initializeRatchet,
  ratchetEncrypt,
  ratchetDecrypt
} from '../src/utils/ratchet';
import { RatchetState } from '../src/types/ratchet';

describe('Ratchet Protocol - Burst Messages', () => {
  beforeEach(() => {
    // Clear localStorage to ensure clean state
    global.localStorage.clear();
  });

  describe('One-way message bursts', () => {
    it('should handle multiple messages from sender before receiver replies', () => {
      const alice = nacl.box.keyPair();
      const bob = nacl.box.keyPair();

      // Initialize ratchet states
      const aliceState = initializeRatchet(alice, bob.publicKey);
      const bobState = initializeRatchet(bob, alice.publicKey);

      // Alice sends 3 messages before Bob replies
      const messages = [
        'First message from Alice',
        'Second message from Alice', 
        'Third message from Alice'
      ];

      const encryptedMessages: Uint8Array[] = [];
      let currentAliceState = aliceState;

      // Alice sends all messages
      for (const msg of messages) {
        const plaintext = new TextEncoder().encode(msg);
        const [encrypted, newState] = ratchetEncrypt(currentAliceState, plaintext);
        encryptedMessages.push(encrypted);
        currentAliceState = newState;
      }

      // Bob receives and decrypts all messages
      let currentBobState = bobState;
      for (let i = 0; i < encryptedMessages.length; i++) {
        const [decrypted, newState] = ratchetDecrypt(currentBobState, encryptedMessages[i]);
        expect(new TextDecoder().decode(decrypted)).toBe(messages[i]);
        currentBobState = newState;
      }

      // Now Bob can reply to Alice
      const bobReply = new TextEncoder().encode('Reply from Bob after receiving 3 messages');
      const [encryptedReply, bobStateAfterReply] = ratchetEncrypt(currentBobState, bobReply);

      // Alice can decrypt Bob's reply
      const [decryptedReply, aliceStateAfterReply] = ratchetDecrypt(currentAliceState, encryptedReply);
      expect(new TextDecoder().decode(decryptedReply)).toBe('Reply from Bob after receiving 3 messages');

      // Conversation can continue normally
      const aliceFollowup = new TextEncoder().encode('Thanks for the reply, Bob!');
      const [encryptedFollowup, aliceStateFinal] = ratchetEncrypt(aliceStateAfterReply, aliceFollowup);
      const [decryptedFollowup, bobStateFinal] = ratchetDecrypt(bobStateAfterReply, encryptedFollowup);
      expect(new TextDecoder().decode(decryptedFollowup)).toBe('Thanks for the reply, Bob!');
    });

    it('should handle out-of-order delivery of burst messages', () => {
      const alice = nacl.box.keyPair();
      const bob = nacl.box.keyPair();

      const aliceState = initializeRatchet(alice, bob.publicKey);
      const bobState = initializeRatchet(bob, alice.publicKey);

      // Alice sends 5 messages
      const messages = [
        'Message 1',
        'Message 2',
        'Message 3',
        'Message 4',
        'Message 5'
      ];

      const encryptedMessages: Uint8Array[] = [];
      let currentAliceState = aliceState;

      for (const msg of messages) {
        const plaintext = new TextEncoder().encode(msg);
        const [encrypted, newState] = ratchetEncrypt(currentAliceState, plaintext);
        encryptedMessages.push(encrypted);
        currentAliceState = newState;
      }

      // Bob receives messages out of order: 1, 3, 2, 5, 4
      const receiveOrder = [0, 2, 1, 4, 3];
      let currentBobState = bobState;

      // Receive first message normally
      const [dec1, bobState1] = ratchetDecrypt(currentBobState, encryptedMessages[0]);
      expect(new TextDecoder().decode(dec1)).toBe('Message 1');
      currentBobState = bobState1;

      // Try to receive message 3 (should handle skipped message 2)
      const [dec3, bobState3] = ratchetDecrypt(currentBobState, encryptedMessages[2]);
      expect(new TextDecoder().decode(dec3)).toBe('Message 3');
      currentBobState = bobState3;

      // Now receive message 2 (out of order)
      const [dec2, bobState2] = ratchetDecrypt(currentBobState, encryptedMessages[1]);
      expect(new TextDecoder().decode(dec2)).toBe('Message 2');
      currentBobState = bobState2;

      // Receive message 5 (skipping 4)
      const [dec5, bobState5] = ratchetDecrypt(currentBobState, encryptedMessages[4]);
      expect(new TextDecoder().decode(dec5)).toBe('Message 5');
      currentBobState = bobState5;

      // Finally receive message 4
      const [dec4, bobState4] = ratchetDecrypt(currentBobState, encryptedMessages[3]);
      expect(new TextDecoder().decode(dec4)).toBe('Message 4');
      currentBobState = bobState4;

      // Bob should still be able to reply
      const bobReply = new TextEncoder().encode('Got all messages despite reordering');
      const [encryptedReply, bobStateFinal] = ratchetEncrypt(currentBobState, bobReply);
      const [decryptedReply, aliceStateFinal] = ratchetDecrypt(currentAliceState, encryptedReply);
      expect(new TextDecoder().decode(decryptedReply)).toBe('Got all messages despite reordering');
    });

    it('should handle alternating bursts from both parties', () => {
      const alice = nacl.box.keyPair();
      const bob = nacl.box.keyPair();

      let aliceState = initializeRatchet(alice, bob.publicKey);
      let bobState = initializeRatchet(bob, alice.publicKey);

      // Alice sends 2 messages
      const alice1 = new TextEncoder().encode('Alice burst 1 - message 1');
      const [enc1, aliceState1] = ratchetEncrypt(aliceState, alice1);
      
      const alice2 = new TextEncoder().encode('Alice burst 1 - message 2');
      const [enc2, aliceState2] = ratchetEncrypt(aliceState1, alice2);

      // Bob receives both
      const [dec1, bobState1] = ratchetDecrypt(bobState, enc1);
      const [dec2, bobState2] = ratchetDecrypt(bobState1, enc2);
      
      expect(new TextDecoder().decode(dec1)).toBe('Alice burst 1 - message 1');
      expect(new TextDecoder().decode(dec2)).toBe('Alice burst 1 - message 2');

      // Bob sends 3 messages
      const bob1 = new TextEncoder().encode('Bob burst - message 1');
      const [encB1, bobState3] = ratchetEncrypt(bobState2, bob1);
      
      const bob2 = new TextEncoder().encode('Bob burst - message 2');
      const [encB2, bobState4] = ratchetEncrypt(bobState3, bob2);
      
      const bob3 = new TextEncoder().encode('Bob burst - message 3');
      const [encB3, bobState5] = ratchetEncrypt(bobState4, bob3);

      // Alice receives all 3
      const [decB1, aliceState3] = ratchetDecrypt(aliceState2, encB1);
      const [decB2, aliceState4] = ratchetDecrypt(aliceState3, encB2);
      const [decB3, aliceState5] = ratchetDecrypt(aliceState4, encB3);
      
      expect(new TextDecoder().decode(decB1)).toBe('Bob burst - message 1');
      expect(new TextDecoder().decode(decB2)).toBe('Bob burst - message 2');
      expect(new TextDecoder().decode(decB3)).toBe('Bob burst - message 3');

      // Alice sends another burst
      const alice3 = new TextEncoder().encode('Alice burst 2 - message 1');
      const [enc3, aliceState6] = ratchetEncrypt(aliceState5, alice3);
      
      const alice4 = new TextEncoder().encode('Alice burst 2 - message 2');
      const [enc4, aliceState7] = ratchetEncrypt(aliceState6, alice4);

      // Bob receives
      const [dec3, bobState6] = ratchetDecrypt(bobState5, enc3);
      const [dec4, bobState7] = ratchetDecrypt(bobState6, enc4);
      
      expect(new TextDecoder().decode(dec3)).toBe('Alice burst 2 - message 1');
      expect(new TextDecoder().decode(dec4)).toBe('Alice burst 2 - message 2');
    });

    it('should maintain forward secrecy across burst messages', () => {
      const alice = nacl.box.keyPair();
      const bob = nacl.box.keyPair();

      const aliceState = initializeRatchet(alice, bob.publicKey);
      const bobState = initializeRatchet(bob, alice.publicKey);

      // Alice sends 3 messages
      let currentAliceState = aliceState;
      const aliceStates: RatchetState[] = [aliceState];
      const encryptedMessages: Uint8Array[] = [];

      for (let i = 1; i <= 3; i++) {
        const msg = new TextEncoder().encode(`Message ${i}`);
        const [encrypted, newState] = ratchetEncrypt(currentAliceState, msg);
        encryptedMessages.push(encrypted);
        aliceStates.push(newState);
        currentAliceState = newState;
      }

      // Each message should have different chain keys
      expect(aliceStates[0].sendingChainKey).not.toEqual(aliceStates[1].sendingChainKey);
      expect(aliceStates[1].sendingChainKey).not.toEqual(aliceStates[2].sendingChainKey);
      expect(aliceStates[2].sendingChainKey).not.toEqual(aliceStates[3].sendingChainKey);

      // Bob receives all messages
      let currentBobState = bobState;
      for (const encrypted of encryptedMessages) {
        const [decrypted, newState] = ratchetDecrypt(currentBobState, encrypted);
        currentBobState = newState;
      }

      // Bob's receiving chain key should have advanced
      expect(bobState.receivingChainKey).not.toEqual(currentBobState.receivingChainKey);
    });
  });

  describe('Edge cases', () => {
    it('should handle extremely large burst (100 messages)', () => {
      const alice = nacl.box.keyPair();
      const bob = nacl.box.keyPair();

      let aliceState = initializeRatchet(alice, bob.publicKey);
      let bobState = initializeRatchet(bob, alice.publicKey);

      // Alice sends 100 messages
      const messageCount = 100;
      const encryptedMessages: Uint8Array[] = [];

      for (let i = 0; i < messageCount; i++) {
        const msg = new TextEncoder().encode(`Burst message ${i}`);
        const [encrypted, newState] = ratchetEncrypt(aliceState, msg);
        encryptedMessages.push(encrypted);
        aliceState = newState;
      }

      // Bob receives all 100 messages
      for (let i = 0; i < messageCount; i++) {
        const [decrypted, newState] = ratchetDecrypt(bobState, encryptedMessages[i]);
        expect(new TextDecoder().decode(decrypted)).toBe(`Burst message ${i}`);
        bobState = newState;
      }

      // Bob can still reply
      const reply = new TextEncoder().encode('Received all 100 messages!');
      const [encryptedReply, bobStateFinal] = ratchetEncrypt(bobState, reply);
      const [decryptedReply, aliceStateFinal] = ratchetDecrypt(aliceState, encryptedReply);
      expect(new TextDecoder().decode(decryptedReply)).toBe('Received all 100 messages!');
    });

    it('should handle zero-length burst (no messages between DH ratchets)', () => {
      const alice = nacl.box.keyPair();
      const bob = nacl.box.keyPair();

      const aliceState = initializeRatchet(alice, bob.publicKey);
      const bobState = initializeRatchet(bob, alice.publicKey);

      // Alice sends one message
      const msg1 = new TextEncoder().encode('First');
      const [enc1, aliceState1] = ratchetEncrypt(aliceState, msg1);
      const [dec1, bobState1] = ratchetDecrypt(bobState, enc1);

      // Bob immediately replies without sending any messages in between
      const reply1 = new TextEncoder().encode('Reply');
      const [encR1, bobState2] = ratchetEncrypt(bobState1, reply1);
      const [decR1, aliceState2] = ratchetDecrypt(aliceState1, encR1);

      // Alice replies again
      const msg2 = new TextEncoder().encode('Second');
      const [enc2, aliceState3] = ratchetEncrypt(aliceState2, msg2);
      const [dec2, bobState3] = ratchetDecrypt(bobState2, enc2);

      expect(new TextDecoder().decode(dec1)).toBe('First');
      expect(new TextDecoder().decode(decR1)).toBe('Reply');
      expect(new TextDecoder().decode(dec2)).toBe('Second');
    });
  });
});
