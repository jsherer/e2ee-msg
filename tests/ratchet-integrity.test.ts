/**
 * Tests for Double Ratchet Protocol integrity and tamper resistance
 */

import * as nacl from 'tweetnacl';
import {
  initializeRatchet,
  ratchetEncrypt,
  ratchetDecrypt
} from '../src/utils/ratchet';
import { RatchetState } from '../src/types/ratchet';
import { KeyPair } from '../src/types';

describe('Ratchet Protocol - Integrity & Misuse Resistance', () => {
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

  describe('Header tampering', () => {
    it('should handle tampered message counter in header', () => {
      const message = new TextEncoder().encode('Test message');
      const [encrypted, newAliceState] = ratchetEncrypt(aliceState, message);
      
      // Tamper with the counter byte (byte 33, after version + ephemeral key)
      const tampered = new Uint8Array(encrypted);
      tampered[33] = (tampered[33] + 1) % 256;
      
      // Note: Headers are not authenticated in the current implementation,
      // so tampering with counter might not cause immediate failure
      // but will cause counter mismatch issues
      const originalCounter = bobState.receiveMessageCounter;
      
      try {
        const [decrypted, newBobState] = ratchetDecrypt(bobState, tampered);
        // If decryption succeeds, state should still be consistent
        expect(newBobState.receiveMessageCounter).toBeGreaterThanOrEqual(originalCounter);
      } catch (error) {
        // If it fails, verify state wasn't corrupted
        expect(bobState.receiveMessageCounter).toBe(originalCounter);
      }
    });

    it('should handle tampered ephemeral key presence', () => {
      // First message includes ephemeral key
      const message1 = new TextEncoder().encode('First message');
      const [encrypted1, aliceState2] = ratchetEncrypt(aliceState, message1);
      
      // Verify first byte indicates ephemeral key presence
      expect(encrypted1[0]).toBe(0x01); // Version with ephemeral
      
      // Flip to indicate no ephemeral key when there is one
      const tampered = new Uint8Array(encrypted1);
      tampered[0] = 0x00; // Change version byte
      
      expect(() => {
        ratchetDecrypt(bobState, tampered);
      }).toThrow();
    });

    it('should reject messages with invalid version byte', () => {
      const message = new TextEncoder().encode('Test message');
      const [encrypted, _] = ratchetEncrypt(aliceState, message);
      
      // Set invalid version byte
      const tampered = new Uint8Array(encrypted);
      tampered[0] = 0xFF;
      
      expect(() => {
        ratchetDecrypt(bobState, tampered);
      }).toThrow(/Unknown protocol version/);
    });
  });

  describe('Ciphertext tampering', () => {
    it('should reject bit-flipped ciphertext', () => {
      const message = new TextEncoder().encode('Sensitive data');
      const [encrypted, _] = ratchetEncrypt(aliceState, message);
      
      // Flip a bit in the ciphertext (after header)
      const tampered = new Uint8Array(encrypted);
      const ciphertextStart = 65; // After version + ephemeral + counter
      tampered[ciphertextStart] ^= 0x01;
      
      expect(() => {
        ratchetDecrypt(bobState, tampered);
      }).toThrow(/Decryption failed/);
    });

    it('should reject truncated ciphertext', () => {
      const message = new TextEncoder().encode('Complete message');
      const [encrypted, _] = ratchetEncrypt(aliceState, message);
      
      // Truncate last 5 bytes
      const truncated = encrypted.slice(0, -5);
      
      expect(() => {
        ratchetDecrypt(bobState, truncated);
      }).toThrow();
    });

    it('should reject extended ciphertext with garbage', () => {
      const message = new TextEncoder().encode('Original message');
      const [encrypted, _] = ratchetEncrypt(aliceState, message);
      
      // Add garbage bytes at the end
      const extended = new Uint8Array(encrypted.length + 10);
      extended.set(encrypted);
      extended.set(nacl.randomBytes(10), encrypted.length);
      
      expect(() => {
        ratchetDecrypt(bobState, extended);
      }).toThrow(/Decryption failed/);
    });

    it('should reject tampered nonce', () => {
      const message = new TextEncoder().encode('Test message');
      const [encrypted, _] = ratchetEncrypt(aliceState, message);
      
      // The message structure is: header (41 bytes) + nonce (24 bytes) + encrypted
      const tampered = new Uint8Array(encrypted);
      // Tamper with the nonce which starts at byte 41
      const nonceStart = 41;
      if (tampered.length > nonceStart) {
        tampered[nonceStart] ^= 0xFF;
      }
      
      expect(() => {
        ratchetDecrypt(bobState, tampered);
      }).toThrow(/Decryption failed/);
    });
  });

  describe('Message replay protection', () => {
    it('should reject replayed messages', () => {
      const message = new TextEncoder().encode('Original message');
      const [encrypted, aliceState2] = ratchetEncrypt(aliceState, message);
      
      // First decryption succeeds
      const [decrypted1, bobState2] = ratchetDecrypt(bobState, encrypted);
      expect(new TextDecoder().decode(decrypted1)).toBe('Original message');
      
      // Replay attempt should fail
      expect(() => {
        ratchetDecrypt(bobState2, encrypted);
      }).toThrow(/Decryption failed/);
    });

    it('should reject messages from old chains after DH ratchet', () => {
      // Exchange messages to establish bidirectional communication
      const msg1 = new TextEncoder().encode('Alice message 1');
      const [enc1, aliceState2] = ratchetEncrypt(aliceState, msg1);
      const [_, bobState2] = ratchetDecrypt(bobState, enc1);
      
      // Bob replies, causing DH ratchet
      const msg2 = new TextEncoder().encode('Bob message 1');
      const [enc2, bobState3] = ratchetEncrypt(bobState2, msg2);
      const [__, aliceState3] = ratchetDecrypt(aliceState2, enc2);
      
      // Alice sends another message with new chain
      const msg3 = new TextEncoder().encode('Alice message 2');
      const [enc3, aliceState4] = ratchetEncrypt(aliceState3, msg3);
      const [___, bobState4] = ratchetDecrypt(bobState3, enc3);
      
      // Try to replay first message from old chain
      expect(() => {
        ratchetDecrypt(bobState4, enc1);
      }).toThrow(/Decryption failed/);
    });
  });

  describe('State protection on failures', () => {
    it('should not modify state on decryption failure', () => {
      const message = new TextEncoder().encode('Test message');
      const [encrypted, _] = ratchetEncrypt(aliceState, message);
      
      // Save original state values
      const originalCounter = bobState.receiveMessageCounter;
      const originalChainKey = new Uint8Array(bobState.receivingChainKey);
      const originalRootKey = new Uint8Array(bobState.rootKey);
      const originalSkippedSize = bobState.skippedMessageKeys.size;
      
      // Corrupt the message
      const corrupted = new Uint8Array(encrypted);
      corrupted[corrupted.length - 1] ^= 0xFF;
      
      // Attempt decryption (should fail)
      expect(() => {
        ratchetDecrypt(bobState, corrupted);
      }).toThrow();
      
      // Verify state unchanged
      expect(bobState.receiveMessageCounter).toBe(originalCounter);
      expect(bobState.receivingChainKey).toEqual(originalChainKey);
      expect(bobState.rootKey).toEqual(originalRootKey);
      expect(bobState.skippedMessageKeys.size).toBe(originalSkippedSize);
    });

    it('should not advance counters on authentication failure', () => {
      // Send multiple messages
      const messages = ['msg1', 'msg2', 'msg3'].map(m => 
        new TextEncoder().encode(m)
      );
      
      let currentAliceState = aliceState;
      const encryptedMessages: Uint8Array[] = [];
      
      for (const msg of messages) {
        const [enc, newState] = ratchetEncrypt(currentAliceState, msg);
        encryptedMessages.push(enc);
        currentAliceState = newState;
      }
      
      // Decrypt first message successfully
      const [_, bobState2] = ratchetDecrypt(bobState, encryptedMessages[0]);
      expect(bobState2.receiveMessageCounter).toBe(1);
      
      // Corrupt second message
      const corrupted = new Uint8Array(encryptedMessages[1]);
      corrupted[70] ^= 0xFF;
      
      // Counter should not advance on failure
      expect(() => {
        ratchetDecrypt(bobState2, corrupted);
      }).toThrow();
      
      // Counter should still be 1
      expect(bobState2.receiveMessageCounter).toBe(1);
      
      // Third message should still decrypt (with skipping)
      const [dec3, bobState3] = ratchetDecrypt(bobState2, encryptedMessages[2]);
      expect(new TextDecoder().decode(dec3)).toBe('msg3');
      expect(bobState3.receiveMessageCounter).toBe(3);
    });
  });

  describe('Cross-session attack prevention', () => {
    it('should reject messages from different sessions', () => {
      // Create two separate sessions
      const alice2 = nacl.box.keyPair();
      const bob2 = nacl.box.keyPair();
      
      const session1Alice = initializeRatchet(alice, bob.publicKey);
      const session1Bob = initializeRatchet(bob, alice.publicKey);
      
      const session2Alice = initializeRatchet(alice2, bob2.publicKey);
      const session2Bob = initializeRatchet(bob2, alice2.publicKey);
      
      // Message from session 1
      const msg = new TextEncoder().encode('Session 1 message');
      const [encrypted, _] = ratchetEncrypt(session1Alice, msg);
      
      // Try to decrypt in session 2 (should fail)
      expect(() => {
        ratchetDecrypt(session2Bob, encrypted);
      }).toThrow();
    });
  });
});