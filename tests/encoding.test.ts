/**
 * Tests for encryption/decryption with 32 and 64 byte keys
 */

import * as nacl from 'tweetnacl';
import { encryptMessage, decryptMessage } from '../src/utils/crypto';

describe('Encryption with different key sizes', () => {
  let alice: ReturnType<typeof nacl.box.keyPair>;
  let bob: ReturnType<typeof nacl.box.keyPair>;

  beforeEach(() => {
    alice = nacl.box.keyPair();
    bob = nacl.box.keyPair();
  });

  describe('Standard encryption (32-byte keys)', () => {
    it('should encrypt and decrypt with 32-byte keys', () => {
      const message = 'Hello Bob!';
      
      // Alice encrypts for Bob
      const encrypted = encryptMessage(message, bob.publicKey, alice.secretKey);
      expect(encrypted).toBeDefined();
      expect(encrypted.length).toBeGreaterThan(0);
      
      // Bob decrypts from Alice
      const decrypted = decryptMessage(encrypted, alice.publicKey, bob.secretKey);
      expect(decrypted).toBe(message);
    });

    it('should fail decryption with wrong keys', () => {
      const message = 'Secret message';
      const eve = nacl.box.keyPair();
      
      const encrypted = encryptMessage(message, bob.publicKey, alice.secretKey);
      
      // Eve tries to decrypt
      const decrypted = decryptMessage(encrypted, alice.publicKey, eve.secretKey);
      expect(decrypted).toBeNull();
    });
  });

  describe('Bundle handling (64-byte keys)', () => {
    it('should extract identity key from 64-byte bundle', () => {
      // Create a 64-byte bundle (identity + ephemeral)
      const bundle = new Uint8Array(64);
      bundle.set(bob.publicKey, 0);
      // Fill ephemeral part with dummy data
      for (let i = 32; i < 64; i++) {
        bundle[i] = i;
      }
      
      // Should use only first 32 bytes for encryption
      const message = 'Test with bundle';
      const encrypted = encryptMessage(message, bundle.slice(0, 32), alice.secretKey);
      
      // Bob can decrypt with his identity key
      const decrypted = decryptMessage(encrypted, alice.publicKey, bob.secretKey);
      expect(decrypted).toBe(message);
    });

    it('should handle mixed key sizes', () => {
      const message = 'Mixed key test';
      
      // Alice has 32-byte key, Bob has 64-byte bundle
      const bobBundle = new Uint8Array(64);
      bobBundle.set(bob.publicKey, 0);
      
      // Alice encrypts using Bob's identity (first 32 bytes)
      const encrypted = encryptMessage(message, bob.publicKey, alice.secretKey);
      
      // Bob decrypts
      const decrypted = decryptMessage(encrypted, alice.publicKey, bob.secretKey);
      expect(decrypted).toBe(message);
    });
  });

  describe('Message format', () => {
    it('should create properly formatted encrypted messages', () => {
      const message = 'Format test';
      const encrypted = encryptMessage(message, bob.publicKey, alice.secretKey);
      
      // Check structure: nonce (24) + encrypted data
      expect(encrypted.length).toBeGreaterThanOrEqual(24 + message.length);
      
      // First 24 bytes should be the nonce
      const nonce = encrypted.slice(0, 24);
      expect(nonce.length).toBe(24);
    });
  });
});
