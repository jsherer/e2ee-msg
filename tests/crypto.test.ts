import * as nacl from 'tweetnacl';
import {
  generateKeyPair,
  generateKeyPairFromSecretKey,
  deriveKeyFromMasterKey,
  encryptSecretKey,
  decryptSecretKey,
  encryptMessage,
  decryptMessage
} from '../src/utils/crypto';

describe('crypto utilities', () => {
  describe('generateKeyPair', () => {
    it('should generate a valid keypair', () => {
      const keypair = generateKeyPair();
      
      expect(keypair.publicKey).toHaveLength(32);
      expect(keypair.secretKey).toHaveLength(32);
    });

    it('should generate unique keypairs', () => {
      const keypair1 = generateKeyPair();
      const keypair2 = generateKeyPair();
      
      expect(keypair1.publicKey).not.toEqual(keypair2.publicKey);
      expect(keypair1.secretKey).not.toEqual(keypair2.secretKey);
    });
  });

  describe('generateKeyPairFromSecretKey', () => {
    it('should regenerate same keypair from secret key', () => {
      const original = generateKeyPair();
      const regenerated = generateKeyPairFromSecretKey(original.secretKey);
      
      expect(regenerated.publicKey).toEqual(original.publicKey);
      expect(regenerated.secretKey).toEqual(original.secretKey);
    });
  });

  describe('deriveKeyFromMasterKey', () => {
    it('should derive a 32-byte key', () => {
      const masterKey = 'test-master-key-12345';
      const derived = deriveKeyFromMasterKey(masterKey);
      
      expect(derived).toHaveLength(32);
    });

    it('should derive same key for same master key', () => {
      const masterKey = 'consistent-key-12345';
      const derived1 = deriveKeyFromMasterKey(masterKey);
      const derived2 = deriveKeyFromMasterKey(masterKey);
      
      expect(derived1).toEqual(derived2);
    });

    it('should derive different keys for different master keys', () => {
      const key1 = deriveKeyFromMasterKey('key-one-12345');
      const key2 = deriveKeyFromMasterKey('key-two-12345');
      
      expect(key1).not.toEqual(key2);
    });
  });

  describe('encryptSecretKey / decryptSecretKey', () => {
    it('should encrypt and decrypt secret key', () => {
      const keypair = generateKeyPair();
      const masterKey = 'test-master-key-12345';
      
      const encrypted = encryptSecretKey(keypair.secretKey, masterKey);
      const decrypted = decryptSecretKey(encrypted, masterKey);
      
      expect(decrypted).toEqual(keypair.secretKey);
    });

    it('should fail with wrong master key', () => {
      const keypair = generateKeyPair();
      const masterKey = 'correct-key-12345';
      const wrongKey = 'wrong-key-12345';
      
      const encrypted = encryptSecretKey(keypair.secretKey, masterKey);
      const decrypted = decryptSecretKey(encrypted, wrongKey);
      
      expect(decrypted).toBeNull();
    });

    it('should produce different encrypted output each time (due to nonce)', () => {
      const keypair = generateKeyPair();
      const masterKey = 'test-master-key-12345';
      
      const encrypted1 = encryptSecretKey(keypair.secretKey, masterKey);
      const encrypted2 = encryptSecretKey(keypair.secretKey, masterKey);
      
      expect(encrypted1).not.toEqual(encrypted2);
      
      // But both should decrypt to same value
      const decrypted1 = decryptSecretKey(encrypted1, masterKey);
      const decrypted2 = decryptSecretKey(encrypted2, masterKey);
      
      expect(decrypted1).toEqual(decrypted2);
      expect(decrypted1).toEqual(keypair.secretKey);
    });
  });

  describe('encryptMessage / decryptMessage', () => {
    it('should encrypt and decrypt message', () => {
      const alice = generateKeyPair();
      const bob = generateKeyPair();
      const message = 'Hello, Bob! This is a secret message.';
      
      const encrypted = encryptMessage(message, bob.publicKey, alice.secretKey);
      const decrypted = decryptMessage(encrypted, alice.publicKey, bob.secretKey);
      
      expect(decrypted).toBe(message);
    });

    it('should fail with wrong keys', () => {
      const alice = generateKeyPair();
      const bob = generateKeyPair();
      const eve = generateKeyPair();
      const message = 'Secret message';
      
      const encrypted = encryptMessage(message, bob.publicKey, alice.secretKey);
      
      // Eve tries to decrypt with her key
      const decrypted = decryptMessage(encrypted, alice.publicKey, eve.secretKey);
      
      expect(decrypted).toBeNull();
    });

    it('should handle empty message', () => {
      const alice = generateKeyPair();
      const bob = generateKeyPair();
      const message = '';
      
      const encrypted = encryptMessage(message, bob.publicKey, alice.secretKey);
      const decrypted = decryptMessage(encrypted, alice.publicKey, bob.secretKey);
      
      expect(decrypted).toBe('');
    });

    it('should handle unicode messages', () => {
      const alice = generateKeyPair();
      const bob = generateKeyPair();
      const message = '👋 Hello 世界! 🔐';
      
      const encrypted = encryptMessage(message, bob.publicKey, alice.secretKey);
      const decrypted = decryptMessage(encrypted, alice.publicKey, bob.secretKey);
      
      expect(decrypted).toBe(message);
    });

    it('should produce different ciphertext each time (due to nonce)', () => {
      const alice = generateKeyPair();
      const bob = generateKeyPair();
      const message = 'Same message';
      
      const encrypted1 = encryptMessage(message, bob.publicKey, alice.secretKey);
      const encrypted2 = encryptMessage(message, bob.publicKey, alice.secretKey);
      
      expect(encrypted1).not.toEqual(encrypted2);
      
      // But both should decrypt to same message
      const decrypted1 = decryptMessage(encrypted1, alice.publicKey, bob.secretKey);
      const decrypted2 = decryptMessage(encrypted2, alice.publicKey, bob.secretKey);
      
      expect(decrypted1).toBe(message);
      expect(decrypted2).toBe(message);
    });
  });
});