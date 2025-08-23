/**
 * End-to-End Encryption Integration Tests
 * Tests the complete encryption flow as it would happen in the real app
 */

import {
  generateKeyPair,
  encryptMessage,
  decryptMessage,
  encryptSecretKey,
  decryptSecretKey,
  generateKeyPairFromSecretKey
} from '../src/utils/crypto';
import {
  uint8ArrayToBase32Crockford,
  base32CrockfordToUint8Array,
  formatInGroups
} from '../src/utils/encoding';
import { uint8ArrayToWords, wordsToUint8Array } from '../src/utils/bip39';

describe('End-to-End Encryption Integration', () => {
  describe('Complete message exchange flow', () => {
    it('should handle the full encryption flow between Alice and Bob', () => {
      // Step 1: Alice and Bob generate their keypairs
      const alice = generateKeyPair();
      const bob = generateKeyPair();

      // Step 2: They exchange public keys (simulating base36 format)
      const alicePublicKeyBase36 = formatInGroups(uint8ArrayToBase32Crockford(alice.publicKey));
      const bobPublicKeyBase36 = formatInGroups(uint8ArrayToBase32Crockford(bob.publicKey));

      // Step 3: Alice sends an encrypted message to Bob
      const aliceMessage = 'Hello Bob! This is a secret message. 🔐';
      
      // Alice gets Bob's public key from base36 format
      const bobPublicKeyRestored = base32CrockfordToUint8Array(bobPublicKeyBase36.replace(/\s/g, ''));
      
      // Alice encrypts the message
      const encryptedByAlice = encryptMessage(aliceMessage, bobPublicKeyRestored, alice.secretKey);
      
      // Convert to base36 for transmission
      const encryptedBase36 = formatInGroups(uint8ArrayToBase32Crockford(encryptedByAlice));

      // Step 4: Bob receives and decrypts the message
      const encryptedReceived = base32CrockfordToUint8Array(encryptedBase36.replace(/\s/g, ''));
      const alicePublicKeyRestored = base32CrockfordToUint8Array(alicePublicKeyBase36.replace(/\s/g, ''));
      
      const decryptedByBob = decryptMessage(encryptedReceived, alicePublicKeyRestored, bob.secretKey);
      
      expect(decryptedByBob).toBe(aliceMessage);

      // Step 5: Bob replies to Alice
      const bobMessage = 'Hi Alice! Got your message. Here\'s my reply. 🔒';
      
      const encryptedByBob = encryptMessage(bobMessage, alicePublicKeyRestored, bob.secretKey);
      const replyBase36 = formatInGroups(uint8ArrayToBase32Crockford(encryptedByBob));
      
      // Step 6: Alice decrypts Bob's reply
      const replyReceived = base32CrockfordToUint8Array(replyBase36.replace(/\s/g, ''));
      const decryptedByAlice = decryptMessage(replyReceived, bobPublicKeyRestored, alice.secretKey);
      
      expect(decryptedByAlice).toBe(bobMessage);
    });

    it('should handle public key exchange via BIP39 words', () => {
      const alice = generateKeyPair();
      const bob = generateKeyPair();

      // Exchange public keys as BIP39 words
      const alicePublicKeyWords = uint8ArrayToWords(alice.publicKey);
      const bobPublicKeyWords = uint8ArrayToWords(bob.publicKey);
      
      expect(alicePublicKeyWords).toHaveLength(24);
      expect(bobPublicKeyWords).toHaveLength(24);

      // Bob gets Alice's public key from words
      const aliceKeyFromWords = wordsToUint8Array(alicePublicKeyWords);
      
      // Alice gets Bob's public key from words
      const bobKeyFromWords = wordsToUint8Array(bobPublicKeyWords);
      
      // Exchange messages
      const message = 'Testing with BIP39 word exchange';
      
      const encrypted = encryptMessage(message, bobKeyFromWords, alice.secretKey);
      const decrypted = decryptMessage(encrypted, aliceKeyFromWords, bob.secretKey);
      
      expect(decrypted).toBe(message);
    });

    it('should prevent Eve from reading messages', () => {
      const alice = generateKeyPair();
      const bob = generateKeyPair();
      const eve = generateKeyPair(); // Eve the eavesdropper

      // Alice sends message to Bob
      const secretMessage = 'This is for Bob\'s eyes only!';
      const encrypted = encryptMessage(secretMessage, bob.publicKey, alice.secretKey);

      // Eve intercepts the message and tries to decrypt
      const eveAttempt1 = decryptMessage(encrypted, alice.publicKey, eve.secretKey);
      const eveAttempt2 = decryptMessage(encrypted, eve.publicKey, bob.secretKey);
      const eveAttempt3 = decryptMessage(encrypted, eve.publicKey, eve.secretKey);
      
      expect(eveAttempt1).toBeNull();
      expect(eveAttempt2).toBeNull();
      expect(eveAttempt3).toBeNull();

      // But Bob can decrypt it
      const bobDecrypted = decryptMessage(encrypted, alice.publicKey, bob.secretKey);
      expect(bobDecrypted).toBe(secretMessage);
    });

    it('should handle master key encryption of private keys', () => {
      // User generates a keypair
      const keypair = generateKeyPair();
      const masterKey = 'my-super-secret-master-key-12345';
      
      // Encrypt the private key with master key (for storage)
      const encryptedPrivateKey = encryptSecretKey(keypair.secretKey, masterKey);
      
      // Convert to base36 for URL storage
      const storageFormat = uint8ArrayToBase32Crockford(encryptedPrivateKey);
      
      // Later: Restore from storage
      const restoredEncrypted = base32CrockfordToUint8Array(storageFormat);
      const restoredSecretKey = decryptSecretKey(restoredEncrypted, masterKey);
      
      expect(restoredSecretKey).toEqual(keypair.secretKey);
      
      // Verify the keypair still works
      const restoredKeypair = generateKeyPairFromSecretKey(restoredSecretKey!);
      expect(restoredKeypair.publicKey).toEqual(keypair.publicKey);
      
      // Test that wrong master key fails
      const wrongKey = decryptSecretKey(restoredEncrypted, 'wrong-password-12345');
      expect(wrongKey).toBeNull();
    });

    it('should handle the complete app flow with all conversions', () => {
      // Simulate the full app flow
      
      // 1. Alice starts the app and enters master key
      const aliceMasterKey = 'alice-master-password-123';
      const aliceKeypair = generateKeyPair();
      
      // 2. Alice's private key is encrypted and stored
      const aliceEncryptedKey = encryptSecretKey(aliceKeypair.secretKey, aliceMasterKey);
      const aliceStoredKey = uint8ArrayToBase32Crockford(aliceEncryptedKey);
      
      // 3. Bob does the same
      const bobMasterKey = 'bob-master-password-456';
      const bobKeypair = generateKeyPair();
      const bobEncryptedKey = encryptSecretKey(bobKeypair.secretKey, bobMasterKey);
      const bobStoredKey = uint8ArrayToBase32Crockford(bobEncryptedKey);
      
      // 4. They exchange public keys (as base36)
      const alicePublicKeyShared = formatInGroups(uint8ArrayToBase32Crockford(aliceKeypair.publicKey));
      const bobPublicKeyShared = formatInGroups(uint8ArrayToBase32Crockford(bobKeypair.publicKey));
      
      // 5. Alice restores her key and sends a message
      const aliceRestoredSecret = decryptSecretKey(
        base32CrockfordToUint8Array(aliceStoredKey),
        aliceMasterKey
      );
      const aliceRestored = generateKeyPairFromSecretKey(aliceRestoredSecret!);
      
      const message = 'Complete flow test message with emojis! 🎉🔐💬';
      const bobKeyForAlice = base32CrockfordToUint8Array(bobPublicKeyShared.replace(/\s/g, ''));
      
      const encrypted = encryptMessage(message, bobKeyForAlice, aliceRestored.secretKey);
      const transmittedMessage = formatInGroups(uint8ArrayToBase32Crockford(encrypted));
      
      // 6. Bob restores his key and decrypts
      const bobRestoredSecret = decryptSecretKey(
        base32CrockfordToUint8Array(bobStoredKey),
        bobMasterKey
      );
      const bobRestored = generateKeyPairFromSecretKey(bobRestoredSecret!);
      
      const receivedEncrypted = base32CrockfordToUint8Array(transmittedMessage.replace(/\s/g, ''));
      const aliceKeyForBob = base32CrockfordToUint8Array(alicePublicKeyShared.replace(/\s/g, ''));
      
      const decrypted = decryptMessage(receivedEncrypted, aliceKeyForBob, bobRestored.secretKey);
      
      expect(decrypted).toBe(message);
    });

    it('should handle large messages', () => {
      const alice = generateKeyPair();
      const bob = generateKeyPair();
      
      // Create a large message
      const largeMessage = 'Lorem ipsum '.repeat(1000); // ~12KB message
      
      const encrypted = encryptMessage(largeMessage, bob.publicKey, alice.secretKey);
      const decrypted = decryptMessage(encrypted, alice.publicKey, bob.secretKey);
      
      expect(decrypted).toBe(largeMessage);
    });

    it('should maintain security with message tampering', () => {
      const alice = generateKeyPair();
      const bob = generateKeyPair();
      
      const message = 'Original message';
      const encrypted = encryptMessage(message, bob.publicKey, alice.secretKey);
      
      // Tamper with the encrypted message
      const tampered = new Uint8Array(encrypted);
      tampered[50] = (tampered[50] + 1) % 256; // Change one byte
      
      // Decryption should fail
      const result = decryptMessage(tampered, alice.publicKey, bob.secretKey);
      expect(result).toBeNull();
    });
  });
});