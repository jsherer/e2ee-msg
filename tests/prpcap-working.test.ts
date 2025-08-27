/**
 * Tests for working 0-RTT implementation
 */

import {
  generateWorkingEpoch,
  createWorkingMessage,
  processWorkingMessage,
  testWorkingConvergence
} from '../src/utils/prpcap-working';

describe('Working 0-RTT Protocol', () => {
  describe('Basic functionality', () => {
    it('should generate valid epoch parameters', () => {
      const epoch = generateWorkingEpoch();
      
      expect(epoch.epochSecret).toHaveLength(32);
      expect(epoch.epochPublic).toHaveLength(32);
      expect(epoch.epochSecret).not.toEqual(epoch.epochPublic);
      expect(epoch.epochId).toHaveLength(32);
    });
    
    it('should successfully encrypt and decrypt', async () => {
      const bobEpoch = generateWorkingEpoch();
      const plaintext = new TextEncoder().encode('Test message');
      
      const msg = await createWorkingMessage(
        plaintext,
        bobEpoch.epochPublic,
        123
      );
      
      expect(msg.senderEphemeralPublic).toHaveLength(32);
      expect(msg.index).toBe(123);
      expect(msg.ciphertext.length).toBeGreaterThan(0);
      expect(msg.nonce).toHaveLength(24);
      
      const decrypted = await processWorkingMessage(msg, bobEpoch.epochSecret);
      
      expect(decrypted).not.toBeNull();
      expect(new Uint8Array(decrypted!)).toEqual(new Uint8Array(plaintext));
    });
    
    it('should achieve key convergence', async () => {
      const result = await testWorkingConvergence();
      expect(result).toBe(true);
    });
  });

  describe('0-RTT property', () => {
    it('allows Alice to encrypt without interaction', async () => {
      // Bob publishes only his epoch public key
      const bobEpoch = generateWorkingEpoch();
      const bobPublicInfo = bobEpoch.epochPublic;
      
      // Alice can immediately encrypt using only public info
      const plaintext = new TextEncoder().encode('0-RTT message');
      const msg = await createWorkingMessage(plaintext, bobPublicInfo, 999);
      
      expect(msg).toBeDefined();
      expect(msg.ciphertext.length).toBeGreaterThan(0);
      
      // Bob can decrypt later
      const decrypted = await processWorkingMessage(msg, bobEpoch.epochSecret);
      expect(new TextDecoder().decode(decrypted!)).toBe('0-RTT message');
    });
    
    it('works for multiple messages with different indices', async () => {
      const bobEpoch = generateWorkingEpoch();
      const messages = [
        'First message',
        'Second message',
        'Third message'
      ];
      const indices = [1, 100, 999999];
      
      for (let i = 0; i < messages.length; i++) {
        const plaintext = new TextEncoder().encode(messages[i]);
        const msg = await createWorkingMessage(
          plaintext,
          bobEpoch.epochPublic,
          indices[i]
        );
        
        const decrypted = await processWorkingMessage(msg, bobEpoch.epochSecret);
        expect(new TextDecoder().decode(decrypted!)).toBe(messages[i]);
      }
    });
  });

  describe('Security properties', () => {
    it('should fail with wrong epoch secret', async () => {
      const bobEpoch = generateWorkingEpoch();
      const plaintext = new TextEncoder().encode('Secret');
      
      const msg = await createWorkingMessage(
        plaintext,
        bobEpoch.epochPublic,
        42
      );
      
      // Try to decrypt with wrong secret
      const wrongEpoch = generateWorkingEpoch();
      const decrypted = await processWorkingMessage(msg, wrongEpoch.epochSecret);
      
      expect(decrypted).toBeNull();
    });
    
    it('should fail with tampered index', async () => {
      const bobEpoch = generateWorkingEpoch();
      const plaintext = new TextEncoder().encode('Test');
      
      const msg = await createWorkingMessage(
        plaintext,
        bobEpoch.epochPublic,
        100
      );
      
      // Tamper with index
      msg.index = 200;
      
      const decrypted = await processWorkingMessage(msg, bobEpoch.epochSecret);
      expect(decrypted).toBeNull();
    });
    
    it('should use different ephemeral keys each time', async () => {
      const bobEpoch = generateWorkingEpoch();
      const plaintext = new TextEncoder().encode('Same message');
      
      const msg1 = await createWorkingMessage(plaintext, bobEpoch.epochPublic, 1);
      const msg2 = await createWorkingMessage(plaintext, bobEpoch.epochPublic, 1);
      
      // Different ephemeral keys
      expect(msg1.senderEphemeralPublic).not.toEqual(msg2.senderEphemeralPublic);
      // Different ciphertexts
      expect(msg1.ciphertext).not.toEqual(msg2.ciphertext);
      // Different nonces
      expect(msg1.nonce).not.toEqual(msg2.nonce);
    });
  });

  describe('Forward secrecy', () => {
    it('should not decrypt after epoch secret deletion', async () => {
      const bobEpoch = generateWorkingEpoch();
      const plaintext = new TextEncoder().encode('Forward secure');
      
      const msg = await createWorkingMessage(
        plaintext,
        bobEpoch.epochPublic,
        42
      );
      
      // Can decrypt initially
      const decrypted1 = await processWorkingMessage(msg, bobEpoch.epochSecret);
      expect(decrypted1).not.toBeNull();
      
      // "Delete" epoch secret
      bobEpoch.epochSecret.fill(0);
      
      // Cannot decrypt anymore
      const decrypted2 = await processWorkingMessage(msg, bobEpoch.epochSecret);
      expect(decrypted2).toBeNull();
    });
  });

  describe('Cryptographic correctness', () => {
    it('should maintain DH commutativity', async () => {
      // This is the core property that makes it work:
      // DH(a, G^b) = DH(b, G^a) = G^(ab)
      
      const bobEpoch = generateWorkingEpoch();
      
      // Multiple rounds should all work
      for (let i = 0; i < 5; i++) {
        const plaintext = new TextEncoder().encode(`Message ${i}`);
        const msg = await createWorkingMessage(
          plaintext,
          bobEpoch.epochPublic,
          i
        );
        
        const decrypted = await processWorkingMessage(msg, bobEpoch.epochSecret);
        expect(new TextDecoder().decode(decrypted!)).toBe(`Message ${i}`);
      }
    });
  });
});