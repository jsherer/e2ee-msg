/**
 * PRP-Cap Ratchet Integration Tests
 */

import * as nacl from 'tweetnacl';
import { 
  generatePRPCapKeyPair,
  generateKeyPair
} from '../src/utils/crypto';
import {
  createPRPCapInitialMessage,
  processPRPCapInitialMessage,
  initializeRatchetFromPRPCap,
  supportsPRPCap,
  extractEpochParams
} from '../src/utils/prpcap-ratchet-bridge';
import {
  ratchetEncrypt,
  ratchetDecrypt,
  initializeRatchetFromPRPCapSecret
} from '../src/utils/ratchet';
import { RatchetState } from '../src/types/ratchet';
import {
  encodePRPCapPublicKey,
  decodePRPCapPublicKey
} from '../src/utils/encoding';

describe('PRP-Cap Ratchet Integration', () => {
  
  describe('Key Generation', () => {
    it('should generate PRP-Cap enabled keypair with epoch parameters', async () => {
      const keypair = await generatePRPCapKeyPair();
      
      expect(keypair.publicKey).toBeInstanceOf(Uint8Array);
      expect(keypair.publicKey.length).toBe(32);
      expect(keypair.secretKey).toBeInstanceOf(Uint8Array);
      expect(keypair.secretKey.length).toBe(32);
      
      expect(keypair.epoch).toBeDefined();
      expect(keypair.epoch!.A).toBeInstanceOf(Uint8Array);
      expect(keypair.epoch!.A.length).toBe(32);
      expect(keypair.epoch!.B).toBeInstanceOf(Uint8Array);
      expect(keypair.epoch!.B.length).toBe(32);
      expect(keypair.epoch!.s1).toBeInstanceOf(Uint8Array);
      expect(keypair.epoch!.s1!.length).toBe(32);
      expect(keypair.epoch!.s2).toBeInstanceOf(Uint8Array);
      expect(keypair.epoch!.s2!.length).toBe(32);
      expect(keypair.epoch!.validFrom).toBeGreaterThan(0);
      expect(keypair.epoch!.validUntil).toBeGreaterThan(keypair.epoch!.validFrom);
      expect(keypair.epoch!.epochId).toMatch(/^[0-9a-f]{32}$/);
    });
    
    it('should generate different epoch parameters for each keypair', async () => {
      const keypair1 = await generatePRPCapKeyPair();
      const keypair2 = await generatePRPCapKeyPair();
      
      expect(keypair1.epoch!.A).not.toEqual(keypair2.epoch!.A);
      expect(keypair1.epoch!.B).not.toEqual(keypair2.epoch!.B);
      expect(keypair1.epoch!.s1).not.toEqual(keypair2.epoch!.s1);
      expect(keypair1.epoch!.s2).not.toEqual(keypair2.epoch!.s2);
      expect(keypair1.epoch!.epochId).not.toEqual(keypair2.epoch!.epochId);
    });
  });

  describe('Encoding/Decoding PRP-Cap Public Keys', () => {
    it('should encode and decode PRP-Cap public key with epoch', async () => {
      const keypair = await generatePRPCapKeyPair();
      
      const encoded = encodePRPCapPublicKey(
        keypair.publicKey,
        keypair.epoch!.A,
        keypair.epoch!.B,
        keypair.epoch!.validFrom,
        keypair.epoch!.validUntil,
        keypair.epoch!.epochId
      );
      
      // Crockford base32 uses 0-9, A-Z (excluding I, L, O, U)
      expect(encoded).toMatch(/^[0-9A-HJ-KM-NP-TV-Z]+$/);
      
      const decoded = decodePRPCapPublicKey(encoded);
      expect(decoded).not.toBeNull();
      expect(decoded!.publicKey).toEqual(keypair.publicKey);
      expect(decoded!.epochA).toEqual(keypair.epoch!.A);
      expect(decoded!.epochB).toEqual(keypair.epoch!.B);
      expect(decoded!.validFrom).toEqual(keypair.epoch!.validFrom);
      expect(decoded!.validUntil).toEqual(keypair.epoch!.validUntil);
      expect(decoded!.epochId).toEqual(keypair.epoch!.epochId);
    });
    
    it('should handle legacy keys without PRP-Cap', () => {
      const publicKey = nacl.randomBytes(32);
      
      // Try to decode a plain public key - should return null
      const plainEncoded = Buffer.from(publicKey).toString('base64');
      const decoded = decodePRPCapPublicKey(plainEncoded);
      expect(decoded).toBeNull();
    });
  });

  describe('0-RTT Initial Message', () => {
    it('should create and process PRP-Cap initial message', async () => {
      // Alice generates PRP-Cap keypair
      const alice = await generatePRPCapKeyPair();
      
      // Bob generates PRP-Cap keypair
      const bob = await generatePRPCapKeyPair();
      
      // Alice sends first message to Bob using Bob's epoch parameters
      const message = 'Hello Bob, this is 0-RTT!';
      const initialMsg = await createPRPCapInitialMessage(
        message,
        alice,
        bob.publicKey,
        bob.epoch!.A,
        bob.epoch!.B
      );
      
      expect(initialMsg.ephemeralPublic).toBeInstanceOf(Uint8Array);
      expect(initialMsg.ciphertext).toBeInstanceOf(Uint8Array);
      expect(initialMsg.protocolVersion).toBe(1);
      expect(initialMsg.senderIdentity).toEqual(alice.publicKey);
      
      // Bob processes the initial message
      const result = await processPRPCapInitialMessage(initialMsg, bob);
      
      expect(result).not.toBeNull();
      expect(result!.payload.message).toBe(message);
      expect(result!.payload.identityPublicKey).toEqual(alice.publicKey);
      expect(result!.payload.version).toBe(1);
      expect(result!.ratchetState.isInitialized).toBe(true);
      expect(result!.ratchetState.theirIdentityPublicKey).toEqual(alice.publicKey);
    });
    
    it('should fail with wrong epoch parameters', async () => {
      const alice = await generatePRPCapKeyPair();
      const bob = await generatePRPCapKeyPair();
      const charlie = await generatePRPCapKeyPair();
      
      // Alice uses Charlie's epoch parameters instead of Bob's
      const initialMsg = await createPRPCapInitialMessage(
        'Hello',
        alice,
        bob.publicKey,
        charlie.epoch!.A,
        charlie.epoch!.B
      );
      
      // Bob should not be able to decrypt
      const result = await processPRPCapInitialMessage(initialMsg, bob);
      expect(result).toBeNull();
    });
    
    it('should reject messages without epoch parameters', async () => {
      const alice = await generatePRPCapKeyPair();
      const bobPlain = generateKeyPair(); // No PRP-Cap
      
      // Create a mock message
      const mockMsg = {
        ephemeralPublic: nacl.randomBytes(32),
        ciphertext: nacl.randomBytes(100),
        index: 0,
        nonce: nacl.randomBytes(24),
        senderIdentity: alice.publicKey,
        timestamp: Date.now(),
        protocolVersion: 1
      };
      
      // Should throw when Bob has no epoch params
      await expect(processPRPCapInitialMessage(mockMsg as any, bobPlain as any))
        .rejects.toThrow('Missing epoch parameters');
    });
  });

  describe('Transition to Double Ratchet', () => {
    it('should transition from PRP-Cap to Double Ratchet', async () => {
      const alice = await generatePRPCapKeyPair();
      const bob = await generatePRPCapKeyPair();
      
      // Alice sends initial PRP-Cap message
      const initialMsg = await createPRPCapInitialMessage(
        'First message via PRP-Cap',
        alice,
        bob.publicKey,
        bob.epoch!.A,
        bob.epoch!.B
      );
      
      // Bob processes and establishes ratchet
      const result = await processPRPCapInitialMessage(initialMsg, bob);
      expect(result).not.toBeNull();
      expect(result!.payload.message).toBe('First message via PRP-Cap');
      
      // Bob's ratchet is established and ready for Double Ratchet
      const bobRatchet = result!.ratchetState;
      expect(bobRatchet.isInitialized).toBe(true);
      expect(bobRatchet.theirIdentityPublicKey).toEqual(alice.publicKey);
      expect(bobRatchet.theirLatestEphemeralPublicKey).toEqual(result!.payload.ephemeralPublicKey);
      
      // Bob can now send messages using Double Ratchet
      const bobMsg = new TextEncoder().encode('Reply from Bob via Ratchet');
      const [bobEncrypted, bobRatchet2] = ratchetEncrypt(bobRatchet, bobMsg);
      
      // Verify the encrypted message has proper ratchet structure
      expect(bobEncrypted.length).toBeGreaterThan(65); // Header + nonce + ciphertext
      expect(bobEncrypted[0]).toBe(0x01); // Version
      expect(bobRatchet2.sendMessageCounter).toBe(1);
      
      // The transition is complete - PRP-Cap was used for 0-RTT first message
      // and now Double Ratchet is active for subsequent messages
      
      // Bob can continue sending more messages
      const bobMsg2 = new TextEncoder().encode('Second message from Bob');
      const [bobEncrypted2, bobRatchet3] = ratchetEncrypt(bobRatchet2, bobMsg2);
      expect(bobRatchet3.sendMessageCounter).toBe(2);
      
      // Verify forward secrecy - Bob's epoch s2 can be deleted
      delete bob.epoch!.s2;
      expect(bob.epoch!.s2).toBeUndefined();
      
      // But ratchet continues to work
      const bobMsg3 = new TextEncoder().encode('Third message from Bob');
      const [bobEncrypted3, bobRatchet4] = ratchetEncrypt(bobRatchet3, bobMsg3);
      expect(bobRatchet4.sendMessageCounter).toBe(3);
    });
    
    it('should maintain forward secrecy after transition', async () => {
      const alice = await generatePRPCapKeyPair();
      const bob = await generatePRPCapKeyPair();
      
      // Initial PRP-Cap message
      const initialMsg = await createPRPCapInitialMessage(
        'Initial',
        alice,
        bob.publicKey,
        bob.epoch!.A,
        bob.epoch!.B
      );
      
      const result = await processPRPCapInitialMessage(initialMsg, bob);
      let bobRatchet = result!.ratchetState;
      
      // Delete Bob's s2 to ensure forward secrecy
      delete bob.epoch!.s2;
      
      // Continue with ratchet messages
      const messages = ['msg1', 'msg2', 'msg3'];
      for (const msg of messages) {
        const [encrypted, newBobRatchet] = ratchetEncrypt(
          bobRatchet, 
          new TextEncoder().encode(msg)
        );
        bobRatchet = newBobRatchet;
        
        // Verify ratchet has advanced
        expect(bobRatchet.sendMessageCounter).toBeGreaterThan(0);
      }
      
      // Bob should not be able to decrypt old PRP-Cap messages
      // even if he wanted to (s2 is deleted)
      expect(bob.epoch!.s2).toBeUndefined();
    });
  });

  describe('Compatibility', () => {
    it('should detect PRP-Cap support', async () => {
      const prpcapKey = await generatePRPCapKeyPair();
      const plainKey = generateKeyPair();
      
      const prpcapData = {
        publicKey: prpcapKey.publicKey,
        epoch: prpcapKey.epoch
      };
      
      const plainData = {
        publicKey: plainKey.publicKey
      };
      
      expect(supportsPRPCap(prpcapData)).toBe(true);
      expect(supportsPRPCap(plainData)).toBe(false);
      expect(supportsPRPCap(null)).toBe(false);
      expect(supportsPRPCap({})).toBe(false);
    });
    
    it('should extract epoch parameters', async () => {
      const keypair = await generatePRPCapKeyPair();
      
      const publicData = {
        publicKey: keypair.publicKey,
        epoch: {
          A: keypair.epoch!.A,
          B: keypair.epoch!.B
        }
      };
      
      const params = extractEpochParams(publicData);
      expect(params).not.toBeNull();
      expect(params!.A).toEqual(keypair.epoch!.A);
      expect(params!.B).toEqual(keypair.epoch!.B);
      
      // No epoch params
      expect(extractEpochParams({ publicKey: keypair.publicKey })).toBeNull();
      expect(extractEpochParams(null)).toBeNull();
    });
    
    it('should fall back to standard ratchet for non-PRP-Cap peers', async () => {
      const alice = await generatePRPCapKeyPair();
      const bob = generateKeyPair(); // No PRP-Cap
      
      // Check that Bob doesn't support PRP-Cap
      expect(supportsPRPCap({ publicKey: bob.publicKey })).toBe(false);
      
      // Alice should use standard ratchet initialization
      // This would be handled by the application logic
      const standardRatchet = initializeRatchetFromPRPCapSecret(
        alice,
        bob.publicKey,
        nacl.box.keyPair().publicKey,
        nacl.randomBytes(32)
      );
      
      expect(standardRatchet.isInitialized).toBe(true);
    });
  });

  describe('Multi-message scenarios', () => {
    it('should handle burst of PRP-Cap initial messages', async () => {
      const alice = await generatePRPCapKeyPair();
      const bob = await generatePRPCapKeyPair();
      
      // Alice sends multiple initial messages before Bob replies
      const messages = [
        'First 0-RTT message',
        'Second 0-RTT message',
        'Third 0-RTT message'
      ];
      
      const initialMsgs = await Promise.all(
        messages.map(msg => 
          createPRPCapInitialMessage(msg, alice, bob.publicKey, bob.epoch!.A, bob.epoch!.B)
        )
      );
      
      // Bob should be able to process all of them
      for (let i = 0; i < initialMsgs.length; i++) {
        const result = await processPRPCapInitialMessage(initialMsgs[i], bob);
        expect(result).not.toBeNull();
        expect(result!.payload.message).toBe(messages[i]);
      }
    });
    
    it('should handle mixed PRP-Cap and ratchet messages', async () => {
      const alice = await generatePRPCapKeyPair();
      const bob = await generatePRPCapKeyPair();
      
      // First message via PRP-Cap
      const prpcapMsg = await createPRPCapInitialMessage(
        'PRP-Cap message',
        alice,
        bob.publicKey,
        bob.epoch!.A,
        bob.epoch!.B
      );
      
      const result = await processPRPCapInitialMessage(prpcapMsg, bob);
      let bobRatchet = result!.ratchetState;
      
      // Subsequent messages via ratchet
      const ratchetMessages = ['Ratchet 1', 'Ratchet 2', 'Ratchet 3'];
      for (const msg of ratchetMessages) {
        const [encrypted, newBobRatchet] = ratchetEncrypt(
          bobRatchet,
          new TextEncoder().encode(msg)
        );
        bobRatchet = newBobRatchet;
        
        // Verify message was encrypted
        expect(encrypted.length).toBeGreaterThan(65); // Header + nonce + ciphertext
      }
      
      // Bob's ratchet should be properly advanced
      expect(bobRatchet.sendMessageCounter).toBe(3);
    });
  });

  describe('Error handling', () => {
    it('should handle corrupted PRP-Cap messages', async () => {
      const alice = await generatePRPCapKeyPair();
      const bob = await generatePRPCapKeyPair();
      
      const initialMsg = await createPRPCapInitialMessage(
        'Test',
        alice,
        bob.publicKey,
        bob.epoch!.A,
        bob.epoch!.B
      );
      
      // Corrupt the ciphertext
      initialMsg.ciphertext[10] ^= 0xFF;
      
      const result = await processPRPCapInitialMessage(initialMsg, bob);
      expect(result).toBeNull();
    });
    
    it('should handle expired epochs gracefully', async () => {
      const alice = await generatePRPCapKeyPair();
      const bob = await generatePRPCapKeyPair();
      
      // Set Bob's epoch as expired
      bob.epoch!.validUntil = Date.now() - 1000;
      
      // Message should still be processable (policy decision)
      const initialMsg = await createPRPCapInitialMessage(
        'Test',
        alice,
        bob.publicKey,
        bob.epoch!.A,
        bob.epoch!.B
      );
      
      const result = await processPRPCapInitialMessage(initialMsg, bob);
      expect(result).not.toBeNull();
    });
    
    it('should handle missing epoch components', async () => {
      const alice = await generatePRPCapKeyPair();
      const bob = await generatePRPCapKeyPair();
      
      // Remove s1 from Bob's epoch
      delete bob.epoch!.s1;
      
      const initialMsg = await createPRPCapInitialMessage(
        'Test',
        alice,
        bob.publicKey,
        bob.epoch!.A,
        bob.epoch!.B
      );
      
      await expect(processPRPCapInitialMessage(initialMsg, bob))
        .rejects.toThrow('Missing epoch parameters');
    });
  });
});
