/**
 * Jest tests for PRP-Cap protocol implementation
 */

import * as nacl from 'tweetnacl';
import {
  initializeEd25519,
  generatePRPCapEpoch,
  computeVi,
  compute_vi,
  ed25519DH,
  createPRPCapMessage,
  processPRPCapMessage,
  testPRPCapConvergence,
  bytesToNumberLE,
  numberToBytesLE
} from '../src/utils/prpcap-impl';

describe('PRP-Cap Protocol Implementation', () => {
  beforeAll(async () => {
    // Initialize the Ed25519 library once
    await initializeEd25519();
  });

  describe('Core functionality', () => {
    it('should initialize Ed25519 library', async () => {
      await expect(initializeEd25519()).resolves.toBeUndefined();
    });

    it('should generate valid epoch parameters', async () => {
      const epoch = await generatePRPCapEpoch();
      
      expect(epoch.A).toHaveLength(32);
      expect(epoch.B).toHaveLength(32);
      expect(epoch.s1).toHaveLength(32);
      expect(epoch.s2).toHaveLength(32);
      expect(epoch.A).not.toEqual(epoch.B);
      expect(epoch.s1).not.toEqual(epoch.s2);
    });

    it('should compute different V_i for different indices', async () => {
      const epoch = await generatePRPCapEpoch();
      
      const V_1 = await computeVi(epoch.A, epoch.B, 1);
      const V_2 = await computeVi(epoch.A, epoch.B, 2);
      const V_100 = await computeVi(epoch.A, epoch.B, 100);
      
      expect(V_1).toHaveLength(32);
      expect(V_2).toHaveLength(32);
      expect(V_100).toHaveLength(32);
      
      // Convert to hex for comparison
      const hex1 = Array.from(V_1).map(b => b.toString(16).padStart(2, '0')).join('');
      const hex2 = Array.from(V_2).map(b => b.toString(16).padStart(2, '0')).join('');
      const hex100 = Array.from(V_100).map(b => b.toString(16).padStart(2, '0')).join('');
      
      expect(hex1).not.toBe(hex2);
      expect(hex1).not.toBe(hex100);
      expect(hex2).not.toBe(hex100);
    });

    it('should achieve key convergence: DH(e, V_i) = DH(v_i, E)', async () => {
      // This is the critical test for PRP-Cap
      const epoch = await generatePRPCapEpoch();
      
      // Import @noble modules dynamically
      const ed = await import('@noble/ed25519');
      const { sha512 } = await import('@noble/hashes/sha2');
      
      // Generate ephemeral
      const ephemeralSeed = ed.utils.randomPrivateKey();
      const ephemeralHash = sha512(ephemeralSeed);
      const ephemeralScalar = ephemeralHash.slice(0, 32);
      ephemeralScalar[0] &= 248;
      ephemeralScalar[31] &= 63;
      ephemeralScalar[31] |= 64;
      
      const ephemeralBigint = ed.etc.mod(bytesToNumberLE(ephemeralScalar), ed.CURVE.n);
      const ephemeralPublic = ed.Point.BASE.multiply(ephemeralBigint).toRawBytes();
      
      const index = 42;
      
      // Alice computes V_i
      const V_i = await computeVi(epoch.A, epoch.B, index);
      
      // Bob computes v_i
      const v_i = await compute_vi(epoch.s1, epoch.s2, epoch.A, epoch.B, index);
      
      // Alice: DH(e, V_i)
      const aliceShared = await ed25519DH(ephemeralScalar, V_i);
      const aliceSecret = sha512(aliceShared).slice(0, 32);
      
      // Bob: DH(v_i, E)
      const bobShared = await ed25519DH(v_i, ephemeralPublic);
      const bobSecret = sha512(bobShared).slice(0, 32);
      
      // The key assertion - they should be identical
      expect(aliceSecret).toEqual(bobSecret);
    });

    it('should verify convergence for multiple indices', async () => {
      const epoch = await generatePRPCapEpoch();
      const ed = await import('@noble/ed25519');
      const { sha512 } = await import('@noble/hashes/sha2');
      
      const ephemeralSeed = ed.utils.randomPrivateKey();
      const ephemeralHash = sha512(ephemeralSeed);
      const ephemeralScalar = ephemeralHash.slice(0, 32);
      ephemeralScalar[0] &= 248;
      ephemeralScalar[31] &= 63;
      ephemeralScalar[31] |= 64;
      
      const ephemeralBigint = ed.etc.mod(bytesToNumberLE(ephemeralScalar), ed.CURVE.n);
      const ephemeralPublic = ed.Point.BASE.multiply(ephemeralBigint).toRawBytes();
      
      const indices = [0, 1, 42, 999, 2147483647];
      
      for (const index of indices) {
        const V_i = await computeVi(epoch.A, epoch.B, index);
        const v_i = await compute_vi(epoch.s1, epoch.s2, epoch.A, epoch.B, index);
        
        const aliceShared = await ed25519DH(ephemeralScalar, V_i);
        const aliceSecret = sha512(aliceShared).slice(0, 32);
        
        const bobShared = await ed25519DH(v_i, ephemeralPublic);
        const bobSecret = sha512(bobShared).slice(0, 32);
        
        expect(aliceSecret).toEqual(bobSecret);
      }
    });

    it('should encrypt and decrypt messages', async () => {
      const epoch = await generatePRPCapEpoch();
      const plaintext = new TextEncoder().encode('Test message for PRP-Cap');
      
      const message = await createPRPCapMessage(
        plaintext,
        epoch.A,
        epoch.B,
        123
      );
      
      expect(message.ephemeralPublic).toHaveLength(32);
      expect(message.index).toBe(123);
      expect(message.ciphertext.length).toBeGreaterThan(0);
      expect(message.nonce).toHaveLength(24);
      
      const decrypted = await processPRPCapMessage(message, epoch);
      expect(decrypted).not.toBeNull();
      
      const decryptedText = new TextDecoder().decode(decrypted!);
      expect(decryptedText).toBe('Test message for PRP-Cap');
    });

    it('should support 0-RTT property', async () => {
      const bobEpoch = await generatePRPCapEpoch();
      
      // Alice only needs Bob's public A and B
      const plaintext = new TextEncoder().encode('0-RTT message');
      const message = await createPRPCapMessage(
        plaintext,
        bobEpoch.A,
        bobEpoch.B,
        999
      );
      
      expect(message).toBeDefined();
      expect(message.ciphertext.length).toBeGreaterThan(0);
      
      // Bob can decrypt with his secrets
      const decrypted = await processPRPCapMessage(message, bobEpoch);
      expect(decrypted).not.toBeNull();
      expect(new TextDecoder().decode(decrypted!)).toBe('0-RTT message');
    });

    it('should fail decryption with wrong epoch', async () => {
      const epoch1 = await generatePRPCapEpoch();
      const epoch2 = await generatePRPCapEpoch();
      
      const plaintext = new TextEncoder().encode('Secret');
      const message = await createPRPCapMessage(
        plaintext,
        epoch1.A,
        epoch1.B,
        42
      );
      
      const decrypted = await processPRPCapMessage(message, epoch2);
      expect(decrypted).toBeNull();
    });

    it('should pass built-in convergence test', async () => {
      const result = await testPRPCapConvergence();
      expect(result).toBe(true);
    });
  });

  describe('Helper functions', () => {
    it('should convert bytes to little-endian bigint', () => {
      const bytes = new Uint8Array([1, 2, 3, 4]);
      const num = bytesToNumberLE(bytes);
      expect(num).toBe(0x04030201n);
    });

    it('should convert bigint to little-endian bytes', () => {
      const num = 0x04030201n;
      const bytes = numberToBytesLE(num, 4);
      expect(bytes).toEqual(new Uint8Array([1, 2, 3, 4]));
    });

    it('should handle large numbers correctly', () => {
      const largeNum = 2n ** 250n + 12345n;
      const bytes = numberToBytesLE(largeNum, 32);
      const recovered = bytesToNumberLE(bytes);
      expect(recovered).toBe(largeNum);
    });
  });

  describe('Security properties', () => {
    it('should produce different ciphertexts for same plaintext', async () => {
      const epoch = await generatePRPCapEpoch();
      const plaintext = new TextEncoder().encode('Same message');
      
      const msg1 = await createPRPCapMessage(plaintext, epoch.A, epoch.B, 100);
      const msg2 = await createPRPCapMessage(plaintext, epoch.A, epoch.B, 100);
      
      // Different ephemeral keys ensure different ciphertexts
      expect(msg1.ephemeralPublic).not.toEqual(msg2.ephemeralPublic);
      expect(msg1.ciphertext).not.toEqual(msg2.ciphertext);
      expect(msg1.nonce).not.toEqual(msg2.nonce);
    });

    it('should fail with tampered index', async () => {
      const epoch = await generatePRPCapEpoch();
      const plaintext = new TextEncoder().encode('Test');
      
      const message = await createPRPCapMessage(
        plaintext,
        epoch.A,
        epoch.B,
        100
      );
      
      // Tamper with index
      message.index = 200;
      
      const decrypted = await processPRPCapMessage(message, epoch);
      expect(decrypted).toBeNull();
    });
  });
});