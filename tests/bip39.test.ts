/**
 * Tests for BIP39 word encoding/decoding with 32 and 64 byte support
 */

import { uint8ArrayToWords, wordsToUint8Array, formatWords } from '../src/utils/bip39';

describe('BIP39 Word Encoding', () => {
  describe('32-byte encoding (24 words)', () => {
    it('should convert 32 bytes to 24 words', () => {
      const bytes32 = new Uint8Array(32);
      // Fill with test data
      for (let i = 0; i < 32; i++) {
        bytes32[i] = i;
      }
      
      const words = uint8ArrayToWords(bytes32);
      expect(words).toHaveLength(24);
      expect(words.every(word => typeof word === 'string')).toBe(true);
    });

    it('should round-trip 32 bytes correctly', () => {
      const original = new Uint8Array(32);
      // Fill with random-like data
      for (let i = 0; i < 32; i++) {
        original[i] = (i * 7 + 13) % 256;
      }
      
      const words = uint8ArrayToWords(original);
      const recovered = wordsToUint8Array(words);
      
      expect(recovered).toHaveLength(32);
      expect(recovered).toEqual(original);
    });
  });

  describe('64-byte encoding (48 words)', () => {
    it('should convert 64 bytes to 48 words', () => {
      const bytes64 = new Uint8Array(64);
      // Fill with test data
      for (let i = 0; i < 64; i++) {
        bytes64[i] = i;
      }
      
      const words = uint8ArrayToWords(bytes64);
      expect(words).toHaveLength(48);
      expect(words.every(word => typeof word === 'string')).toBe(true);
    });

    it('should round-trip 64 bytes correctly', () => {
      const original = new Uint8Array(64);
      // Fill with random-like data
      for (let i = 0; i < 64; i++) {
        original[i] = (i * 11 + 23) % 256;
      }
      
      const words = uint8ArrayToWords(original);
      const recovered = wordsToUint8Array(words);
      
      expect(recovered).toHaveLength(64);
      expect(recovered).toEqual(original);
    });

    it('should handle a full 64-byte bundle (identity + ephemeral)', () => {
      const bundle = new Uint8Array(64);
      // First 32 bytes: identity key
      for (let i = 0; i < 32; i++) {
        bundle[i] = 0xAA;
      }
      // Last 32 bytes: ephemeral seed
      for (let i = 32; i < 64; i++) {
        bundle[i] = 0xBB;
      }
      
      const words = uint8ArrayToWords(bundle);
      expect(words).toHaveLength(48);
      
      const recovered = wordsToUint8Array(words);
      expect(recovered).toEqual(bundle);
    });
  });

  describe('formatWords', () => {
    it('should format 24 words in groups of 4', () => {
      const words = Array(24).fill('test');
      const formatted = formatWords(words, 4);
      const lines = formatted.split('\n');
      expect(lines).toHaveLength(6); // 24 words / 4 per line
    });

    it('should format 48 words in groups of 4', () => {
      const words = Array(48).fill('word');
      const formatted = formatWords(words, 4);
      const lines = formatted.split('\n');
      expect(lines).toHaveLength(12); // 48 words / 4 per line
    });
  });

  describe('error handling', () => {
    it('should reject invalid byte lengths', () => {
      const bytes16 = new Uint8Array(16);
      expect(() => uint8ArrayToWords(bytes16)).toThrow('Expected 32 or 64 bytes');
      
      const bytes48 = new Uint8Array(48);
      expect(() => uint8ArrayToWords(bytes48)).toThrow('Expected 32 or 64 bytes');
    });

    it('should reject invalid word counts', () => {
      const words12 = Array(12).fill('abandon');
      expect(() => wordsToUint8Array(words12)).toThrow('Expected 24 or 48 words');
      
      const words36 = Array(36).fill('abandon');
      expect(() => wordsToUint8Array(words36)).toThrow('Expected 24 or 48 words');
    });
  });
});