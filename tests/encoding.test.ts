import {
  uint8ArrayToBase32Crockford,
  base32CrockfordToUint8Array,
  formatInGroups,
  generateUserId
} from '../src/utils/encoding';

describe('encoding utilities', () => {
  describe('uint8ArrayToBase32Crockford', () => {
    it('should convert a Uint8Array to base32 Crockford string', () => {
      const input = new Uint8Array([0, 1, 2, 3, 4]);
      const result = uint8ArrayToBase32Crockford(input);
      expect(result).toBe('000G40R4');
    });

    it('should handle empty array', () => {
      const input = new Uint8Array([]);
      const result = uint8ArrayToBase32Crockford(input);
      expect(result).toBe('');
    });

    it('should handle all zeros', () => {
      const input = new Uint8Array([0, 0, 0, 0]);
      const result = uint8ArrayToBase32Crockford(input);
      expect(result).toBe('0000000');
    });

    it('should handle max values', () => {
      const input = new Uint8Array([255, 255, 255, 255]);
      const result = uint8ArrayToBase32Crockford(input);
      expect(result).toBe('ZZZZZZR');
    });
  });

  describe('base32CrockfordToUint8Array', () => {
    it('should convert base32 Crockford string back to Uint8Array', () => {
      const input = '000G40R4';
      const result = base32CrockfordToUint8Array(input);
      expect(result).toEqual(new Uint8Array([0, 1, 2, 3, 4]));
    });

    it('should handle strings with spaces', () => {
      const input = '000G 40R4';  // Same as '000G40R4' but with space
      const result = base32CrockfordToUint8Array(input);
      expect(result).toEqual(new Uint8Array([0, 1, 2, 3, 4]));
    });

    it('should handle ambiguous characters', () => {
      // Crockford base32 treats O as 0, I/L as 1
      const input1 = 'O00G40R4'; // O instead of first 0
      const result1 = base32CrockfordToUint8Array(input1);
      expect(result1).toEqual(new Uint8Array([0, 1, 2, 3, 4]));
      
      const input2 = '0O0G40R4'; // O instead of second 0
      const result2 = base32CrockfordToUint8Array(input2);
      expect(result2).toEqual(new Uint8Array([0, 1, 2, 3, 4]));
    });
  });

  describe('round-trip conversion', () => {
    it('should convert back and forth correctly', () => {
      const original = new Uint8Array(32);
      crypto.getRandomValues(original);
      
      const base32 = uint8ArrayToBase32Crockford(original);
      const restored = base32CrockfordToUint8Array(base32);
      
      expect(restored).toEqual(original);
    });

    it('should handle various sizes', () => {
      for (const size of [1, 5, 10, 32, 64, 100]) {
        const original = new Uint8Array(size);
        crypto.getRandomValues(original);
        
        const base32 = uint8ArrayToBase32Crockford(original);
        const restored = base32CrockfordToUint8Array(base32);
        
        expect(restored).toEqual(original);
      }
    });
  });

  describe('formatInGroups', () => {
    it('should format string in groups of 5', () => {
      const input = 'abcdefghijklmnop';
      const result = formatInGroups(input);
      expect(result).toBe('abcde fghij klmno p');
    });

    it('should handle empty string', () => {
      const input = '';
      const result = formatInGroups(input);
      expect(result).toBe('');
    });

    it('should handle string shorter than 5 chars', () => {
      const input = 'abc';
      const result = formatInGroups(input);
      expect(result).toBe('abc');
    });

    it('should handle exact multiple of 5', () => {
      const input = 'abcdefghij';
      const result = formatInGroups(input);
      expect(result).toBe('abcde fghij');
    });

    it('should add newlines every 5 groups when addNewlines is true', () => {
      const input = 'abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJK';
      const result = formatInGroups(input, true);
      expect(result).toBe('abcde fghij klmno pqrst uvwxy\nz0123 45678 9ABCD EFGHI JK');
    });

    it('should format with newlines for exactly 25 chars', () => {
      const input = 'abcdefghijklmnopqrstuvwxy';
      const result = formatInGroups(input, true);
      expect(result).toBe('abcde fghij klmno pqrst uvwxy');
    });

    it('should handle short string with newlines flag', () => {
      const input = 'abc';
      const result = formatInGroups(input, true);
      expect(result).toBe('abc');
    });
  });

  describe('generateUserId', () => {
    it('should generate a formatted user ID', () => {
      const publicKey = new Uint8Array(32);
      publicKey.fill(42); // Fill with test data
      
      const result = generateUserId(publicKey);
      
      expect(result).toMatch(/^[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}$/);
    });

    it('should generate consistent ID for same key', () => {
      const publicKey = new Uint8Array(32);
      publicKey.fill(123);
      
      const id1 = generateUserId(publicKey);
      const id2 = generateUserId(publicKey);
      
      expect(id1).toBe(id2);
    });

    it('should generate different IDs for different keys', () => {
      const key1 = new Uint8Array(32);
      key1.fill(1);
      
      const key2 = new Uint8Array(32);
      key2.fill(2);
      
      const id1 = generateUserId(key1);
      const id2 = generateUserId(key2);
      
      expect(id1).not.toBe(id2);
    });
  });
});