import {
  uint8ArrayToBase36,
  base36ToUint8Array,
  formatInGroups,
  generateUserId
} from '../../utils/encoding';

describe('encoding utilities', () => {
  describe('uint8ArrayToBase36', () => {
    it('should convert a Uint8Array to base36 string', () => {
      const input = new Uint8Array([0, 1, 2, 3, 4]);
      const result = uint8ArrayToBase36(input);
      expect(result).toBe('a2f44');
    });

    it('should handle empty array', () => {
      const input = new Uint8Array([]);
      const result = uint8ArrayToBase36(input);
      expect(result).toBe('0');
    });

    it('should handle all zeros', () => {
      const input = new Uint8Array([0, 0, 0, 0]);
      const result = uint8ArrayToBase36(input);
      expect(result).toBe('0');
    });

    it('should handle max values', () => {
      const input = new Uint8Array([255, 255, 255, 255]);
      const result = uint8ArrayToBase36(input);
      expect(result).toBe('1z141z3');
    });
  });

  describe('base36ToUint8Array', () => {
    it('should convert base36 string back to Uint8Array', () => {
      const input = 'a2f44';
      const result = base36ToUint8Array(input, 5);
      expect(result).toEqual(new Uint8Array([0, 1, 2, 3, 4]));
    });

    it('should handle strings with spaces', () => {
      const input = 'a2 f44';  // Same as 'a2f44' but with space
      const result = base36ToUint8Array(input, 5);
      expect(result).toEqual(new Uint8Array([0, 1, 2, 3, 4]));
    });

    it('should pad to expected length', () => {
      const input = '1';
      const result = base36ToUint8Array(input, 4);
      expect(result.length).toBe(4);
      expect(result[3]).toBe(1);
    });
  });

  describe('round-trip conversion', () => {
    it('should convert back and forth correctly', () => {
      const original = new Uint8Array(32);
      crypto.getRandomValues(original);
      
      const base36 = uint8ArrayToBase36(original);
      const restored = base36ToUint8Array(base36, 32);
      
      expect(restored).toEqual(original);
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
  });

  describe('generateUserId', () => {
    it('should generate a formatted user ID', () => {
      const publicKey = new Uint8Array(32);
      publicKey.fill(42); // Fill with test data
      
      const result = generateUserId(publicKey);
      
      expect(result).toMatch(/^[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}$/);
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