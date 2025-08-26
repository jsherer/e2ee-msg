import '@testing-library/jest-dom';
import crypto from 'crypto';
import { TextEncoder, TextDecoder } from 'util';

// Add TextEncoder/TextDecoder to global
global.TextEncoder = TextEncoder as any;
global.TextDecoder = TextDecoder as any;

// Mock crypto API for tests
const webcrypto = crypto.webcrypto || (crypto as any);
Object.defineProperty(global, 'crypto', {
  value: {
    getRandomValues: (arr: Uint8Array) => {
      const bytes = crypto.randomBytes(arr.length);
      arr.set(bytes);
      return arr;
    },
    subtle: webcrypto.subtle
  }
});

// Mock clipboard API
Object.assign(navigator, {
  clipboard: {
    writeText: jest.fn(),
    write: jest.fn(),
  },
});

// Mock window.location.hash
delete (window as any).location;
window.location = { hash: '' } as any;

// Mock window.confirm
window.confirm = jest.fn(() => true);

// Mock window.alert
window.alert = jest.fn();