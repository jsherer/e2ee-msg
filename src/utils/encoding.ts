/**
 * Encoding utilities for converting between different formats
 */

export const uint8ArrayToBase36 = (arr: Uint8Array): string => {
  let bigInt = BigInt(0);
  for (let i = 0; i < arr.length; i++) {
    bigInt = (bigInt << BigInt(8)) | BigInt(arr[i]);
  }
  return bigInt.toString(36).toLowerCase();
};

export const base36ToUint8Array = (str: string, expectedLength?: number): Uint8Array => {
  const cleanStr = str.replace(/\s/g, '');
  let bigInt = BigInt(0);
  for (let i = 0; i < cleanStr.length; i++) {
    bigInt = bigInt * BigInt(36) + BigInt(parseInt(cleanStr[i], 36));
  }
  const hex = bigInt.toString(16);
  const paddedHex = hex.padStart((expectedLength || 32) * 2, '0');
  const arr = new Uint8Array(expectedLength || Math.ceil(paddedHex.length / 2));
  for (let i = 0; i < arr.length; i++) {
    arr[i] = parseInt(paddedHex.substr(i * 2, 2), 16);
  }
  return arr;
};

export const formatInGroups = (str: string): string => {
  return str.match(/.{1,5}/g)?.join(' ') || str;
};

export const generateUserId = (publicKey: Uint8Array): string => {
  // Import nacl dynamically to avoid circular dependency
  const nacl = require('tweetnacl');
  const hash = nacl.hash(publicKey);
  const idBytes = hash.slice(0, 8);
  const hexId = Array.from(idBytes as Uint8Array)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
  return hexId.match(/.{1,4}/g)?.join('-') || hexId;
};