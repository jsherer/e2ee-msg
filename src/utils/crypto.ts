/**
 * Cryptographic utility functions wrapping TweetNaCl
 */

import * as nacl from 'tweetnacl';

export interface KeyPair {
  publicKey: Uint8Array;
  secretKey: Uint8Array;
}

export const generateKeyPair = (): KeyPair => {
  return nacl.box.keyPair();
};

export const generateKeyPairFromSecretKey = (secretKey: Uint8Array): KeyPair => {
  return nacl.box.keyPair.fromSecretKey(secretKey);
};

export const deriveKeyFromMasterKey = (masterKey: string): Uint8Array => {
  const masterKeyBytes = new TextEncoder().encode(masterKey);
  return nacl.hash(masterKeyBytes).slice(0, nacl.secretbox.keyLength);
};

export const encryptSecretKey = (secretKey: Uint8Array, masterKey: string): Uint8Array => {
  const hashedKey = deriveKeyFromMasterKey(masterKey);
  const nonce = nacl.randomBytes(nacl.secretbox.nonceLength);
  const encrypted = nacl.secretbox(secretKey, nonce, hashedKey);
  
  // Combine nonce and encrypted data
  const fullMessage = new Uint8Array(nonce.length + encrypted.length);
  fullMessage.set(nonce);
  fullMessage.set(encrypted, nonce.length);
  
  return fullMessage;
};

export const decryptSecretKey = (encryptedData: Uint8Array, masterKey: string): Uint8Array | null => {
  const hashedKey = deriveKeyFromMasterKey(masterKey);
  const nonce = encryptedData.slice(0, nacl.secretbox.nonceLength);
  const encrypted = encryptedData.slice(nacl.secretbox.nonceLength);
  
  return nacl.secretbox.open(encrypted, nonce, hashedKey);
};

export const encryptMessage = (
  message: string,
  recipientPublicKey: Uint8Array,
  senderSecretKey: Uint8Array
): Uint8Array => {
  const nonce = nacl.randomBytes(nacl.box.nonceLength);
  const messageUint8 = new TextEncoder().encode(message);
  const encrypted = nacl.box(messageUint8, nonce, recipientPublicKey, senderSecretKey);
  
  const fullMessage = new Uint8Array(nonce.length + encrypted.length);
  fullMessage.set(nonce);
  fullMessage.set(encrypted, nonce.length);
  
  return fullMessage;
};

export const decryptMessage = (
  encryptedData: Uint8Array,
  senderPublicKey: Uint8Array,
  recipientSecretKey: Uint8Array
): string | null => {
  const nonce = encryptedData.slice(0, nacl.box.nonceLength);
  const encrypted = encryptedData.slice(nacl.box.nonceLength);
  
  const decrypted = nacl.box.open(encrypted, nonce, senderPublicKey, recipientSecretKey);
  
  if (!decrypted) {
    return null;
  }
  
  return new TextDecoder().decode(decrypted);
};