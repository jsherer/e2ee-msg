/**
 * Cryptographic utility functions wrapping TweetNaCl
 */

import * as nacl from 'tweetnacl';
import { PRPCapKeyPair } from '../types';
import { generatePRPCapEpoch, initializeEd25519 } from './prpcap';

export interface KeyPair {
  publicKey: Uint8Array;
  secretKey: Uint8Array;
}

export const generateKeyPair = (): KeyPair => {
  return nacl.box.keyPair();
};

/**
 * Generate a PRP-Cap enabled keypair with epoch parameters
 * This allows 0-RTT encryption for the first message
 */
export const generatePRPCapKeyPair = async (): Promise<PRPCapKeyPair> => {
  // Generate standard X25519 keypair
  const keypair = generateKeyPair();
  
  // Initialize Ed25519 for PRP-Cap
  await initializeEd25519();
  
  // Generate PRP-Cap epoch parameters
  const epoch = await generatePRPCapEpoch();
  
  return {
    publicKey: keypair.publicKey,
    secretKey: keypair.secretKey,
    epoch: {
      A: epoch.A,
      B: epoch.B,
      s1: epoch.s1,
      s2: epoch.s2,
      validFrom: Date.now(),
      validUntil: Date.now() + (30 * 24 * 60 * 60 * 1000), // 30 days
      epochId: Array.from(nacl.hash(new Uint8Array([...epoch.A, ...epoch.B])).slice(0, 16))
        .map(b => b.toString(16).padStart(2, '0'))
        .join('')
    }
  };
};

/**
 * Generate a PRP-Cap enabled keypair from an existing secret key
 * This generates new epoch parameters (since they're independent of the identity key)
 */
export const generatePRPCapKeyPairFromSecretKey = async (
  secretKey: Uint8Array,
  existingEpoch?: {
    A: Uint8Array;
    B: Uint8Array;
    s1?: Uint8Array;
    s2?: Uint8Array;
    validFrom: number;
    validUntil: number;
    epochId: string;
  }
): Promise<PRPCapKeyPair> => {
  // Restore the X25519 keypair from secret key
  const keypair = generateKeyPairFromSecretKey(secretKey);
  
  // If we have existing epoch parameters, use them
  if (existingEpoch) {
    return {
      publicKey: keypair.publicKey,
      secretKey: keypair.secretKey,
      epoch: existingEpoch
    };
  }
  
  // Otherwise generate new epoch parameters
  await initializeEd25519();
  const newEpoch = await generatePRPCapEpoch();
  
  return {
    publicKey: keypair.publicKey,
    secretKey: keypair.secretKey,
    epoch: {
      A: newEpoch.A,
      B: newEpoch.B,
      s1: newEpoch.s1,
      s2: newEpoch.s2,
      validFrom: Date.now(),
      validUntil: Date.now() + (30 * 24 * 60 * 60 * 1000), // 30 days
      epochId: Array.from(nacl.hash(new Uint8Array([...newEpoch.A, ...newEpoch.B])).slice(0, 16))
        .map(b => b.toString(16).padStart(2, '0'))
        .join('')
    }
  };
};

export const generateKeyPairFromSecretKey = (secretKey: Uint8Array): KeyPair => {
  return nacl.box.keyPair.fromSecretKey(secretKey);
};

export const deriveKeyFromMasterKey = (masterKey: string): Uint8Array => {
  const masterKeyBytes = new TextEncoder().encode(masterKey);
  // Ensure it's a real Uint8Array (not a Node Buffer)
  const bytes = new Uint8Array(masterKeyBytes);
  return nacl.hash(bytes).slice(0, nacl.secretbox.keyLength);
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
  const messageBytes = new TextEncoder().encode(message);
  // Ensure it's a real Uint8Array (not a Node Buffer)
  const messageUint8 = new Uint8Array(messageBytes);
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
