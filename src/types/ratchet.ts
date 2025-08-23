/**
 * Double Ratchet Protocol Types
 */

import { KeyPair } from './index';

export interface RatchetState {
  // Identity keys (long-term)
  myIdentityKeyPair: KeyPair;
  theirIdentityPublicKey: Uint8Array;
  
  // Ephemeral keys
  myCurrentEphemeralKeyPair: KeyPair;
  theirLatestEphemeralPublicKey: Uint8Array | null;
  
  // Chain keys
  rootKey: Uint8Array;           // 32 bytes
  sendingChainKey: Uint8Array;   // 32 bytes
  receivingChainKey: Uint8Array; // 32 bytes
  
  // Counters
  sendMessageCounter: number;
  receiveMessageCounter: number;
  previousSendCounter: number;
  
  // Skipped message keys (for out-of-order delivery)
  skippedMessageKeys: Map<string, Uint8Array>;
  
  // Session state
  isInitialized: boolean;
}

export interface RatchetMessage {
  version: number;
  ephemeralPublicKey: Uint8Array;
  previousChainCounter: number;
  messageCounter: number;
  nonce: Uint8Array;
  encryptedPayload: Uint8Array;
}

export interface RatchetOperation {
  timestamp: number;
  type: 'init' | 'encrypt' | 'decrypt' | 'dh-ratchet' | 'skip-messages' | 'error';
  details: string;
}

export interface SerializedRatchetState {
  encrypted: Uint8Array;
  nonce: Uint8Array;
}