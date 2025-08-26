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
  hasRatchetedForTheirEphemeral: boolean;  // Track if we've ratcheted for their current ephemeral
  
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
  
  // Previous receiving chains (for out-of-order messages across chain boundaries)
  // Map from ephemeral public key string to chain state
  previousReceivingChains: Map<string, {
    chainKey: Uint8Array;
    messageCounter: number;
  }>;
  
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