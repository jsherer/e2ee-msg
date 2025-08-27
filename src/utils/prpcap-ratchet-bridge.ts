/**
 * PRP-Cap to Double Ratchet Bridge
 * Handles the transition from 0-RTT PRP-Cap to Double Ratchet protocol
 */

import * as nacl from 'tweetnacl';
import { PRPCapKeyPair } from '../types';
import { RatchetState } from '../types/ratchet';
import {
  initializeEd25519,
  createPRPCapMessage,
  processPRPCapMessage,
  PRPCapMessage,
  PRPCapEpoch
} from './prpcap';

/**
 * Initial message payload that establishes Double Ratchet
 */
export interface RatchetInitPayload {
  // Sender's ephemeral public key for ratchet
  ephemeralPublicKey: Uint8Array;
  // Sender's identity public key
  identityPublicKey: Uint8Array;
  // Initial message content
  message: string;
  // Protocol version
  version: number;
}

/**
 * PRP-Cap enhanced initial message
 */
export interface PRPCapInitialMessage extends PRPCapMessage {
  // Additional metadata
  senderIdentity: Uint8Array;
  timestamp: number;
  protocolVersion: number;
}

/**
 * Create an initial message using PRP-Cap for 0-RTT encryption
 * This message establishes a Double Ratchet session
 */
export async function createPRPCapInitialMessage(
  message: string,
  senderKeypair: PRPCapKeyPair,
  recipientPublicKey: Uint8Array,
  recipientEpochA: Uint8Array,
  recipientEpochB: Uint8Array
): Promise<PRPCapInitialMessage> {
  // Generate ephemeral keypair for Double Ratchet
  const ratchetEphemeral = nacl.box.keyPair();
  
  // Create payload for ratchet initialization
  const payload: RatchetInitPayload = {
    ephemeralPublicKey: ratchetEphemeral.publicKey,
    identityPublicKey: senderKeypair.publicKey,
    message,
    version: 1
  };
  
  // Serialize payload (convert Uint8Arrays to arrays for JSON)
  const payloadForJson = {
    ...payload,
    ephemeralPublicKey: Array.from(payload.ephemeralPublicKey),
    identityPublicKey: Array.from(payload.identityPublicKey)
  };
  const payloadBytes = new TextEncoder().encode(JSON.stringify(payloadForJson));
  
  // Create PRP-Cap message
  const prpcapMsg = await createPRPCapMessage(
    payloadBytes,
    recipientEpochA,
    recipientEpochB
  );
  
  // Add metadata
  return {
    ...prpcapMsg,
    senderIdentity: senderKeypair.publicKey,
    timestamp: Date.now(),
    protocolVersion: 1
  };
}

/**
 * Process a PRP-Cap initial message and establish Double Ratchet
 */
export async function processPRPCapInitialMessage(
  message: PRPCapInitialMessage,
  recipientKeypair: PRPCapKeyPair
): Promise<{ payload: RatchetInitPayload; ratchetState: RatchetState } | null> {
  // Check if we have epoch parameters
  if (!recipientKeypair.epoch || !recipientKeypair.epoch.s1 || !recipientKeypair.epoch.s2) {
    throw new Error('Missing epoch parameters for PRP-Cap decryption');
  }
  
  // Create PRPCapEpoch from our keypair
  const epoch: PRPCapEpoch = {
    A: recipientKeypair.epoch.A,
    B: recipientKeypair.epoch.B,
    s1: recipientKeypair.epoch.s1,
    s2: recipientKeypair.epoch.s2
  };
  
  // Decrypt the message using PRP-Cap
  const decryptedBytes = await processPRPCapMessage(message, epoch);
  
  if (!decryptedBytes) {
    return null;
  }
  
  // Parse the payload
  const payloadStr = new TextDecoder().decode(decryptedBytes);
  const payloadData = JSON.parse(payloadStr);
  
  // Convert arrays back to Uint8Arrays
  const payload: RatchetInitPayload = {
    ...payloadData,
    identityPublicKey: new Uint8Array(payloadData.identityPublicKey),
    ephemeralPublicKey: new Uint8Array(payloadData.ephemeralPublicKey)
  };
  
  // Initialize Double Ratchet state from the shared secret
  const ratchetState = await initializeRatchetFromPRPCap(
    recipientKeypair,
    payload.identityPublicKey,
    payload.ephemeralPublicKey,
    message
  );
  
  return { payload, ratchetState };
}

/**
 * Initialize Double Ratchet from PRP-Cap shared secret
 */
export async function initializeRatchetFromPRPCap(
  myKeypair: PRPCapKeyPair,
  theirIdentityPublicKey: Uint8Array,
  theirEphemeralPublicKey: Uint8Array,
  prpcapMessage: PRPCapInitialMessage
): Promise<RatchetState> {
  // Generate our ephemeral for ratchet
  const myEphemeral = nacl.box.keyPair();
  
  // Compute initial shared secret using standard DH
  const dh1 = nacl.box.before(theirIdentityPublicKey, myKeypair.secretKey);
  const dh2 = nacl.box.before(theirEphemeralPublicKey, myKeypair.secretKey);
  const dh3 = nacl.box.before(theirEphemeralPublicKey, myEphemeral.secretKey);
  
  // Combine DHs for root key derivation
  const combined = new Uint8Array(dh1.length + dh2.length + dh3.length);
  combined.set(dh1, 0);
  combined.set(dh2, dh1.length);
  combined.set(dh3, dh1.length + dh2.length);
  
  const hashedSecret = nacl.hash(combined);
  const rootKey = hashedSecret.slice(0, 32);
  const initialChainKey = hashedSecret.slice(32, 64);
  
  // Initialize ratchet state
  const state: RatchetState = {
    myIdentityKeyPair: {
      publicKey: myKeypair.publicKey,
      secretKey: myKeypair.secretKey
    },
    theirIdentityPublicKey,
    myCurrentEphemeralKeyPair: myEphemeral,
    theirLatestEphemeralPublicKey: theirEphemeralPublicKey,
    hasRatchetedForTheirEphemeral: false,
    rootKey,
    sendingChainKey: new Uint8Array(initialChainKey),
    receivingChainKey: new Uint8Array(initialChainKey),
    sendMessageCounter: 0,
    receiveMessageCounter: 0,
    previousSendCounter: 0,
    skippedMessageKeys: new Map(),
    previousReceivingChains: new Map(),
    isInitialized: true
  };
  
  // Clear sensitive data
  dh1.fill(0);
  dh2.fill(0);
  dh3.fill(0);
  combined.fill(0);
  
  return state;
}

/**
 * Check if a peer supports PRP-Cap
 */
export function supportsPRPCap(peerPublicData: any): boolean {
  return !!(peerPublicData?.epoch?.A && peerPublicData?.epoch?.B);
}

/**
 * Extract epoch parameters from public key data
 */
export function extractEpochParams(publicKeyData: any): { A: Uint8Array; B: Uint8Array } | null {
  if (!publicKeyData?.epoch?.A || !publicKeyData?.epoch?.B) {
    return null;
  }
  
  return {
    A: publicKeyData.epoch.A,
    B: publicKeyData.epoch.B
  };
}