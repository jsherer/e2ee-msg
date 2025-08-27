/**
 * PRP-Cap Protocol Core Implementation
 * Implements the Pseudorandom Permutation Capability protocol for 0-RTT key exchange
 */

import * as nacl from 'tweetnacl';

// Use nacl.hash for SHA-512 instead of @noble/hashes to avoid module issues  
const sha512 = (data: Uint8Array): Uint8Array => nacl.hash(data);
import { 
  generateScalar, 
  scalarMultBase, 
  pointAdd, 
  scalarMultPoint,
  scalarAdd,
  scalarMult,
  hashToScalar,
  ed25519DH,
  bytesToNumberLE,
  numberToBytesLE,
  secureErase
} from './ed25519-ops';
import {
  EpochParams,
  PublicEpochInfo,
  PRPCapIdentity,
  InitialMessage,
  CreateMessageParams,
  ProcessMessageResult,
  PRPCapSession,
  PRPCapSessionState,
  PRPCapConfig
} from '../types/prpcap';

/**
 * Default configuration for PRP-Cap protocol
 */
export const DEFAULT_CONFIG: PRPCapConfig = {
  epochDuration: 30 * 24 * 60 * 60 * 1000,  // 30 days
  detectionWindow: 30 * 1000,               // 30 seconds
  indexSpace: 2 ** 32,                      // 4 billion indices
  maxSkippedIndices: 1000,
  domain: 'PRP-CAP-v1',
  singleLadderContext: 'SingleLadder',
  doubleLadderContext: 'DoubleLadder'
};

/**
 * Generate new epoch parameters
 */
export function generateEpochParams(
  validFrom?: number, 
  duration: number = DEFAULT_CONFIG.epochDuration
): EpochParams {
  // Generate random scalars
  const s1 = generateScalar();
  const s2 = generateScalar();
  
  // Compute public points
  const A = scalarMultBase(s1);
  const B = scalarMultBase(s2);
  
  // Set validity period
  const now = Date.now();
  const from = validFrom || now;
  const until = from + duration;
  
  // Generate epoch ID
  const epochData = new Uint8Array(64);
  epochData.set(A, 0);
  epochData.set(B, 32);
  const epochId = Array.from(sha512(epochData).slice(0, 16))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
  
  return {
    A,
    B,
    s1,
    s2,
    validFrom: from,
    validUntil: until,
    epochId
  };
}

/**
 * Extract public information from epoch params
 */
export function getPublicEpochInfo(params: EpochParams): PublicEpochInfo {
  return {
    A: params.A,
    B: params.B,
    validFrom: params.validFrom,
    validUntil: params.validUntil,
    epochId: params.epochId
  };
}

/**
 * Compute PRP Capability: V_i = A + t_i·B
 */
export function computePRPCap(
  A: Uint8Array,
  B: Uint8Array,
  index: number,
  domain: string = DEFAULT_CONFIG.domain
): Uint8Array {
  // Prepare hash input: domain || index || A || B
  const domainBytes = new TextEncoder().encode(domain);
  const indexBytes = new Uint8Array(4);
  new DataView(indexBytes.buffer).setUint32(0, index, false);
  
  const hashInput = new Uint8Array(domainBytes.length + 4 + 64);
  hashInput.set(domainBytes, 0);
  hashInput.set(indexBytes, domainBytes.length);
  hashInput.set(A, domainBytes.length + 4);
  hashInput.set(B, domainBytes.length + 36);
  
  // Compute t_i = H(domain || i || A || B)
  const t_i = hashToScalar(hashInput);
  
  // Compute V_i = A + t_i·B
  const tiB = scalarMultPoint(t_i, B);
  const V_i = pointAdd(A, tiB);
  
  return V_i;
}

/**
 * Compute private scalar for V_i
 * v_i = s1 + t_i·s2 (mod n)
 */
export function computePrivateScalarForVi(
  s1: Uint8Array,
  s2: Uint8Array,
  A: Uint8Array,
  B: Uint8Array,
  index: number,
  domain: string = DEFAULT_CONFIG.domain
): Uint8Array {
  // Prepare hash input (same as computePRPCap)
  const domainBytes = new TextEncoder().encode(domain);
  const indexBytes = new Uint8Array(4);
  new DataView(indexBytes.buffer).setUint32(0, index, false);
  
  const hashInput = new Uint8Array(domainBytes.length + 4 + 64);
  hashInput.set(domainBytes, 0);
  hashInput.set(indexBytes, domainBytes.length);
  hashInput.set(A, domainBytes.length + 4);
  hashInput.set(B, domainBytes.length + 36);
  
  // Compute t_i
  const t_i = hashToScalar(hashInput);
  
  // Compute v_i = s1 + t_i·s2 (mod n)
  const ti_s2 = scalarMult(t_i, s2);
  const v_i = scalarAdd(s1, ti_s2);
  
  return v_i;
}

/**
 * Generate a random or timestamp-based index
 */
export function generateIndex(useTimestamp: boolean = false): number {
  if (useTimestamp) {
    // Use current timestamp as index (seconds since epoch)
    return Math.floor(Date.now() / 1000);
  } else {
    // Generate random index
    const bytes = new Uint8Array(4);
    crypto.getRandomValues(bytes);
    return new DataView(bytes.buffer).getUint32(0, false);
  }
}

/**
 * Create an initial 0-RTT message
 */
export async function createInitialMessage(
  params: CreateMessageParams,
  config: PRPCapConfig = DEFAULT_CONFIG
): Promise<InitialMessage> {
  // Extract recipient's epoch info
  const recipientEpoch = params.recipientIdentity.currentEpoch;
  if (!('A' in recipientEpoch && 'B' in recipientEpoch)) {
    throw new Error('Recipient epoch information incomplete');
  }
  
  // Generate ephemeral keypair
  const ephemeralScalar = generateScalar();
  const ephemeralPublic = scalarMultBase(ephemeralScalar);
  
  // Select index
  const index = params.index ?? generateIndex();
  
  // Compute V_i for recipient
  const V_i = computePRPCap(recipientEpoch.A, recipientEpoch.B, index, config.domain);
  
  // Compute shared secret: DH(e, V_i)
  const sharedPoint = ed25519DH(ephemeralScalar, V_i);
  const sharedSecret = sha512(sharedPoint).slice(0, 32);
  
  // Derive encryption key
  const encryptionKey = sha512(
    new Uint8Array([
      ...sharedSecret,
      ...new TextEncoder().encode(config.singleLadderContext)
    ])
  ).slice(0, 32);
  
  // Encrypt message
  const nonce = nacl.randomBytes(nacl.secretbox.nonceLength);
  const ciphertext = nacl.secretbox(params.plaintext, nonce, encryptionKey);
  
  // Create message structure
  const messageId = nacl.randomBytes(16);
  const timestamp = Date.now();
  
  const message: InitialMessage = {
    version: 1,
    messageId,
    timestamp,
    ephemeralPublicKey: ephemeralPublic,
    capabilityPoint: V_i,
    index,
    ciphertext,
    nonce,
    signature: new Uint8Array(0), // Will be filled below
    senderIdentity: params.myIdentity.identityPublicKey
  };
  
  // Sign the message (if we have the secret key)
  if (params.myIdentity.identitySecretKey) {
    const dataToSign = new Uint8Array(
      8 + // version (as 64-bit)
      16 + // messageId
      8 + // timestamp (as 64-bit)
      32 + // ephemeralPublicKey
      32 + // capabilityPoint
      4 + // index
      ciphertext.length +
      nonce.length
    );
    
    let offset = 0;
    const view = new DataView(dataToSign.buffer);
    
    // Pack data for signing
    view.setBigUint64(offset, BigInt(message.version), false);
    offset += 8;
    dataToSign.set(messageId, offset);
    offset += 16;
    view.setBigUint64(offset, BigInt(timestamp), false);
    offset += 8;
    dataToSign.set(ephemeralPublic, offset);
    offset += 32;
    dataToSign.set(V_i, offset);
    offset += 32;
    view.setUint32(offset, index, false);
    offset += 4;
    dataToSign.set(ciphertext, offset);
    offset += ciphertext.length;
    dataToSign.set(nonce, offset);
    
    // Sign with identity key
    message.signature = (nacl.sign as any).detached(dataToSign, params.myIdentity.identitySecretKey);
  }
  
  // Clean up ephemeral secret
  secureErase(ephemeralScalar);
  
  return message;
}

/**
 * Process a received initial message
 */
export async function processInitialMessage(
  message: InitialMessage,
  myIdentity: PRPCapIdentity,
  peerIdentity: PRPCapIdentity,
  config: PRPCapConfig = DEFAULT_CONFIG
): Promise<ProcessMessageResult> {
  try {
    // Verify message version
    if (message.version !== 1) {
      return { success: false, error: 'Unsupported protocol version' };
    }
    
    // Verify signature
    const dataToVerify = new Uint8Array(
      8 + 16 + 8 + 32 + 32 + 4 + 
      message.ciphertext.length + message.nonce.length
    );
    
    let offset = 0;
    const view = new DataView(dataToVerify.buffer);
    view.setBigUint64(offset, BigInt(message.version), false);
    offset += 8;
    dataToVerify.set(message.messageId, offset);
    offset += 16;
    view.setBigUint64(offset, BigInt(message.timestamp), false);
    offset += 8;
    dataToVerify.set(message.ephemeralPublicKey, offset);
    offset += 32;
    dataToVerify.set(message.capabilityPoint, offset);
    offset += 32;
    view.setUint32(offset, message.index, false);
    offset += 4;
    dataToVerify.set(message.ciphertext, offset);
    offset += message.ciphertext.length;
    dataToVerify.set(message.nonce, offset);
    
    const validSignature = (nacl.sign as any).detached.verify(
      dataToVerify,
      message.signature,
      peerIdentity.verificationKey
    );
    
    if (!validSignature) {
      return { success: false, error: 'Invalid signature' };
    }
    
    // Check if we have the private epoch params
    const myEpoch = myIdentity.currentEpoch;
    if (!('s1' in myEpoch && 's2' in myEpoch)) {
      return { success: false, error: 'Missing private epoch parameters' };
    }
    
    // Compute v_i for the received index
    const v_i = computePrivateScalarForVi(
      myEpoch.s1,
      myEpoch.s2,
      myEpoch.A,
      myEpoch.B,
      message.index,
      config.domain
    );
    
    // Compute shared secret: DH(v_i, E)
    const sharedPoint = ed25519DH(v_i, message.ephemeralPublicKey);
    const sharedSecret = sha512(sharedPoint).slice(0, 32);
    
    // Derive decryption key
    const decryptionKey = sha512(
      new Uint8Array([
        ...sharedSecret,
        ...new TextEncoder().encode(config.singleLadderContext)
      ])
    ).slice(0, 32);
    
    // Decrypt message
    const plaintext = nacl.secretbox.open(
      message.ciphertext,
      message.nonce,
      decryptionKey
    );
    
    if (!plaintext) {
      return { success: false, error: 'Decryption failed' };
    }
    
    // Create session
    const session: PRPCapSession = {
      sessionId: Array.from(message.messageId)
        .map(b => b.toString(16).padStart(2, '0'))
        .join(''),
      peerIdentity: peerIdentity.identityPublicKey,
      state: PRPCapSessionState.SINGLE_LADDER,
      createdAt: Date.now(),
      lastActivity: Date.now(),
      ladderType: 'single',
      theirEphemeral: message.ephemeralPublicKey,
      sharedSecret,
      receivedInitial: message,
      usedIndices: new Set([message.index])
    };
    
    // Clean up
    secureErase(v_i);
    
    return {
      success: true,
      session,
      plaintext
    };
    
  } catch (error) {
    return {
      success: false,
      error: error instanceof Error ? error.message : 'Unknown error'
    };
  }
}

/**
 * Merge two ladder shared secrets for double ladder mode
 */
export function mergeLadders(
  ladder1: Uint8Array,
  ladder2: Uint8Array,
  ephemeral1: Uint8Array,
  ephemeral2: Uint8Array,
  context: string = DEFAULT_CONFIG.doubleLadderContext
): Uint8Array {
  // Sort deterministically based on ephemeral public keys
  const e1Num = bytesToNumberLE(ephemeral1.slice(0, 8));
  const e2Num = bytesToNumberLE(ephemeral2.slice(0, 8));
  
  let first: Uint8Array, second: Uint8Array;
  if (e1Num < e2Num) {
    first = ladder1;
    second = ladder2;
  } else {
    first = ladder2;
    second = ladder1;
  }
  
  // Combine with context
  const combined = new Uint8Array(
    first.length + second.length + context.length
  );
  combined.set(first, 0);
  combined.set(second, first.length);
  combined.set(new TextEncoder().encode(context), first.length + second.length);
  
  // Final root key derivation
  return sha512(combined).slice(0, 32);
}

/**
 * Delete epoch's s2 parameter for forward secrecy
 */
export function deleteEpochS2(params: EpochParams): void {
  if (params.s2) {
    secureErase(params.s2);
    // Set to empty array to indicate it's been deleted
    params.s2 = new Uint8Array(0);
  }
}

/**
 * Check if an epoch is currently valid
 */
export function isEpochValid(epoch: PublicEpochInfo | EpochParams): boolean {
  const now = Date.now();
  return now >= epoch.validFrom && now <= epoch.validUntil;
}

/**
 * Check if two messages indicate simultaneous initiation
 */
export function detectSimultaneousInitiation(
  sent: InitialMessage,
  received: InitialMessage,
  windowMs: number = DEFAULT_CONFIG.detectionWindow
): boolean {
  const timeDiff = Math.abs(sent.timestamp - received.timestamp);
  return timeDiff <= windowMs;
}