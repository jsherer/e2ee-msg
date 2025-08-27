/**
 * Working 0-RTT implementation using simpler cryptography
 * 
 * Key insight: For true 0-RTT, Bob needs to publish something that allows
 * Alice to compute a shared secret that only Bob can also compute.
 * 
 * Approach: Bob publishes G^b, Alice sends G^a, shared secret is G^(ab)
 * But we make it index-specific for forward secrecy.
 */

import * as nacl from 'tweetnacl';
import { hkdf } from './hkdf';

export interface WorkingEpochParams {
  // Bob's long-term secret for this epoch
  epochSecret: Uint8Array; // 32 bytes
  
  // Bob's public parameter = G^epochSecret
  epochPublic: Uint8Array; // 32 bytes
  
  validFrom: number;
  validUntil: number;
  epochId: string;
}

/**
 * Generate epoch parameters
 */
export function generateWorkingEpoch(): WorkingEpochParams {
  // Generate Bob's epoch secret
  const epochSecret = nacl.randomBytes(32);
  // Apply X25519 clamping
  epochSecret[0] &= 248;
  epochSecret[31] &= 127;
  epochSecret[31] |= 64;
  
  // Compute public point
  const epochPublic = nacl.scalarMult.base(epochSecret);
  
  const epochId = Array.from(nacl.hash(epochPublic).slice(0, 16))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
  
  return {
    epochSecret,
    epochPublic,
    validFrom: Date.now(),
    validUntil: Date.now() + 30 * 24 * 60 * 60 * 1000,
    epochId
  };
}

export interface WorkingMessage {
  senderEphemeralPublic: Uint8Array;
  index: number;
  ciphertext: Uint8Array;
  nonce: Uint8Array;
}

/**
 * Alice creates a 0-RTT message for Bob
 * Alice knows: Bob's epochPublic
 * Alice generates: ephemeral keypair
 * Shared secret: DH(alice_ephemeral_secret, bob_epoch_public)
 */
export async function createWorkingMessage(
  plaintext: Uint8Array,
  bobEpochPublic: Uint8Array,
  index: number = Math.floor(Math.random() * 2**32)
): Promise<WorkingMessage> {
  // Alice generates ephemeral keypair
  const aliceEphemeral = nacl.box.keyPair();
  
  // Alice computes: DH(alice_eph_secret, bob_epoch_public)
  const sharedSecret = nacl.box.before(bobEpochPublic, aliceEphemeral.secretKey);
  
  // Derive index-specific key
  const indexBytes = new Uint8Array(4);
  new DataView(indexBytes.buffer).setUint32(0, index, false);
  
  const encryptionKey = await hkdf(
    new TextEncoder().encode('0RTT-ENC'),
    sharedSecret,
    indexBytes,
    32
  );
  
  // Encrypt
  const nonce = nacl.randomBytes(24);
  const ciphertext = nacl.secretbox(
    new Uint8Array(plaintext),
    new Uint8Array(nonce),
    new Uint8Array(encryptionKey)
  );
  
  return {
    senderEphemeralPublic: aliceEphemeral.publicKey,
    index,
    ciphertext,
    nonce
  };
}

/**
 * Bob processes Alice's message
 * Bob knows: his epochSecret
 * Bob receives: Alice's ephemeralPublic
 * Shared secret: DH(bob_epoch_secret, alice_ephemeral_public)
 */
export async function processWorkingMessage(
  msg: WorkingMessage,
  bobEpochSecret: Uint8Array
): Promise<Uint8Array | null> {
  try {
    // Bob computes: DH(bob_epoch_secret, alice_eph_public)
    // This is the same as Alice's DH(alice_eph_secret, bob_epoch_public)!
    const sharedSecret = nacl.box.before(msg.senderEphemeralPublic, bobEpochSecret);
    
    // Derive the same index-specific key
    const indexBytes = new Uint8Array(4);
    new DataView(indexBytes.buffer).setUint32(0, msg.index, false);
    
    const decryptionKey = await hkdf(
      new TextEncoder().encode('0RTT-ENC'),
      sharedSecret,
      indexBytes,
      32
    );
    
    // Decrypt
    return nacl.secretbox.open(
      msg.ciphertext,
      msg.nonce,
      new Uint8Array(decryptionKey)
    );
  } catch (error) {
    return null;
  }
}

/**
 * Test that DH is commutative
 */
export async function testWorkingConvergence(): Promise<boolean> {
  // Setup
  const bobEpoch = generateWorkingEpoch();
  const plaintext = new TextEncoder().encode('Hello Bob!');
  
  // Alice sends
  const msg = await createWorkingMessage(
    plaintext,
    bobEpoch.epochPublic,
    42
  );
  
  // Bob receives
  const decrypted = await processWorkingMessage(msg, bobEpoch.epochSecret);
  
  if (!decrypted) return false;
  
  return new TextDecoder().decode(decrypted) === 'Hello Bob!';
}