/**
 * Ladder Protocol Types
 * Lightweight Asynchronous Deterministic Double-Ratchet
 */

// Extended key pair for Ladder protocol
export interface ExtendedKeyPair {
  identity: {
    publicKey: Uint8Array;
    secretKey: Uint8Array;
  };
  ephemeralSeed: {
    publicKey: Uint8Array;
    secretKey: Uint8Array;
  };
}
