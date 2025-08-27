/**
 * TypeScript type definitions for the E2EE messaging app
 */

export interface KeyPair {
  publicKey: Uint8Array;
  secretKey: Uint8Array;
}

export interface KeyPairDisplay {
  publicKey: string;
  secretKey: string;
}

/**
 * PRP-Cap enabled keypair with epoch parameters
 */
export interface PRPCapKeyPair extends KeyPair {
  epoch?: {
    A: Uint8Array;           // Public point A (32 bytes)
    B: Uint8Array;           // Public point B (32 bytes)
    s1?: Uint8Array;         // Secret scalar 1 (only for own keys)
    s2?: Uint8Array;         // Secret scalar 2 (only for own keys)
    validFrom: number;       // Unix timestamp
    validUntil: number;      // Unix timestamp
    epochId: string;         // Hex string identifier
  };
}

export interface ExtendedKeyPair {
  identity: KeyPair;
  ephemeralSeed: KeyPair;
}

export type DisplayFormat = 'base32' | 'qr';

export interface CryptoState {
  keypair: KeyPair | null;
  keypairDisplay: KeyPairDisplay | null;
  encryptedPrivateKey: string | null;
  userId: string | null;
}

export interface MasterKeyState {
  masterKey: string;
  masterKeyLocked: boolean;
  waitingForMasterKey: boolean;
}

export interface EncryptionState {
  recipientPublicKey: string;
  message: string;
  output: string;
  isEncrypting: boolean;
  isDecrypting: boolean;
}

export interface UIState {
  copied: boolean;
  copiedOutput: boolean;
  copiedEncryptedKey: boolean;
  isRegenerating: boolean;
  displayFormat: DisplayFormat;
  showScanner: boolean;
  hasCamera: boolean | null;
  nonceCounter: number;
}
