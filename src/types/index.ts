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

export type DisplayFormat = 'base36' | 'words' | 'qr';

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