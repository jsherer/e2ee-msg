declare module 'tweetnacl' {
  export interface KeyPair {
    publicKey: Uint8Array;
    secretKey: Uint8Array;
  }

  export namespace box {
    const nonceLength: number;
    const publicKeyLength: number;
    const secretKeyLength: number;
    const sharedKeyLength: number;
    const overheadLength: number;
    
    function keyPair(): KeyPair;
    namespace keyPair {
      function fromSecretKey(secretKey: Uint8Array): KeyPair;
    }
    function open(box: Uint8Array, nonce: Uint8Array, theirPublicKey: Uint8Array, mySecretKey: Uint8Array): Uint8Array | null;
    function before(theirPublicKey: Uint8Array, mySecretKey: Uint8Array): Uint8Array;
  }
  
  export function box(message: Uint8Array, nonce: Uint8Array, theirPublicKey: Uint8Array, mySecretKey: Uint8Array): Uint8Array;

  export namespace secretbox {
    const keyLength: number;
    const nonceLength: number;
    const overheadLength: number;
    
    function open(box: Uint8Array, nonce: Uint8Array, key: Uint8Array): Uint8Array | null;
  }
  
  export function secretbox(message: Uint8Array, nonce: Uint8Array, key: Uint8Array): Uint8Array;

  export namespace sign {
    function keyPair(): KeyPair;
  }
  
  export function randomBytes(n: number): Uint8Array;
  export function hash(message: Uint8Array): Uint8Array;
  export function scalarMult(n: Uint8Array, p: Uint8Array): Uint8Array;
  
  export namespace scalarMult {
    const scalarLength: number;
    const groupElementLength: number;
    function base(n: Uint8Array): Uint8Array;
  }
}