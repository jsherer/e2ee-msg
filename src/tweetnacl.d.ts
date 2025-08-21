declare module 'tweetnacl' {
  export interface KeyPair {
    publicKey: Uint8Array;
    secretKey: Uint8Array;
  }

  export namespace box {
    function keyPair(): KeyPair;
  }

  export namespace sign {
    function keyPair(): KeyPair;
  }
}