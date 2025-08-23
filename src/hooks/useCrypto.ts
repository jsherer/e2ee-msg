/**
 * Hook for encryption and decryption operations
 */

import { useState } from 'react';
import { KeyPair } from '../types';
import { encryptMessage, decryptMessage } from '../utils/crypto';
import { base36ToUint8Array, formatInGroups, uint8ArrayToBase36 } from '../utils/encoding';
import { isBIP39Format, wordsToUint8Array } from '../utils/bip39';

export const useCrypto = (keypair: KeyPair | null, onNonceUpdate: () => void) => {
  const [recipientPublicKey, setRecipientPublicKey] = useState('');
  const [message, setMessage] = useState('');
  const [output, setOutput] = useState('');
  const [isEncrypting, setIsEncrypting] = useState(false);
  const [isDecrypting, setIsDecrypting] = useState(false);

  const parsePublicKey = (keyString: string): Uint8Array => {
    if (isBIP39Format(keyString)) {
      const words = keyString.toLowerCase().trim().split(/\s+/);
      return wordsToUint8Array(words);
    } else {
      return base36ToUint8Array(keyString, 32);
    }
  };

  const handleEncrypt = async () => {
    if (!keypair || !recipientPublicKey || !message) {
      setOutput('Error: Missing keypair, recipient public key, or message');
      return;
    }

    setIsEncrypting(true);
    setOutput('Encrypting...');

    await new Promise(resolve => setTimeout(resolve, 300));

    try {
      const recipientKey = parsePublicKey(recipientPublicKey);
      const encrypted = encryptMessage(message, recipientKey, keypair.secretKey);
      const formattedOutput = formatInGroups(uint8ArrayToBase36(encrypted));
      setOutput(`Encrypted:\n${formattedOutput}`);
      
      // Re-encrypt private key with new nonce
      onNonceUpdate();
    } catch (error) {
      setOutput(`Encryption error: ${error}`);
    } finally {
      setIsEncrypting(false);
    }
  };

  const handleDecrypt = async () => {
    if (!keypair || !recipientPublicKey || !message) {
      setOutput('Error: Missing keypair, sender public key, or encrypted message');
      return;
    }

    setIsDecrypting(true);
    setOutput('Decrypting...');

    await new Promise(resolve => setTimeout(resolve, 300));

    try {
      const senderKey = parsePublicKey(recipientPublicKey);
      const encryptedData = base36ToUint8Array(message);
      const decrypted = decryptMessage(encryptedData, senderKey, keypair.secretKey);
      
      if (!decrypted) {
        setOutput('Decryption failed: Invalid message or wrong keys');
      } else {
        setOutput(`Decrypted:\n${decrypted}`);
        // Re-encrypt private key with new nonce
        onNonceUpdate();
      }
    } catch (error) {
      setOutput(`Decryption error: ${error}`);
    } finally {
      setIsDecrypting(false);
    }
  };

  return {
    recipientPublicKey,
    setRecipientPublicKey,
    message,
    setMessage,
    output,
    setOutput,
    isEncrypting,
    isDecrypting,
    handleEncrypt,
    handleDecrypt
  };
};