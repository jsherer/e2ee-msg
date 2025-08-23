/**
 * Hook for encryption and decryption operations
 */

import { useState, useCallback } from 'react';
import { KeyPair } from '../types';
import { encryptMessage, decryptMessage } from '../utils/crypto';
import { base32CrockfordToUint8Array, formatInGroups, uint8ArrayToBase32Crockford } from '../utils/encoding';
import { isBIP39Format, wordsToUint8Array } from '../utils/bip39';
import { useRatchet } from './useRatchet';

export const useCrypto = (
  keypair: KeyPair | null, 
  onNonceUpdate: () => void,
  masterKey: string
) => {
  const [recipientPublicKey, setRecipientPublicKey] = useState('');
  const [message, setMessage] = useState('');
  const [output, setOutput] = useState('');
  const [isEncrypting, setIsEncrypting] = useState(false);
  const [isDecrypting, setIsDecrypting] = useState(false);
  const [useRatchetProtocol, setUseRatchetProtocol] = useState(true); // Default to ratchet ON
  
  // Ratchet protocol hook
  const {
    encryptWithRatchet,
    decryptWithRatchet,
    getCurrentSession,
    resetSession,
    clearAllSessions,
    operations,
    isProcessing,
    sessionCount
  } = useRatchet(keypair, masterKey);

  const parsePublicKey = useCallback((keyString: string): Uint8Array => {
    if (isBIP39Format(keyString)) {
      const words = keyString.toLowerCase().trim().split(/\s+/);
      return wordsToUint8Array(words);
    } else {
      return base32CrockfordToUint8Array(keyString);
    }
  }, []);

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
      
      let encrypted: Uint8Array;
      if (useRatchetProtocol) {
        // Use ratchet protocol
        const encryptedData = encryptWithRatchet(message, recipientKey);
        if (!encryptedData) {
          setOutput('Error: Ratchet encryption failed');
          return;
        }
        encrypted = encryptedData;
      } else {
        // Use standard encryption
        encrypted = encryptMessage(message, recipientKey, keypair.secretKey);
      }
      
      const formattedOutput = formatInGroups(uint8ArrayToBase32Crockford(encrypted));
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
      const encryptedData = base32CrockfordToUint8Array(message);
      
      // Check if this is a ratchet message (version byte 0x01)
      const isRatchetMessage = encryptedData.length > 0 && encryptedData[0] === 0x01;
      
      let decrypted: string | null;
      if (isRatchetMessage || useRatchetProtocol) {
        // Use ratchet protocol
        decrypted = decryptWithRatchet(encryptedData, senderKey);
        if (!decrypted) {
          setOutput('Decryption failed: Invalid ratchet message or wrong keys');
        } else {
          setOutput(`Decrypted:\n${decrypted}`);
          onNonceUpdate();
        }
      } else {
        // Use standard decryption
        const decryptedMsg = decryptMessage(encryptedData, senderKey, keypair.secretKey);
        if (!decryptedMsg) {
          setOutput('Decryption failed: Invalid message or wrong keys');
        } else {
          setOutput(`Decrypted:\n${decryptedMsg}`);
          onNonceUpdate();
        }
      }
    } catch (error) {
      setOutput(`Decryption error: ${error}`);
    } finally {
      setIsDecrypting(false);
    }
  };

  // Check if ratchet is initialized for current recipient
  const isRatchetInitialized = useCallback((): boolean => {
    if (!recipientPublicKey) return false;
    try {
      const recipientKey = parsePublicKey(recipientPublicKey);
      const session = getCurrentSession();
      return session !== null && session.isInitialized;
    } catch {
      return false;
    }
  }, [recipientPublicKey, getCurrentSession, parsePublicKey]);

  // Reset ratchet for current recipient
  const handleResetRatchet = useCallback(() => {
    if (!recipientPublicKey) return;
    try {
      const recipientKey = parsePublicKey(recipientPublicKey);
      resetSession(recipientKey);
    } catch (error) {
      console.error('Failed to reset ratchet:', error);
    }
  }, [recipientPublicKey, resetSession, parsePublicKey]);

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
    handleDecrypt,
    // Ratchet specific
    useRatchet: useRatchetProtocol,
    setUseRatchet: setUseRatchetProtocol,
    ratchetInitialized: isRatchetInitialized(),
    ratchetOperations: operations,
    ratchetSession: getCurrentSession(),
    isRatchetProcessing: isProcessing,
    ratchetSessionCount: sessionCount,
    handleResetRatchet,
    clearAllSessions
  };
};