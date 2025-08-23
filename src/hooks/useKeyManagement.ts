/**
 * Hook for managing cryptographic keys and master key
 */

import { useState, useEffect, useMemo } from 'react';
import { KeyPair, KeyPairDisplay } from '../types';
import {
  generateKeyPair,
  generateKeyPairFromSecretKey,
  encryptSecretKey,
  decryptSecretKey
} from '../utils/crypto';
import {
  uint8ArrayToBase36,
  base36ToUint8Array,
  formatInGroups,
  generateUserId
} from '../utils/encoding';

export const useKeyManagement = () => {
  const [keypair, setKeypair] = useState<KeyPair | null>(null);
  const [keypairDisplay, setKeypairDisplay] = useState<KeyPairDisplay | null>(null);
  const [masterKey, setMasterKey] = useState('');
  const [masterKeyLocked, setMasterKeyLocked] = useState(false);
  const [waitingForMasterKey, setWaitingForMasterKey] = useState(false);
  const [nonceCounter, setNonceCounter] = useState(0);

  const generateNewKeypair = async (showLoading = false) => {
    const pair = generateKeyPair();
    
    setKeypair(pair);
    
    const publicKeyBase36 = formatInGroups(uint8ArrayToBase36(pair.publicKey));
    const secretKeyBase36 = formatInGroups(uint8ArrayToBase36(pair.secretKey));
    
    setKeypairDisplay({
      publicKey: publicKeyBase36,
      secretKey: secretKeyBase36
    });
  };

  const tryRestoreFromHash = (hash: string, key: string): boolean => {
    try {
      const encryptedData = base36ToUint8Array(hash);
      const decrypted = decryptSecretKey(encryptedData, key);
      
      if (decrypted && decrypted.length === 32) {
        const pair = generateKeyPairFromSecretKey(decrypted);
        
        setKeypair(pair);
        
        const publicKeyBase36 = formatInGroups(uint8ArrayToBase36(pair.publicKey));
        const secretKeyBase36 = formatInGroups(uint8ArrayToBase36(pair.secretKey));
        
        setKeypairDisplay({
          publicKey: publicKeyBase36,
          secretKey: secretKeyBase36
        });
        
        return true;
      }
    } catch (error) {
      console.error('Failed to restore from hash:', error);
    }
    return false;
  };

  const handleMasterKeySubmit = () => {
    if (!masterKey || masterKey.length < 12) {
      return false;
    }
    
    const hash = window.location.hash.slice(1);
    if (hash) {
      const restored = tryRestoreFromHash(hash, masterKey);
      if (restored) {
        setWaitingForMasterKey(false);
        setMasterKeyLocked(true);
        return true;
      } else {
        alert('Invalid master key for the encrypted private key in URL');
        return false;
      }
    } else {
      generateNewKeypair();
      setMasterKeyLocked(true);
      return true;
    }
  };

  const lockApp = () => {
    setMasterKey('');
    setMasterKeyLocked(false);
    if (window.location.hash) {
      setWaitingForMasterKey(true);
    }
  };

  const encryptedPrivateKey = useMemo(() => {
    if (!keypair || !masterKey) return null;
    
    try {
      const encrypted = encryptSecretKey(keypair.secretKey, masterKey);
      return formatInGroups(uint8ArrayToBase36(encrypted));
    } catch (error) {
      console.error('Failed to encrypt private key:', error);
      return null;
    }
  }, [keypair, masterKey, nonceCounter]);

  const userId = useMemo(() => {
    if (!keypair) return null;
    return generateUserId(keypair.publicKey);
  }, [keypair]);

  // Check for encrypted key in URL on mount
  useEffect(() => {
    const hash = window.location.hash.slice(1);
    if (hash) {
      setWaitingForMasterKey(true);
    }
  }, []);

  // Update URL hash when encrypted private key changes
  useEffect(() => {
    if (encryptedPrivateKey) {
      const cleanKey = encryptedPrivateKey.replace(/\s/g, '');
      window.location.hash = cleanKey;
    }
  }, [encryptedPrivateKey]);

  const incrementNonceCounter = () => {
    setNonceCounter(prev => prev + 1);
  };

  return {
    keypair,
    keypairDisplay,
    masterKey,
    setMasterKey,
    masterKeyLocked,
    waitingForMasterKey,
    encryptedPrivateKey,
    userId,
    generateNewKeypair,
    handleMasterKeySubmit,
    lockApp,
    incrementNonceCounter,
    setWaitingForMasterKey
  };
};