/**
 * Hook for managing cryptographic keys and master key with secure URL storage
 */

import { useState, useEffect, useMemo, useCallback } from 'react';
import { KeyPair, KeyPairDisplay } from '../types';
import {
  generateKeyPair,
  generateKeyPairFromSecretKey,
  encryptSecretKey,
  decryptSecretKey
} from '../utils/crypto';
import {
  uint8ArrayToBase32Crockford,
  base32CrockfordToUint8Array,
  formatInGroups,
  generateUserId
} from '../utils/encoding';
import { encryptToFragment, decryptFromFragment, PlainPayload } from '../utils/seal';

interface KeyData {
  secretKey: string; // Base32 encoded secret key
  publicKey: string; // Base32 encoded public key
  timestamp: number;
}

export const useKeyManagement = () => {
  const [keypair, setKeypair] = useState<KeyPair | null>(null);
  const [keypairDisplay, setKeypairDisplay] = useState<KeyPairDisplay | null>(null);
  const [masterKey, setMasterKey] = useState('');
  const [masterKeyLocked, setMasterKeyLocked] = useState(false);
  const [waitingForMasterKey, setWaitingForMasterKey] = useState(false);
  const [nonceCounter, setNonceCounter] = useState(0);
  const [lastSeenSeq, setLastSeenSeq] = useState(0);

  const generateNewKeypair = async (showLoading = false) => {
    const pair = generateKeyPair();
    
    setKeypair(pair);
    
    const publicKeyBase32 = formatInGroups(uint8ArrayToBase32Crockford(pair.publicKey));
    const secretKeyBase32 = formatInGroups(uint8ArrayToBase32Crockford(pair.secretKey));
    
    setKeypairDisplay({
      publicKey: publicKeyBase32,
      secretKey: secretKeyBase32
    });
    
    return pair;
  };

  const saveKeysToUrl = useCallback(async (pair: KeyPair, passphrase: string) => {
    try {
      const keyData: KeyData = {
        secretKey: uint8ArrayToBase32Crockford(pair.secretKey),
        publicKey: uint8ArrayToBase32Crockford(pair.publicKey),
        timestamp: Date.now()
      };

      // Get existing params if we have a fragment
      let existingParams = undefined;
      let seq = 1;
      
      const currentHash = window.location.hash.slice(1);
      if (currentHash && currentHash.startsWith('v1.scrypt')) {
        try {
          const { params, payload } = await decryptFromFragment<KeyData>(passphrase, currentHash);
          existingParams = params;
          seq = (payload.seq || 0) + 1;
        } catch {
          // If decryption fails, start fresh
        }
      }

      const fragment = await encryptToFragment(passphrase, keyData, {
        N: 16384, // Lower for mobile/browser performance
        r: 8,
        p: 1,
        salt: existingParams?.salt, // Reuse salt if we have one
        seq,
        context: location.origin
      });

      // Replace the URL without adding to history
      history.replaceState(null, '', location.pathname + location.search + '#' + fragment);
      setLastSeenSeq(seq);
    } catch (error) {
      console.error('Failed to save keys to URL:', error);
    }
  }, []);

  const tryRestoreFromFragment = useCallback(async (passphrase: string): Promise<boolean> => {
    try {
      const hash = window.location.hash.slice(1);
      if (!hash || !hash.startsWith('v1.scrypt')) {
        return false;
      }

      const { payload, rotate } = await decryptFromFragment<KeyData>(passphrase, hash, {
        lastSeenSeq
      });

      // Restore the keypair
      const secretKeyBytes = base32CrockfordToUint8Array(payload.data.secretKey);
      const pair = generateKeyPairFromSecretKey(secretKeyBytes);
      
      setKeypair(pair);
      
      const publicKeyBase32 = formatInGroups(uint8ArrayToBase32Crockford(pair.publicKey));
      const secretKeyBase32 = formatInGroups(uint8ArrayToBase32Crockford(pair.secretKey));
      
      setKeypairDisplay({
        publicKey: publicKeyBase32,
        secretKey: secretKeyBase32
      });

      setLastSeenSeq(payload.seq);

      // Rotate the fragment with a fresh nonce
      const rotated = await rotate(true);
      history.replaceState(null, '', location.pathname + location.search + '#' + rotated);
      
      return true;
    } catch (error) {
      console.error('Failed to restore from fragment:', error);
      return false;
    }
  }, [lastSeenSeq]);

  const handleMasterKeySubmit = useCallback(async () => {
    if (!masterKey || masterKey.length < 12) {
      return false;
    }
    
    const hash = window.location.hash.slice(1);
    
    // Check for new seal format
    if (hash && hash.startsWith('v1.scrypt')) {
      // Try to decrypt existing sealed data
      const restored = await tryRestoreFromFragment(masterKey);
      if (restored) {
        setWaitingForMasterKey(false);
        setMasterKeyLocked(true);
        return true;
      } else {
        alert('Invalid master key for the encrypted data in URL');
        return false;
      }
    } 
    // Check for old format (backwards compatibility)
    else if (hash) {
      try {
        const encryptedData = base32CrockfordToUint8Array(hash);
        const decrypted = decryptSecretKey(encryptedData, masterKey);
        
        if (decrypted && decrypted.length === 32) {
          const pair = generateKeyPairFromSecretKey(decrypted);
          
          setKeypair(pair);
          
          const publicKeyBase32 = formatInGroups(uint8ArrayToBase32Crockford(pair.publicKey));
          const secretKeyBase32 = formatInGroups(uint8ArrayToBase32Crockford(pair.secretKey));
          
          setKeypairDisplay({
            publicKey: publicKeyBase32,
            secretKey: secretKeyBase32
          });
          
          // Migrate to new format
          await saveKeysToUrl(pair, masterKey);
          setWaitingForMasterKey(false);
          setMasterKeyLocked(true);
          return true;
        }
      } catch (error) {
        console.error('Failed to restore from old format:', error);
      }
      alert('Invalid master key for the encrypted private key in URL');
      return false;
    }
    // No existing hash, generate new
    else {
      const pair = await generateNewKeypair();
      await saveKeysToUrl(pair, masterKey);
      setMasterKeyLocked(true);
      return true;
    }
  }, [masterKey, tryRestoreFromFragment, saveKeysToUrl]);

  const lockApp = () => {
    setMasterKey('');
    setMasterKeyLocked(false);
    if (window.location.hash) {
      setWaitingForMasterKey(true);
    }
  };

  const encryptedPrivateKey = useMemo(() => {
    // This is now handled by the seal in the URL
    // Return a placeholder or the fragment itself for display
    const hash = window.location.hash.slice(1);
    if (hash && hash.startsWith('v1.scrypt')) {
      // Just show a truncated version for UI display
      return hash.slice(0, 20) + '...';
    }
    return null;
  }, [nonceCounter]); // Still respond to nonce updates

  const userId = useMemo(() => {
    if (!keypair) return null;
    return generateUserId(keypair.publicKey);
  }, [keypair]);

  // Check for encrypted key in URL on mount
  useEffect(() => {
    const hash = window.location.hash.slice(1);
    if (hash && hash.startsWith('v1.scrypt')) {
      setWaitingForMasterKey(true);
    }
  }, []);

  // Update URL when keys change (if we have a master key)
  useEffect(() => {
    if (keypair && masterKey && masterKeyLocked) {
      saveKeysToUrl(keypair, masterKey);
    }
  }, [keypair, masterKey, masterKeyLocked, saveKeysToUrl]);

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