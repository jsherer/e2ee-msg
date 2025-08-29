/**
 * Hook for managing cryptographic keys and master key with secure URL storage
 */

import { useState, useEffect, useMemo, useCallback } from 'react';
import { ExtendedKeyPair, KeyPair, KeyPairDisplay, PRPCapKeyPair } from '../types';
import {
  generateKeyPair,
  generateKeyPairFromSecretKey,
  generatePRPCapKeyPair,
  generatePRPCapKeyPairFromSecretKey,
  encryptSecretKey,
  decryptSecretKey
} from '../utils/crypto';
import {
  uint8ArrayToBase32Crockford,
  base32CrockfordToUint8Array,
  formatInGroups,
  generateUserId,
  encodePRPCapPublicKey
} from '../utils/encoding';
import { encryptToFragment, decryptFromFragment, PlainPayload } from '../utils/seal';

interface KeyData {
  secretKey: string; // Base32 encoded secret key
  publicKey: string; // Base32 encoded public key
  // PRP-Cap epoch parameters
  epochA?: string; // Base32 encoded epoch point A (32 bytes)
  epochB?: string; // Base32 encoded epoch point B (32 bytes)
  epochS1?: string; // Base32 encoded epoch secret s1 (32 bytes)
  epochS2?: string; // Base32 encoded epoch secret s2 (32 bytes)
  epochValidFrom?: number; // Unix timestamp
  epochValidUntil?: number; // Unix timestamp
  epochId?: string; // Hex string identifier
  // Legacy fields (for backward compatibility)
  ephemeralSeedSecret?: string; // Base32 encoded ephemeral seed secret (Ladder)
  ephemeralSeedPublic?: string; // Base32 encoded ephemeral seed public (Ladder)
  timestamp: number;
}

export const useKeyManagement = () => {
  const [keypair, setKeypair] = useState<PRPCapKeyPair | null>(null);
  const [keypairDisplay, setKeypairDisplay] = useState<KeyPairDisplay | null>(null);
  const [masterKey, setMasterKey] = useState('');
  const [masterKeyLocked, setMasterKeyLocked] = useState(false);
  const [waitingForMasterKey, setWaitingForMasterKey] = useState(false);
  const [nonceCounter, setNonceCounter] = useState(0);
  const [lastSeenSeq, setLastSeenSeq] = useState(0);
  const [isUnlocking, setIsUnlocking] = useState(false);
  const [isSavingKeys, setIsSavingKeys] = useState(false);
  const [isLocking, setIsLocking] = useState(false);

  const saveKeysToUrl = useCallback(async (pair: PRPCapKeyPair, passphrase: string) => {
    setIsSavingKeys(true);
    try {
      const keyData: KeyData = {
        secretKey: uint8ArrayToBase32Crockford(pair.secretKey),
        publicKey: uint8ArrayToBase32Crockford(pair.publicKey),
        // Save PRP-Cap epoch parameters if present
        epochA: pair.epoch ? uint8ArrayToBase32Crockford(pair.epoch.A) : undefined,
        epochB: pair.epoch ? uint8ArrayToBase32Crockford(pair.epoch.B) : undefined,
        epochS1: pair.epoch?.s1 ? uint8ArrayToBase32Crockford(pair.epoch.s1) : undefined,
        epochS2: pair.epoch?.s2 ? uint8ArrayToBase32Crockford(pair.epoch.s2) : undefined,
        epochValidFrom: pair.epoch?.validFrom,
        epochValidUntil: pair.epoch?.validUntil,
        epochId: pair.epoch?.epochId,
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
    } finally {
      setIsSavingKeys(false);
    }
  }, []);

  const generateNewKeypair = useCallback(async (): Promise<PRPCapKeyPair> => {
    const pair = await generatePRPCapKeyPair();
    
    setKeypair(pair);
    
    const publicKeyBase32 = formatInGroups(uint8ArrayToBase32Crockford(pair.publicKey));
    const secretKeyBase32 = formatInGroups(uint8ArrayToBase32Crockford(pair.secretKey));
    
    setKeypairDisplay({
      publicKey: publicKeyBase32,
      secretKey: secretKeyBase32
    });
    
    // Save to URL if we have a master key (regeneration case)
    if (masterKey && masterKeyLocked) {
      await saveKeysToUrl(pair, masterKey);
    }
    
    return pair;
  }, [masterKey, masterKeyLocked, saveKeysToUrl]);

  const tryRestoreFromFragment = useCallback(async (passphrase: string): Promise<boolean> => {
    try {
      const hash = window.location.hash.slice(1);
      if (!hash || !hash.startsWith('v1.scrypt')) {
        return false;
      }

      const { payload, rotate } = await decryptFromFragment<KeyData>(passphrase, hash, {
        lastSeenSeq
      });

      // Restore the keypair with epoch if available
      const secretKeyBytes = base32CrockfordToUint8Array(payload.data.secretKey);
      
      let pair: PRPCapKeyPair;
      let needsUpdate = false;
      
      // Check if we have PRP-Cap epoch data
      if (payload.data.epochA && payload.data.epochB) {
        // Restore with existing epoch parameters
        const existingEpoch = {
          A: base32CrockfordToUint8Array(payload.data.epochA),
          B: base32CrockfordToUint8Array(payload.data.epochB),
          s1: payload.data.epochS1 ? base32CrockfordToUint8Array(payload.data.epochS1) : undefined,
          s2: payload.data.epochS2 ? base32CrockfordToUint8Array(payload.data.epochS2) : undefined,
          validFrom: payload.data.epochValidFrom || Date.now(),
          validUntil: payload.data.epochValidUntil || Date.now() + (30 * 24 * 60 * 60 * 1000),
          epochId: payload.data.epochId || ''
        };
        pair = await generatePRPCapKeyPairFromSecretKey(secretKeyBytes, existingEpoch);
      } else {
        // Legacy format or missing epoch - generate new epoch parameters
        pair = await generatePRPCapKeyPairFromSecretKey(secretKeyBytes);
        needsUpdate = true; // Need to save the new epoch parameters
      }
      
      setKeypair(pair);
      
      const publicKeyBase32 = formatInGroups(uint8ArrayToBase32Crockford(pair.publicKey));
      const secretKeyBase32 = formatInGroups(uint8ArrayToBase32Crockford(pair.secretKey));
      
      setKeypairDisplay({
        publicKey: publicKeyBase32,
        secretKey: secretKeyBase32
      });

      setLastSeenSeq(payload.seq);

      if (needsUpdate) {
        // Save with the new PRP-Cap epoch parameters
        await saveKeysToUrl(pair, passphrase);
      } else {
        // Rotate the fragment with a fresh nonce
        const rotated = await rotate(true);
        history.replaceState(null, '', location.pathname + location.search + '#' + rotated);
      }
      
      return true;
    } catch (error) {
      console.error('Failed to restore from fragment:', error);
      return false;
    }
  }, [lastSeenSeq, saveKeysToUrl]);

  const handleMasterKeySubmit = useCallback(async (): Promise<boolean> => {
    if (!masterKey || masterKey.length < 12) {
      return false;
    }
    
    setIsUnlocking(true);
    const hash = window.location.hash.slice(1);
    
    // Check for new seal format
    if (hash && hash.startsWith('v1.scrypt')) {
      // Try to decrypt existing sealed data
      const restored = await tryRestoreFromFragment(masterKey);
      if (restored) {
        setWaitingForMasterKey(false);
        setMasterKeyLocked(true);
        setIsUnlocking(false);
        return true;
      } else {
        alert('Invalid master key for the encrypted data in URL');
        setIsUnlocking(false);
        return false;
      }
    } 
    // Check for old format (backwards compatibility)
    else if (hash) {
      try {
        const encryptedData = base32CrockfordToUint8Array(hash);
        const decrypted = decryptSecretKey(encryptedData, masterKey);
        
        if (decrypted && decrypted.length === 32) {
          // Migrate to PRP-Cap format
          const pair = await generatePRPCapKeyPairFromSecretKey(decrypted);
          
          setKeypair(pair);
          
          const publicKeyBase32 = formatInGroups(uint8ArrayToBase32Crockford(pair.publicKey));
          const secretKeyBase32 = formatInGroups(uint8ArrayToBase32Crockford(pair.secretKey));
          
          setKeypairDisplay({
            publicKey: publicKeyBase32,
            secretKey: secretKeyBase32
          });
          
          // Save in new format with PRP-Cap epoch parameters
          await saveKeysToUrl(pair, masterKey);
          setWaitingForMasterKey(false);
          setMasterKeyLocked(true);
          setIsUnlocking(false);
          return true;
        } else {
          alert('Invalid encrypted data format');
          setIsUnlocking(false);
          return false;
        }
      } catch (error) {
        console.error('Failed to restore from old format:', error);
        alert('Invalid master key for the encrypted private key in URL');
        setIsUnlocking(false);
        return false;
      }
    }
    // No existing hash, generate new
    else {
      const pair = await generateNewKeypair();
      await saveKeysToUrl(pair, masterKey);
      setMasterKeyLocked(true);
      setIsUnlocking(false);
      return true;
    }
  }, [masterKey, tryRestoreFromFragment, saveKeysToUrl, generateNewKeypair]);

  const lockApp = useCallback(async () => {
    setIsLocking(true);
    try {
      // Rotate the fragment with a fresh nonce before locking
      if (keypair && masterKey && window.location.hash) {
        const hash = window.location.hash.slice(1);
        if (hash && hash.startsWith('v1.scrypt')) {
          try {
            const { rotate } = await decryptFromFragment<KeyData>(masterKey, hash, {
              lastSeenSeq  
            });
            // Just rotate with fresh nonce, don't bump sequence when locking
            const rotated = await rotate(false);
            history.replaceState(null, '', location.pathname + location.search + '#' + rotated);
            // Wait a moment to ensure the URL is updated
            await new Promise(resolve => setTimeout(resolve, 50));
          } catch (error) {
            console.error('Failed to rotate fragment before locking:', error);
          }
        }
      }
      
      // Only clear the master key and show locked screen AFTER fragment is rotated
      setMasterKey('');
      setMasterKeyLocked(false);
      // Reset lastSeenSeq when locking so next unlock doesn't fail anti-rollback
      setLastSeenSeq(0);
      if (window.location.hash) {
        setWaitingForMasterKey(true);
      }
    } finally {
      setIsLocking(false);
    }
  }, [keypair, masterKey, lastSeenSeq]);

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

  // Note: We don't need to constantly update the URL fragment.
  // It's only updated when:
  // 1. Keys are initially generated (in handleMasterKeySubmit)
  // 2. Keys are regenerated (in generateNewKeypair, called explicitly)
  // 3. On lock (for nonce rotation)
  // 4. On unlock (for nonce rotation)

  const incrementNonceCounter = () => {
    setNonceCounter(prev => prev + 1);
  };

  // Format public key bundle with PRP-Cap epoch parameters
  const formatPublicKeyBundle = useCallback((): Uint8Array | null => {
    if (!keypair || !keypair.epoch) return null;
    
    // Create a bundle with public key and epoch parameters
    // Format: publicKey (32) + A (32) + B (32) = 96 bytes
    const bundle = new Uint8Array(96);
    bundle.set(keypair.publicKey, 0);
    bundle.set(keypair.epoch.A, 32);
    bundle.set(keypair.epoch.B, 64);
    return bundle;
  }, [keypair]);

  // Check if we have PRP-Cap support
  const hasPRPCapSupport = useCallback((): boolean => {
    return !!(keypair && keypair.epoch && keypair.epoch.A && keypair.epoch.B);
  }, [keypair]);

  const changeMasterKey = useCallback(async (newMasterKey: string): Promise<boolean> => {
    if (!keypair || !masterKey || newMasterKey.length < 12) {
      return false;
    }

    try {
      // Save keys with new master key
      await saveKeysToUrl(keypair, newMasterKey);
      
      // Update the master key in state
      setMasterKey(newMasterKey);
      
      return true;
    } catch (error) {
      console.error('Failed to change master key:', error);
      return false;
    }
  }, [keypair, masterKey, saveKeysToUrl]);

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
    setWaitingForMasterKey,
    isUnlocking,
    isSavingKeys,
    isLocking,
    changeMasterKey,
    formatPublicKeyBundle,
    hasPRPCapSupport
  };
};
