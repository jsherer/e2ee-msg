import React, { useState, useMemo } from 'react';
import { LockScreen } from './components/LockScreen';
import { MasterKeyCard } from './components/MasterKeyCard';
import { KeysDisplay } from './components/KeysDisplay';
import { EncryptDecryptCard } from './components/EncryptDecryptCard';
import { OutputCard } from './components/OutputCard';
import { QRScannerModal } from './components/QRScannerModal';
import { RatchetVisualizer } from './components/RatchetVisualizer';
import { useKeyManagement } from './hooks/useKeyManagement';
import { useCrypto } from './hooks/useCrypto';
import { useQRScanner } from './hooks/useQRScanner';
import { uint8ArrayToBase32Crockford, formatInGroups } from './utils/encoding';
import { copyTextToClipboard, copyImageToClipboard } from './utils/clipboard';
import { DisplayFormat } from './types';

const App: React.FC = () => {
  const {
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
  } = useKeyManagement();

  const {
    recipientPublicKey,
    setRecipientPublicKey,
    message,
    setMessage,
    output,
    isEncrypting,
    isDecrypting,
    handleEncrypt,
    handleDecrypt,
    useRatchet,
    setUseRatchet,
    ratchetInitialized,
    ratchetOperations,
    ratchetSession,
    isRatchetProcessing,
    ratchetSessionCount,
    handleResetRatchet,
    clearAllSessions
  } = useCrypto(keypair, incrementNonceCounter, masterKey);

  const {
    showScanner,
    hasCamera,
    videoRef,
    openScanner,
    stopScanner
  } = useQRScanner((data) => setRecipientPublicKey(data));

  const [displayFormat, setDisplayFormat] = useState<DisplayFormat>('base32');
  const [copied, setCopied] = useState(false);
  const [copiedOutput, setCopiedOutput] = useState(false);
  const [isRegenerating, setIsRegenerating] = useState(false);

  // Always use the full 64-byte bundle for display
  const bundleForDisplay = useMemo(() => {
    const bundle = formatPublicKeyBundle();
    return bundle; // Only return valid bundles, not fallbacks
  }, [formatPublicKeyBundle]);

  const publicKeyDisplay = useMemo(() => {
    if (!bundleForDisplay) return null;
    // Format in groups with newlines after every 6 groups
    return formatInGroups(uint8ArrayToBase32Crockford(bundleForDisplay), true);
  }, [bundleForDisplay]);

  const handleRegenerate = async () => {
    if (window.confirm('Generate new keys?\n\nThis will replace your current keypair. You will lose access to messages encrypted with the old keys.\n\nContinue?')) {
      setIsRegenerating(true);
      await new Promise(resolve => setTimeout(resolve, 300));
      await generateNewKeypair();
      // Wait for keys to be saved (isSavingKeys will be set by the useEffect)
      setIsRegenerating(false);
    }
  };

  const copyPublicKey = async () => {
    const keyToCopy = publicKeyDisplay || keypairDisplay?.publicKey;
    if (displayFormat === 'qr' && keyToCopy) {
      const svg = document.querySelector('#public-key-qr') as SVGElement;
      if (svg) {
        const success = await copyImageToClipboard(svg);
        if (!success) {
          await copyTextToClipboard(keyToCopy);
        }
      }
    } else if (keyToCopy) {
      await copyTextToClipboard(keyToCopy);
    }
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const copyOutput = async () => {
    if (output) {
      const textToCopy = output.replace(/^(Encrypted:|Decrypted:)\n/, '');
      await copyTextToClipboard(textToCopy);
      setCopiedOutput(true);
      setTimeout(() => setCopiedOutput(false), 2000);
    }
  };

  const handleFreshStart = () => {
    window.location.hash = '';
    setWaitingForMasterKey(false);
  };

  // Show lock screen if master key not set (but keep showing main UI while locking)
  if (!masterKeyLocked && !isLocking) {
    return (
      <LockScreen
        masterKey={masterKey}
        setMasterKey={setMasterKey}
        onUnlock={handleMasterKeySubmit}
        waitingForMasterKey={waitingForMasterKey}
        onFreshStart={handleFreshStart}
        isUnlocking={isUnlocking}
      />
    );
  }

  // Main app UI
  return (
    <div style={{ 
      minHeight: '100vh',
      backgroundColor: '#f5f5f5',
      fontFamily: 'Arial, sans-serif'
    }}>
      <div style={{
        maxWidth: '800px',
        margin: '0 auto',
        padding: '20px'
      }}>
        <MasterKeyCard 
          masterKey={masterKey} 
          onLock={lockApp} 
          isLocking={isLocking}
          onChangeMasterKey={changeMasterKey}
          isChangingMasterKey={isSavingKeys}
        />

        {masterKeyLocked && (
          <KeysDisplay
            userId={userId}
            encryptedPrivateKey={encryptedPrivateKey}
            keypairDisplay={{ 
              publicKey: publicKeyDisplay || keypairDisplay?.publicKey || '', 
              secretKey: keypairDisplay?.secretKey || '' 
            }}
            displayFormat={displayFormat}
            setDisplayFormat={setDisplayFormat}
            copied={copied}
            onCopyPublicKey={copyPublicKey}
            isRegenerating={isRegenerating || isSavingKeys}
            onRegenerate={handleRegenerate}
          />
        )}

        {keypair && !waitingForMasterKey && (
          <>
            <EncryptDecryptCard
              recipientPublicKey={recipientPublicKey}
              setRecipientPublicKey={setRecipientPublicKey}
              message={message}
              setMessage={setMessage}
              isEncrypting={isEncrypting}
              isDecrypting={isDecrypting}
              onEncrypt={handleEncrypt}
              onDecrypt={handleDecrypt}
              hasCamera={hasCamera}
              onOpenScanner={openScanner}
              useRatchet={useRatchet}
              onToggleRatchet={() => setUseRatchet(!useRatchet)}
              ratchetInitialized={ratchetInitialized}
            />

            {useRatchet && (
              <RatchetVisualizer
                currentSession={ratchetSession}
                operations={ratchetOperations}
                isProcessing={isRatchetProcessing}
                sessionCount={ratchetSessionCount}
                onReset={handleResetRatchet}
                onClearAll={clearAllSessions}
              />
            )}

            <OutputCard
              output={output}
              copiedOutput={copiedOutput}
              onCopyOutput={copyOutput}
            />
          </>
        )}

        {showScanner && (
          <QRScannerModal videoRef={videoRef} onClose={stopScanner} />
        )}
      </div>
    </div>
  );
};

export default App;
