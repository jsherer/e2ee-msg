import React, { useState, useEffect, useMemo, useRef } from 'react';
import * as nacl from 'tweetnacl';
import { IconRefresh, IconCopy, IconCheck, IconQrcode, IconX } from '@tabler/icons-react';
import { QRCodeSVG } from 'qrcode.react';
import QrScanner from 'qr-scanner';
import { uint8ArrayToWords, wordsToUint8Array, formatWords, isBIP39Format } from './bip39';

const App: React.FC = () => {
  const [keypair, setKeypair] = useState<{ publicKey: Uint8Array; secretKey: Uint8Array } | null>(null);
  const [keypairDisplay, setKeypairDisplay] = useState<{ publicKey: string; secretKey: string } | null>(null);
  const [recipientPublicKey, setRecipientPublicKey] = useState('');
  const [message, setMessage] = useState('');
  const [output, setOutput] = useState('');
  const [masterKey, setMasterKey] = useState('');
  const [masterKeyLocked, setMasterKeyLocked] = useState(false);
  const [isDecrypting, setIsDecrypting] = useState(false);
  const [isEncrypting, setIsEncrypting] = useState(false);
  const [copied, setCopied] = useState(false);
  const [copiedOutput, setCopiedOutput] = useState(false);
  const [isRegenerating, setIsRegenerating] = useState(false);
  const [copiedEncryptedKey, setCopiedEncryptedKey] = useState(false);
  const [waitingForMasterKey, setWaitingForMasterKey] = useState(false);
  const [nonceCounter, setNonceCounter] = useState(0);
  const [displayFormat, setDisplayFormat] = useState<'base36' | 'words' | 'qr'>('base36');
  const [showScanner, setShowScanner] = useState(false);
  const videoRef = useRef<HTMLVideoElement>(null);
  const scannerRef = useRef<QrScanner | null>(null);

  const uint8ArrayToBase36 = (arr: Uint8Array): string => {
    let bigInt = BigInt(0);
    for (let i = 0; i < arr.length; i++) {
      bigInt = (bigInt << BigInt(8)) | BigInt(arr[i]);
    }
    return bigInt.toString(36).toLowerCase();
  };

  const base36ToUint8Array = (str: string, expectedLength?: number): Uint8Array => {
    const cleanStr = str.replace(/\s/g, '');
    let bigInt = BigInt(0);
    for (let i = 0; i < cleanStr.length; i++) {
      bigInt = bigInt * BigInt(36) + BigInt(parseInt(cleanStr[i], 36));
    }
    const hex = bigInt.toString(16);
    const paddedHex = hex.padStart((expectedLength || 32) * 2, '0');
    const arr = new Uint8Array(expectedLength || Math.ceil(paddedHex.length / 2));
    for (let i = 0; i < arr.length; i++) {
      arr[i] = parseInt(paddedHex.substr(i * 2, 2), 16);
    }
    return arr;
  };

  const formatInGroups = (str: string): string => {
    return str.match(/.{1,5}/g)?.join(' ') || str;
  };

  const generateKeypair = async (showLoading = false) => {
    if (showLoading) {
      setIsRegenerating(true);
      setKeypairDisplay(null);
      await new Promise(resolve => setTimeout(resolve, 300));
    }
    
    const pair = nacl.box.keyPair();
    
    setKeypair(pair);
    
    const publicKeyBase36 = formatInGroups(uint8ArrayToBase36(pair.publicKey));
    const secretKeyBase36 = formatInGroups(uint8ArrayToBase36(pair.secretKey));
    
    setKeypairDisplay({
      publicKey: publicKeyBase36,
      secretKey: secretKeyBase36
    });
    
    if (showLoading) {
      setIsRegenerating(false);
    }
  };

  const tryRestoreFromHash = (hash: string, key: string) => {
    try {
      // Convert from base36 back to Uint8Array
      const encryptedData = base36ToUint8Array(hash);
      
      // Derive key from master key
      const masterKeyBytes = new TextEncoder().encode(key);
      const hashedKey = nacl.hash(masterKeyBytes).slice(0, nacl.secretbox.keyLength);
      
      // Extract nonce and encrypted content
      const nonce = encryptedData.slice(0, nacl.secretbox.nonceLength);
      const encrypted = encryptedData.slice(nacl.secretbox.nonceLength);
      
      // Try to decrypt
      const decrypted = nacl.secretbox.open(encrypted, nonce, hashedKey);
      
      if (decrypted && decrypted.length === 32) {
        // Successfully decrypted, this should be the secret key
        // Generate the public key from the secret key
        const pair = nacl.box.keyPair.fromSecretKey(decrypted);
        
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

  useEffect(() => {
    // Check if there's an encrypted key in the URL hash
    const hash = window.location.hash.slice(1); // Remove the #
    if (hash) {
      // We need the user to enter their master key to restore
      setWaitingForMasterKey(true);
    }
    // Don't generate keys without a master key
  }, []);

  const publicKeyWords = useMemo(() => {
    if (!keypair) return null;
    try {
      const words = uint8ArrayToWords(keypair.publicKey);
      return formatWords(words, 6);
    } catch (error) {
      console.error('Failed to convert to words:', error);
      return null;
    }
  }, [keypair]);

  const userId = useMemo(() => {
    if (!keypair) return null;
    // Create a hash of the public key for a unique user ID
    const hash = nacl.hash(keypair.publicKey);
    // Take first 8 bytes and convert to hex for a shorter ID
    const idBytes = hash.slice(0, 8);
    const hexId = Array.from(idBytes)
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
    // Format as XXXX-XXXX-XXXX-XXXX
    return hexId.match(/.{1,4}/g)?.join('-') || hexId;
  }, [keypair]);

  const copyPublicKey = async () => {
    if (displayFormat === 'qr' && keypairDisplay) {
      // Copy QR code as image
      try {
        const svg = document.querySelector('#public-key-qr') as SVGElement;
        if (svg) {
          // Convert SVG to blob
          const svgData = new XMLSerializer().serializeToString(svg);
          const canvas = document.createElement('canvas');
          const ctx = canvas.getContext('2d');
          const img = new Image();
          
          img.onload = async () => {
            canvas.width = img.width;
            canvas.height = img.height;
            ctx?.drawImage(img, 0, 0);
            
            canvas.toBlob(async (blob) => {
              if (blob) {
                try {
                  await navigator.clipboard.write([
                    new ClipboardItem({ 'image/png': blob })
                  ]);
                  setCopied(true);
                  setTimeout(() => setCopied(false), 2000);
                } catch (err) {
                  // Fallback to copying text if image copy fails
                  await navigator.clipboard.writeText(keypairDisplay.publicKey);
                  setCopied(true);
                  setTimeout(() => setCopied(false), 2000);
                }
              }
            }, 'image/png');
          };
          
          img.src = 'data:image/svg+xml;base64,' + btoa(svgData);
        }
      } catch (err) {
        // Fallback to text copy
        await navigator.clipboard.writeText(keypairDisplay.publicKey);
        setCopied(true);
        setTimeout(() => setCopied(false), 2000);
      }
    } else if (displayFormat === 'words' && publicKeyWords) {
      await navigator.clipboard.writeText(publicKeyWords.replace(/\n/g, ' '));
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } else if (keypairDisplay) {
      await navigator.clipboard.writeText(keypairDisplay.publicKey);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  const copyOutput = async () => {
    if (output) {
      // Remove the "Encrypted:" or "Decrypted:" prefix when copying
      const textToCopy = output.replace(/^(Encrypted:|Decrypted:)\n/, '');
      await navigator.clipboard.writeText(textToCopy);
      setCopiedOutput(true);
      setTimeout(() => setCopiedOutput(false), 2000);
    }
  };

  const effectiveMasterKey = masterKey;

  const encryptedPrivateKey = useMemo(() => {
    if (!keypair || !effectiveMasterKey) return null;
    
    try {
      // Derive a key from the effective master key using hash
      const masterKeyBytes = new TextEncoder().encode(effectiveMasterKey);
      const hashedKey = nacl.hash(masterKeyBytes).slice(0, nacl.secretbox.keyLength);
      
      // Generate a random nonce
      const nonce = nacl.randomBytes(nacl.secretbox.nonceLength);
      
      // Encrypt the secret key
      const encrypted = nacl.secretbox(keypair.secretKey, nonce, hashedKey);
      
      // Combine nonce and encrypted data
      const fullMessage = new Uint8Array(nonce.length + encrypted.length);
      fullMessage.set(nonce);
      fullMessage.set(encrypted, nonce.length);
      
      // Convert to base36 and format
      return formatInGroups(uint8ArrayToBase36(fullMessage));
    } catch (error) {
      console.error('Failed to encrypt private key:', error);
      return null;
    }
  }, [keypair, effectiveMasterKey, nonceCounter]);

  // Update URL hash when encrypted private key changes
  useEffect(() => {
    if (encryptedPrivateKey) {
      // Remove spaces from the encrypted key for URL
      const cleanKey = encryptedPrivateKey.replace(/\s/g, '');
      window.location.hash = cleanKey;
    }
  }, [encryptedPrivateKey]);

  // Handle master key submission
  const handleMasterKeySubmit = () => {
    if (!masterKey) return;
    
    // Check minimum length
    if (masterKey.length < 12) {
      alert('Master key must be at least 12 characters long');
      return;
    }
    
    const hash = window.location.hash.slice(1);
    if (hash) {
      // Try to restore with the user's master key
      const restored = tryRestoreFromHash(hash, masterKey);
      if (restored) {
        setWaitingForMasterKey(false);
        setMasterKeyLocked(true);
      } else {
        // Wrong master key for this hash
        alert('Invalid master key for the encrypted private key in URL');
      }
    } else {
      // No hash, generate new keypair
      generateKeypair();
      setMasterKeyLocked(true);
    }
  };

  const copyEncryptedKey = async () => {
    if (encryptedPrivateKey) {
      await navigator.clipboard.writeText(encryptedPrivateKey);
      setCopiedEncryptedKey(true);
      setTimeout(() => setCopiedEncryptedKey(false), 2000);
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
      // Auto-detect format and convert to Uint8Array
      let recipientKey: Uint8Array;
      if (isBIP39Format(recipientPublicKey)) {
        const words = recipientPublicKey.toLowerCase().trim().split(/\s+/);
        recipientKey = wordsToUint8Array(words);
      } else {
        recipientKey = base36ToUint8Array(recipientPublicKey, 32);
      }
      
      const nonce = nacl.randomBytes(nacl.box.nonceLength);
      const messageUint8 = new TextEncoder().encode(message);
      
      const encrypted = nacl.box(messageUint8, nonce, recipientKey, keypair.secretKey);
      
      const fullMessage = new Uint8Array(nonce.length + encrypted.length);
      fullMessage.set(nonce);
      fullMessage.set(encrypted, nonce.length);
      
      const encryptedBase36 = formatInGroups(uint8ArrayToBase36(fullMessage));
      setOutput(`Encrypted:\n${encryptedBase36}`);
      // Re-encrypt private key with new nonce
      setNonceCounter(prev => prev + 1);
    } catch (error) {
      setOutput(`Encryption error: ${error}`);
    } finally {
      setIsEncrypting(false);
    }
  };

  const startScanner = async () => {
    if (!videoRef.current) return;
    
    try {
      // First check if camera is available
      const hasCamera = await QrScanner.hasCamera();
      if (!hasCamera) {
        alert('No camera found on this device.');
        setShowScanner(false);
        return;
      }

      // For iOS, we need to explicitly request camera permission
      try {
        const stream = await navigator.mediaDevices.getUserMedia({ 
          video: { 
            facingMode: 'environment' // Prefer back camera
          } 
        });
        // Stop the test stream immediately
        stream.getTracks().forEach(track => track.stop());
      } catch (permError) {
        console.error('Camera permission denied:', permError);
        alert('Camera access denied. Please enable camera permissions for this site in your browser settings.');
        setShowScanner(false);
        return;
      }

      const scanner = new QrScanner(
        videoRef.current,
        (result: QrScanner.ScanResult) => {
          // Handle the scanned result
          const scannedText = result.data;
          
          // Check if it's a valid public key format
          if (scannedText) {
            // Remove any whitespace for validation
            const cleanText = scannedText.trim();
            
            // Set the recipient public key field
            setRecipientPublicKey(cleanText);
            
            // Close the scanner
            stopScanner();
          }
        },
        {
          returnDetailedScanResult: true,
          highlightScanRegion: true,
          highlightCodeOutline: true,
          preferredCamera: 'environment', // Use back camera
          maxScansPerSecond: 5,
        }
      );
      
      scannerRef.current = scanner;
      await scanner.start();
    } catch (error) {
      console.error('Failed to start scanner:', error);
      alert('Failed to access camera. Please ensure camera permissions are granted and try again.');
      setShowScanner(false);
    }
  };

  const stopScanner = () => {
    if (scannerRef.current) {
      scannerRef.current.stop();
      scannerRef.current.destroy();
      scannerRef.current = null;
    }
    setShowScanner(false);
  };

  // Start scanner when modal opens
  useEffect(() => {
    if (showScanner && videoRef.current) {
      startScanner();
    }
    
    return () => {
      if (scannerRef.current) {
        scannerRef.current.stop();
        scannerRef.current.destroy();
        scannerRef.current = null;
      }
    };
  }, [showScanner]);

  const handleDecrypt = async () => {
    if (!keypair || !recipientPublicKey || !message) {
      setOutput('Error: Missing keypair, sender public key, or encrypted message');
      return;
    }

    setIsDecrypting(true);
    setOutput('Decrypting...');

    await new Promise(resolve => setTimeout(resolve, 300));

    try {
      // Auto-detect format and convert to Uint8Array
      let senderKey: Uint8Array;
      if (isBIP39Format(recipientPublicKey)) {
        const words = recipientPublicKey.toLowerCase().trim().split(/\s+/);
        senderKey = wordsToUint8Array(words);
      } else {
        senderKey = base36ToUint8Array(recipientPublicKey, 32);
      }
      
      const fullMessage = base36ToUint8Array(message);
      
      const nonce = fullMessage.slice(0, nacl.box.nonceLength);
      const encrypted = fullMessage.slice(nacl.box.nonceLength);
      
      const decrypted = nacl.box.open(encrypted, nonce, senderKey, keypair.secretKey);
      
      if (!decrypted) {
        setOutput('Decryption failed: Invalid message or wrong keys');
        setIsDecrypting(false);
        return;
      }
      
      const decryptedMessage = new TextDecoder().decode(decrypted);
      setOutput(`Decrypted:\n${decryptedMessage}`);
      // Re-encrypt private key with new nonce
      setNonceCounter(prev => prev + 1);
    } catch (error) {
      setOutput(`Decryption error: ${error}`);
    } finally {
      setIsDecrypting(false);
    }
  };

  // Show lock screen if master key not set
  if (!masterKeyLocked) {
    return (
      <div style={{ 
        height: '100vh',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        fontFamily: 'Arial, sans-serif',
        backgroundColor: '#f5f5f5'
      }}>
        <div style={{
          backgroundColor: 'white',
          padding: '40px',
          borderRadius: '12px',
          boxShadow: '0 4px 6px rgba(0, 0, 0, 0.1)',
          maxWidth: '400px',
          width: '100%'
        }}>
          <h1 style={{ 
            margin: '0 0 10px 0',
            fontSize: '28px',
            textAlign: 'center'
          }}>
            🔐 E2EE Local Messenger
          </h1>
          
          <p style={{ 
            textAlign: 'center',
            color: '#666',
            marginBottom: '30px',
            fontSize: '14px'
          }}>
            Enter your master key to unlock
          </p>

          <input
            type="password"
            value={masterKey}
            onChange={(e) => setMasterKey(e.target.value)}
            onKeyPress={(e) => e.key === 'Enter' && handleMasterKeySubmit()}
            placeholder="Master key / password"
            autoFocus
            style={{
              width: '100%',
              padding: '12px',
              fontFamily: 'monospace',
              fontSize: '16px',
              border: '2px solid #ddd',
              borderRadius: '6px',
              marginBottom: '15px',
              boxSizing: 'border-box'
            }}
          />
          
          <button
            onClick={handleMasterKeySubmit}
            disabled={!masterKey || masterKey.length < 12}
            style={{
              width: '100%',
              padding: '12px',
              backgroundColor: masterKey && masterKey.length >= 12 ? '#4CAF50' : '#ccc',
              color: 'white',
              border: 'none',
              borderRadius: '6px',
              fontSize: '16px',
              fontWeight: 'bold',
              cursor: masterKey && masterKey.length >= 12 ? 'pointer' : 'not-allowed',
              transition: 'background-color 0.2s'
            }}
          >
            Unlock
          </button>

          {waitingForMasterKey && (
            <>
              <p style={{ 
                fontSize: '12px', 
                color: '#ff9800',
                margin: '15px 0 0 0',
                textAlign: 'center'
              }}>
                📋 Encrypted key found in URL. Enter your master key to restore.
              </p>
              <button
                onClick={() => {
                  if (window.confirm('This will clear the encrypted private key from the URL.\n\nYou will get a new keypair and lose access to messages encrypted with the old key.\n\nContinue?')) {
                    window.location.hash = '';
                    setWaitingForMasterKey(false);
                  }
                }}
                style={{
                  background: 'transparent',
                  color: '#666',
                  border: 'none',
                  fontSize: '11px',
                  cursor: 'pointer',
                  marginTop: '8px',
                  textDecoration: 'underline',
                  padding: '4px',
                  transition: 'color 0.2s',
                  display: 'block',
                  margin: '8px auto 0',
                  textAlign: 'center'
                }}
                onMouseOver={(e) => e.currentTarget.style.color = '#f44336'}
                onMouseOut={(e) => e.currentTarget.style.color = '#666'}
              >
                (Need a fresh start?)
              </button>
            </>
          )}
          
          {!waitingForMasterKey && (
            <p style={{ 
              fontSize: '12px', 
              color: '#666',
              margin: '15px 0 0 0',
              textAlign: 'center'
            }}>
              {masterKey.length > 0 && masterKey.length < 12 ? (
                <span style={{ color: '#ff9800' }}>
                  {masterKey.length}/12 characters minimum
                </span>
              ) : masterKey.length >= 12 ? (
                'This key will encrypt your private keys for security'
              ) : (
                'This key will encrypt your private keys for security'
              )}
            </p>
          )}
        </div>
      </div>
    );
  }

  // Main app UI (after master key is set)
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
        <h1 style={{ 
          textAlign: 'center',
          fontSize: '32px',
          marginBottom: '30px',
          color: '#333'
        }}>
          🔐 E2EE Local Messenger
        </h1>
        
        {/* Master Key Card */}
        <div style={{
          backgroundColor: 'white',
          borderRadius: '8px',
          padding: '20px',
          marginBottom: '20px',
          boxShadow: '0 2px 4px rgba(0, 0, 0, 0.1)'
        }}>
          <div style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            marginBottom: '10px'
          }}>
            <h3 style={{ 
              margin: 0,
              fontSize: '18px',
              color: '#333',
              display: 'flex',
              alignItems: 'center',
              gap: '8px'
            }}>
              <span style={{ color: '#4CAF50' }}>✓</span>
              Master Key (Unlocked)
            </h3>
            <button
              onClick={() => {
                if (window.confirm('Lock the app?\n\nThis will clear your master key from memory. Your encrypted private key remains in the URL.\n\nContinue?')) {
                  setMasterKey('');
                  setMasterKeyLocked(false);
                  // Set waiting flag if there's a hash so lock screen shows restore message
                  if (window.location.hash) {
                    setWaitingForMasterKey(true);
                  }
                }
              }}
              title="Lock the app"
              style={{
                background: 'white',
                border: '1px solid #e0e0e0',
                borderRadius: '6px',
                padding: '4px 10px',
                cursor: 'pointer',
                fontSize: '13px',
                color: '#666',
                display: 'flex',
                alignItems: 'center',
                gap: '4px',
                transition: 'all 0.2s'
              }}
              onMouseOver={(e) => e.currentTarget.style.borderColor = '#f44336'}
              onMouseOut={(e) => e.currentTarget.style.borderColor = '#e0e0e0'}
            >
              🔒 Lock
            </button>
          </div>
          <div style={{
            padding: '10px',
            fontFamily: 'monospace',
            fontSize: '14px',
            border: '1px solid #e0e0e0',
            borderRadius: '6px',
            backgroundColor: '#fafafa'
          }}>
            {'•'.repeat(masterKey.length)}
          </div>
        </div>
      
        {/* Keys Card */}
        {masterKeyLocked && (
          <div style={{
            backgroundColor: 'white',
            borderRadius: '8px',
            padding: '20px',
            marginBottom: '20px',
            boxShadow: '0 2px 4px rgba(0, 0, 0, 0.1)'
          }}>
            <div style={{ 
              display: 'flex', 
              alignItems: 'center', 
              justifyContent: 'space-between',
              marginBottom: '15px' 
            }}>
              <h3 style={{ 
                margin: 0,
                fontSize: '18px',
                color: '#333'
              }}>
                🔑 Your Keys
              </h3>
              <div style={{ display: 'flex', gap: '10px' }}>
                <button
                  onClick={() => {
                    if (window.confirm('Generate new keys?\n\nThis will replace your current keypair. You will lose access to messages encrypted with the old keys.\n\nContinue?')) {
                      generateKeypair(true);
                    }
                  }}
                  disabled={isRegenerating}
                  title="Generate new keypair"
                  style={{
                    background: 'white',
                    border: '1px solid #e0e0e0',
                    borderRadius: '6px',
                    padding: '6px 12px',
                    cursor: isRegenerating ? 'not-allowed' : 'pointer',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '6px',
                    fontSize: '14px',
                    opacity: isRegenerating ? 0.6 : 1,
                    transition: 'all 0.2s'
                  }}
                >
                  <IconRefresh size={16} />
                  {isRegenerating ? 'Regenerating...' : 'Regenerate'}
                </button>
              </div>
            </div>
            <div style={{
              backgroundColor: '#fafafa',
              border: '1px solid #e0e0e0',
              borderRadius: '6px',
              padding: '15px',
              fontFamily: 'monospace',
              fontSize: '13px',
              whiteSpace: 'pre-wrap',
              wordBreak: 'break-all'
            }}>
              {isRegenerating ? (
            'Regenerating keypair...'
          ) : waitingForMasterKey ? (
            <span style={{ color: '#d32f2f' }}>
              ⚠️ Enter your master key above to restore your encrypted private key from URL
            </span>
          ) : keypairDisplay ? (
            <>
              {userId && (
                <>
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                    <strong>User ID:</strong>
                  </div>
                  {userId}
                  {'\n\n'}
                </>
              )}
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                <strong>Private Key (Encrypted with Master Key):</strong>
              </div>
              {encryptedPrivateKey || 'Generating...'}
              {'\n\n'}
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                <strong>Public Key (Share with your recipient):</strong>
                <div style={{ display: 'flex', gap: '6px' }}>
                  <button
                    onClick={() => {
                      if (displayFormat === 'base36') setDisplayFormat('words');
                      else if (displayFormat === 'words') setDisplayFormat('qr');
                      else setDisplayFormat('base36');
                    }}
                    title="Toggle display format"
                    style={{
                      background: 'transparent',
                      border: '1px solid #ddd',
                      borderRadius: '4px',
                      padding: '2px 6px',
                      cursor: 'pointer',
                      fontSize: '12px'
                    }}
                  >
                    {displayFormat === 'base36' ? 'Base36' : displayFormat === 'words' ? 'Words' : 'QR'}
                  </button>
                  <button
                    onClick={copyPublicKey}
                    title="Copy public key to clipboard"
                    style={{
                      background: 'transparent',
                      border: '1px solid #ddd',
                      borderRadius: '4px',
                      padding: '2px 6px',
                      cursor: 'pointer',
                      display: 'flex',
                      alignItems: 'center',
                      gap: '4px',
                      fontSize: '12px'
                    }}
                  >
                    {copied ? <IconCheck size={14} /> : <IconCopy size={14} />}
                    {copied ? 'Copied!' : 'Copy'}
                  </button>
                </div>
              </div>
              {displayFormat === 'words' && publicKeyWords ? (
                <div style={{ fontSize: '12px', lineHeight: '1.6' }}>
                  {publicKeyWords}
                </div>
              ) : displayFormat === 'qr' && keypairDisplay ? (
                <div style={{ 
                  display: 'flex', 
                  justifyContent: 'center', 
                  padding: '10px 0',
                  backgroundColor: 'white',
                  borderRadius: '4px'
                }}>
                  <QRCodeSVG 
                    id="public-key-qr"
                    value={keypairDisplay.publicKey.replace(/\s/g, '')} 
                    size={160}
                    level="M"
                    includeMargin={true}
                  />
                </div>
              ) : (
                keypairDisplay.publicKey
              )}
            </>
          ) : (
            'Generating keypair...'
            )}
            </div>
          </div>
        )}

        {/* Encrypt/Decrypt Card */}
        {keypair && !waitingForMasterKey && (
          <div style={{
            backgroundColor: 'white',
            borderRadius: '8px',
            padding: '20px',
            boxShadow: '0 2px 4px rgba(0, 0, 0, 0.1)'
          }}>
            <h3 style={{ 
              margin: '0 0 20px 0',
              fontSize: '18px',
              color: '#333'
            }}>
              💬 Encrypt/Decrypt Messages
            </h3>
        
            <div style={{ marginBottom: '20px' }}>
              <label style={{ 
                display: 'block', 
                marginBottom: '8px',
                fontSize: '14px',
                fontWeight: '500',
                color: '#555'
              }}>
                Recipient's Public Key:
              </label>
              <div style={{ position: 'relative', display: 'flex', gap: '8px' }}>
                <input
                  type="text"
                  value={recipientPublicKey}
                  onChange={(e) => setRecipientPublicKey(e.target.value)}
                  placeholder="Enter public key (base36 or 24 words)..."
                  style={{
                    flex: 1,
                    padding: '10px',
                    fontFamily: 'monospace',
                    fontSize: '14px',
                    border: '1px solid #e0e0e0',
                    borderRadius: '6px',
                    boxSizing: 'border-box',
                    transition: 'border-color 0.2s'
                  }}
                />
                <button
                  onClick={() => {
                    // Check if we're on HTTPS or localhost
                    const isSecure = window.location.protocol === 'https:' || 
                                   window.location.hostname === 'localhost' || 
                                   window.location.hostname === '127.0.0.1';
                    
                    if (!isSecure) {
                      alert('Camera access requires HTTPS. Please use HTTPS or run on localhost.');
                      return;
                    }
                    
                    setShowScanner(true);
                  }}
                  title="Scan QR code"
                  style={{
                    padding: '10px',
                    backgroundColor: 'white',
                    border: '1px solid #e0e0e0',
                    borderRadius: '6px',
                    cursor: 'pointer',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    transition: 'all 0.2s'
                  }}
                  onMouseOver={(e) => {
                    e.currentTarget.style.backgroundColor = '#f5f5f5';
                    e.currentTarget.style.borderColor = '#2196F3';
                  }}
                  onMouseOut={(e) => {
                    e.currentTarget.style.backgroundColor = 'white';
                    e.currentTarget.style.borderColor = '#e0e0e0';
                  }}
                >
                  <IconQrcode size={20} />
                </button>
              </div>
            </div>

            <div style={{ marginBottom: '20px' }}>
              <label style={{ 
                display: 'block', 
                marginBottom: '8px',
                fontSize: '14px',
                fontWeight: '500',
                color: '#555'
              }}>
                Message:
              </label>
              <textarea
                value={message}
                onChange={(e) => setMessage(e.target.value)}
                placeholder="Enter your message contents here..."
                rows={4}
                style={{
                  width: '100%',
                  padding: '10px',
                  fontFamily: 'monospace',
                  fontSize: '14px',
                  border: '1px solid #e0e0e0',
                  borderRadius: '6px',
                  boxSizing: 'border-box',
                  resize: 'vertical',
                  transition: 'border-color 0.2s'
                }}
              />
            </div>

            <div style={{ 
              display: 'flex',
              gap: '10px',
              marginBottom: '20px' 
            }}>
              <button 
                onClick={handleEncrypt}
                disabled={isEncrypting || isDecrypting}
                style={{
                  flex: 1,
                  padding: '12px',
                  backgroundColor: isEncrypting || isDecrypting ? '#ccc' : '#4CAF50',
                  color: 'white',
                  border: 'none',
                  borderRadius: '6px',
                  fontSize: '16px',
                  fontWeight: '500',
                  cursor: isEncrypting || isDecrypting ? 'not-allowed' : 'pointer',
                  transition: 'background-color 0.2s'
                }}
              >
                {isEncrypting ? 'Encrypting...' : 'Encrypt'}
              </button>
              <button 
                onClick={handleDecrypt}
                disabled={isEncrypting || isDecrypting}
                style={{
                  flex: 1,
                  padding: '12px',
                  backgroundColor: isEncrypting || isDecrypting ? '#ccc' : '#2196F3',
                  color: 'white',
                  border: 'none',
                  borderRadius: '6px',
                  fontSize: '16px',
                  fontWeight: '500',
                  cursor: isEncrypting || isDecrypting ? 'not-allowed' : 'pointer',
                  transition: 'background-color 0.2s'
                }}
              >
                {isDecrypting ? 'Decrypting...' : 'Decrypt'}
              </button>
            </div>

            {output && (
              <div>
                <label style={{ 
                  display: 'block', 
                  marginBottom: '8px',
                  fontSize: '14px',
                  fontWeight: '500',
                  color: '#555'
                }}>
                  Output:
                </label>
                <div style={{
                  backgroundColor: '#fafafa',
                  border: '1px solid #e0e0e0',
                  borderRadius: '6px',
                  padding: '15px',
                  fontFamily: 'monospace',
                  fontSize: '13px',
                  whiteSpace: 'pre-wrap',
                  wordBreak: 'break-all',
                  position: 'relative'
                }}>
                  <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between' }}>
                    <div style={{ flex: 1 }}>
                      {output}
                    </div>
                    {output !== 'Encrypting...' && output !== 'Decrypting...' && (
                      <button
                        onClick={copyOutput}
                        title="Copy output to clipboard"
                        style={{
                          background: 'white',
                          border: '1px solid #e0e0e0',
                          borderRadius: '4px',
                          padding: '4px 8px',
                          cursor: 'pointer',
                          display: 'flex',
                          alignItems: 'center',
                          gap: '4px',
                          fontSize: '12px',
                          marginLeft: '10px',
                          flexShrink: 0,
                          transition: 'all 0.2s'
                        }}
                      >
                        {copiedOutput ? <IconCheck size={14} /> : <IconCopy size={14} />}
                        {copiedOutput ? 'Copied!' : 'Copy'}
                      </button>
                    )}
                  </div>
                </div>
              </div>
            )}
          </div>
        )}
        
        {/* QR Scanner Modal */}
        {showScanner && (
          <div style={{
            position: 'fixed',
            top: 0,
            left: 0,
            right: 0,
            bottom: 0,
            backgroundColor: 'rgba(0, 0, 0, 0.9)',
            zIndex: 1000,
            display: 'flex',
            flexDirection: 'column',
            alignItems: 'center',
            justifyContent: 'center'
          }}>
            <div style={{
              backgroundColor: 'white',
              borderRadius: '12px',
              padding: '20px',
              maxWidth: '500px',
              width: '90%',
              maxHeight: '90vh',
              display: 'flex',
              flexDirection: 'column'
            }}>
              <div style={{
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
                marginBottom: '15px'
              }}>
                <h3 style={{ margin: 0 }}>Scan QR Code</h3>
                <button
                  onClick={stopScanner}
                  style={{
                    background: 'transparent',
                    border: 'none',
                    cursor: 'pointer',
                    padding: '4px'
                  }}
                >
                  <IconX size={24} />
                </button>
              </div>
              
              <div style={{
                position: 'relative',
                width: '100%',
                backgroundColor: '#000',
                borderRadius: '8px',
                overflow: 'hidden'
              }}>
                <video
                  ref={videoRef}
                  playsInline
                  muted
                  style={{
                    width: '100%',
                    height: 'auto',
                    display: 'block'
                  }}
                />
              </div>
              
              <p style={{
                textAlign: 'center',
                color: '#666',
                fontSize: '14px',
                marginTop: '15px',
                marginBottom: 0
              }}>
                Position the QR code within the frame to scan
              </p>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default App;
