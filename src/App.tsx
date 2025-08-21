import React, { useState, useEffect, useMemo } from 'react';
import * as nacl from 'tweetnacl';
import { IconRefresh, IconCopy, IconCheck } from '@tabler/icons-react';

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

  const copyPublicKey = async () => {
    if (keypairDisplay) {
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
      const recipientKey = base36ToUint8Array(recipientPublicKey, 32);
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

  const handleDecrypt = async () => {
    if (!keypair || !recipientPublicKey || !message) {
      setOutput('Error: Missing keypair, sender public key, or encrypted message');
      return;
    }

    setIsDecrypting(true);
    setOutput('Decrypting...');

    await new Promise(resolve => setTimeout(resolve, 300));

    try {
      const senderKey = base36ToUint8Array(recipientPublicKey, 32);
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
            disabled={!masterKey}
            style={{
              width: '100%',
              padding: '12px',
              backgroundColor: masterKey ? '#4CAF50' : '#ccc',
              color: 'white',
              border: 'none',
              borderRadius: '6px',
              fontSize: '16px',
              fontWeight: 'bold',
              cursor: masterKey ? 'pointer' : 'not-allowed',
              transition: 'background-color 0.2s'
            }}
          >
            Unlock
          </button>

          {waitingForMasterKey && (
            <p style={{ 
              fontSize: '12px', 
              color: '#ff9800',
              margin: '15px 0 0 0',
              textAlign: 'center'
            }}>
              📋 Encrypted key found in URL. Enter your master key to restore.
            </p>
          )}
          
          {!waitingForMasterKey && (
            <p style={{ 
              fontSize: '12px', 
              color: '#666',
              margin: '15px 0 0 0',
              textAlign: 'center'
            }}>
              This key will encrypt your private keys for security
            </p>
          )}
        </div>
      </div>
    );
  }

  // Main app UI (after master key is set)
  return (
    <div style={{ padding: '20px', fontFamily: 'Arial, sans-serif' }}>
      <h1>E2EE Local Messenger</h1>
      <div style={{
        backgroundColor: '#e3f2fd',
        border: '1px solid #90caf9',
        borderRadius: '8px',
        padding: '16px',
        marginTop: '16px',
        marginBottom: '20px'
      }}>
        <p style={{ margin: 0, lineHeight: '1.6', color: '#1565c0' }}>
          Send encrypted messages using public key cryptography. Share your public key with others to receive messages, and use their public key to send encrypted messages only they can read.
        </p>
      </div>
      
      <div style={{ marginTop: '20px', marginBottom: '20px' }}>
        <h3>Master Key (Locked)</h3>
        <div style={{
          padding: '8px',
          fontFamily: 'monospace',
          fontSize: '14px',
          border: '1px solid #ddd',
          borderRadius: '4px',
          backgroundColor: '#f9f9f9'
        }}>
          {'•'.repeat(masterKey.length)}
        </div>
      </div>
      
      {masterKeyLocked && (
        <div style={{ marginTop: '20px', marginBottom: '20px' }}>
          <div style={{ display: 'flex', alignItems: 'center', marginBottom: '10px' }}>
            <h3 style={{ margin: 0, marginRight: '10px' }}>Your Keys</h3>
          <button
            onClick={() => generateKeypair(true)}
            disabled={isRegenerating}
            title="Generate new keypair"
            style={{
              background: 'transparent',
              border: '1px solid #ddd',
              borderRadius: '4px',
              padding: '4px 8px',
              cursor: isRegenerating ? 'not-allowed' : 'pointer',
              display: 'flex',
              alignItems: 'center',
              gap: '4px',
              fontSize: '14px',
              opacity: isRegenerating ? 0.6 : 1
            }}
          >
            <IconRefresh size={16} />
            {isRegenerating ? 'Regenerating...' : 'Regen'}
          </button>
        </div>
        <code style={{
          display: 'block',
          backgroundColor: '#f4f4f4',
          border: '1px solid #ddd',
          borderRadius: '4px',
          padding: '15px',
          fontFamily: 'monospace',
          fontSize: '14px',
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
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                <strong>Private Key (Encrypted with Master Key):</strong>
              </div>
              {encryptedPrivateKey || 'Generating...'}
              {'\n\n'}
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                <strong>Public Key (Share with your recipient):</strong>
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
              {keypairDisplay.publicKey}
            </>
          ) : (
            'Generating keypair...'
          )}
        </code>
        </div>
      )}

      {keypair && !waitingForMasterKey && (
        <div style={{ marginTop: '20px', marginBottom: '20px' }}>
          <h3>Encrypt/Decrypt Messages</h3>
        
        <div style={{ marginBottom: '15px' }}>
          <label style={{ display: 'block', marginBottom: '5px' }}>
            Recipient's Public Key:
          </label>
          <input
            type="text"
            value={recipientPublicKey}
            onChange={(e) => setRecipientPublicKey(e.target.value)}
            placeholder="Enter recipient's public key..."
            style={{
              width: '100%',
              padding: '8px',
              fontFamily: 'monospace',
              fontSize: '14px',
              border: '1px solid #ddd',
              borderRadius: '4px'
            }}
          />
        </div>

        <div style={{ marginBottom: '15px' }}>
          <label style={{ display: 'block', marginBottom: '5px' }}>
            Message:
          </label>
          <textarea
            value={message}
            onChange={(e) => setMessage(e.target.value)}
            placeholder="Enter your message contents here..."
            rows={4}
            style={{
              width: '100%',
              padding: '8px',
              fontFamily: 'monospace',
              fontSize: '14px',
              border: '1px solid #ddd',
              borderRadius: '4px'
            }}
          />
        </div>

        <div style={{ marginBottom: '15px' }}>
          <button 
            onClick={handleEncrypt}
            disabled={isEncrypting || isDecrypting}
            style={{
              padding: '10px 20px',
              marginRight: '10px',
              backgroundColor: isEncrypting || isDecrypting ? '#ccc' : '#4CAF50',
              color: 'white',
              border: 'none',
              borderRadius: '4px',
              cursor: isEncrypting || isDecrypting ? 'not-allowed' : 'pointer',
              opacity: isEncrypting || isDecrypting ? 0.6 : 1
            }}
          >
            {isEncrypting ? 'Encrypting...' : 'Encrypt'}
          </button>
          <button 
            onClick={handleDecrypt}
            disabled={isEncrypting || isDecrypting}
            style={{
              padding: '10px 20px',
              backgroundColor: isEncrypting || isDecrypting ? '#ccc' : '#2196F3',
              color: 'white',
              border: 'none',
              borderRadius: '4px',
              cursor: isEncrypting || isDecrypting ? 'not-allowed' : 'pointer',
              opacity: isEncrypting || isDecrypting ? 0.6 : 1
            }}
          >
            {isDecrypting ? 'Decrypting...' : 'Decrypt'}
          </button>
        </div>

        {output && (
          <div style={{ marginTop: '15px' }}>
            <label style={{ display: 'block', marginBottom: '5px' }}>Output:</label>
            <code style={{
              display: 'block',
              backgroundColor: '#f4f4f4',
              border: '1px solid #ddd',
              borderRadius: '4px',
              padding: '15px',
              fontFamily: 'monospace',
              fontSize: '14px',
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
                      background: 'transparent',
                      border: '1px solid #ddd',
                      borderRadius: '4px',
                      padding: '2px 6px',
                      cursor: 'pointer',
                      display: 'flex',
                      alignItems: 'center',
                      gap: '4px',
                      fontSize: '12px',
                      marginLeft: '10px',
                      flexShrink: 0
                    }}
                  >
                    {copiedOutput ? <IconCheck size={14} /> : <IconCopy size={14} />}
                    {copiedOutput ? 'Copied!' : 'Copy'}
                  </button>
                )}
              </div>
            </code>
          </div>
        )}
        </div>
      )}
    </div>
  );
};

export default App;
