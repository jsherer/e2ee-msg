import React, { useState, useEffect } from 'react';
import * as nacl from 'tweetnacl';
import { IconRefresh, IconCopy, IconCheck } from '@tabler/icons-react';

const App: React.FC = () => {
  const [keypair, setKeypair] = useState<{ publicKey: Uint8Array; secretKey: Uint8Array } | null>(null);
  const [keypairDisplay, setKeypairDisplay] = useState<{ publicKey: string; secretKey: string } | null>(null);
  const [recipientPublicKey, setRecipientPublicKey] = useState('');
  const [message, setMessage] = useState('');
  const [output, setOutput] = useState('');
  const [isDecrypting, setIsDecrypting] = useState(false);
  const [isEncrypting, setIsEncrypting] = useState(false);
  const [copied, setCopied] = useState(false);
  const [isRegenerating, setIsRegenerating] = useState(false);

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

  useEffect(() => {
    generateKeypair();
  }, []);

  const copyPublicKey = async () => {
    if (keypairDisplay) {
      await navigator.clipboard.writeText(keypairDisplay.publicKey);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
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
    } catch (error) {
      setOutput(`Decryption error: ${error}`);
    } finally {
      setIsDecrypting(false);
    }
  };

  return (
    <div style={{ padding: '20px', fontFamily: 'Arial, sans-serif' }}>
      <h1>End-to-End Encryption Messenger</h1>
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
        <div style={{ display: 'flex', alignItems: 'center', marginBottom: '10px' }}>
          <h3 style={{ margin: 0, marginRight: '10px' }}>Your Keypair (Base36)</h3>
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
          ) : keypairDisplay ? (
            <>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                <strong>Public Key:</strong>
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
              {'\n\n'}
              <strong>Secret Key:</strong>{'\n'}
              {keypairDisplay.secretKey.replace(/[a-z0-9]/g, '•')}
            </>
          ) : (
            'Generating keypair...'
          )}
        </code>
      </div>

      <div style={{ marginTop: '20px', marginBottom: '20px' }}>
        <h3>Encrypt/Decrypt Messages</h3>
        
        <div style={{ marginBottom: '15px' }}>
          <label style={{ display: 'block', marginBottom: '5px' }}>
            Other Person's Public Key (base36) - Recipient for encrypt, Sender for decrypt:
          </label>
          <input
            type="text"
            value={recipientPublicKey}
            onChange={(e) => setRecipientPublicKey(e.target.value)}
            placeholder="Enter public key in base36 format"
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
            Message (plain text for encrypt, base36 for decrypt):
          </label>
          <textarea
            value={message}
            onChange={(e) => setMessage(e.target.value)}
            placeholder="Enter your message here"
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
              wordBreak: 'break-all'
            }}>
              {output}
            </code>
          </div>
        )}
      </div>
    </div>
  );
};

export default App;
