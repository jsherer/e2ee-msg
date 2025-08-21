import React, { useState, useEffect } from 'react';
import * as nacl from 'tweetnacl';

const App: React.FC = () => {
  const [keypair, setKeypair] = useState<{ publicKey: Uint8Array; secretKey: Uint8Array } | null>(null);
  const [keypairDisplay, setKeypairDisplay] = useState<{ publicKey: string; secretKey: string } | null>(null);
  const [recipientPublicKey, setRecipientPublicKey] = useState('');
  const [message, setMessage] = useState('');
  const [output, setOutput] = useState('');

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

  useEffect(() => {
    const pair = nacl.box.keyPair();
    
    setKeypair(pair);
    
    const publicKeyBase36 = formatInGroups(uint8ArrayToBase36(pair.publicKey));
    const secretKeyBase36 = formatInGroups(uint8ArrayToBase36(pair.secretKey));
    
    setKeypairDisplay({
      publicKey: publicKeyBase36,
      secretKey: secretKeyBase36
    });
  }, []);

  const handleEncrypt = () => {
    if (!keypair || !recipientPublicKey || !message) {
      setOutput('Error: Missing keypair, recipient public key, or message');
      return;
    }

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
    }
  };

  const handleDecrypt = () => {
    if (!keypair || !recipientPublicKey || !message) {
      setOutput('Error: Missing keypair, sender public key, or encrypted message');
      return;
    }

    try {
      const senderKey = base36ToUint8Array(recipientPublicKey, 32);
      const fullMessage = base36ToUint8Array(message);
      
      const nonce = fullMessage.slice(0, nacl.box.nonceLength);
      const encrypted = fullMessage.slice(nacl.box.nonceLength);
      
      const decrypted = nacl.box.open(encrypted, nonce, senderKey, keypair.secretKey);
      
      if (!decrypted) {
        setOutput('Decryption failed: Invalid message or wrong keys');
        return;
      }
      
      const decryptedMessage = new TextDecoder().decode(decrypted);
      setOutput(`Decrypted:\n${decryptedMessage}`);
    } catch (error) {
      setOutput(`Decryption error: ${error}`);
    }
  };

  return (
    <div style={{ padding: '20px', fontFamily: 'Arial, sans-serif' }}>
      <h1>React + TypeScript App</h1>
      <p>This is a basic React app with TypeScript!</p>
      
      <div style={{ marginTop: '20px', marginBottom: '20px' }}>
        <h3>Your Keypair (Base36)</h3>
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
          {keypairDisplay ? (
            <>
              <strong>Public Key:</strong>{'\n'}
              {keypairDisplay.publicKey}
              {'\n\n'}
              <strong>Secret Key:</strong>{'\n'}
              {keypairDisplay.secretKey}
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
            Other Person's Public Key (base36):
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
            style={{
              padding: '10px 20px',
              marginRight: '10px',
              backgroundColor: '#4CAF50',
              color: 'white',
              border: 'none',
              borderRadius: '4px',
              cursor: 'pointer'
            }}
          >
            Encrypt
          </button>
          <button 
            onClick={handleDecrypt}
            style={{
              padding: '10px 20px',
              backgroundColor: '#2196F3',
              color: 'white',
              border: 'none',
              borderRadius: '4px',
              cursor: 'pointer'
            }}
          >
            Decrypt
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
