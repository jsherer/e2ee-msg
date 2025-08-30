import React from 'react';
import { IconRefresh, IconCopy, IconCheck } from '@tabler/icons-react';
import { QRCodeSVG } from 'qrcode.react';
import { DisplayFormat, KeyPairDisplay, PRPCapKeyPair } from '../types';
import { uint8ArrayToBase32Crockford, formatInGroups } from '../utils/encoding';

// Helper to format bytes as hex with proper spacing
const formatBytesAsHex = (bytes: Uint8Array): string => {
  return Array.from(bytes)
    .map(b => b.toString(16).padStart(2, '0'))
    .join(' ')
    .match(/.{1,48}/g)?.join('\n') || '';
};

interface KeysDisplayProps {
  userId: string | null;
  encryptedPrivateKey: string | null;
  keypairDisplay: KeyPairDisplay | null;
  keypair?: PRPCapKeyPair | null;
  displayFormat: DisplayFormat;
  setDisplayFormat: (format: DisplayFormat) => void;
  copied: boolean;
  onCopyPublicKey: () => void;
  isRegenerating: boolean;
  onRegenerate: () => void;
  showPrivateKey?: boolean;
}

export const KeysDisplay: React.FC<KeysDisplayProps> = ({
  userId,
  encryptedPrivateKey,
  keypairDisplay,
  keypair,
  displayFormat,
  setDisplayFormat,
  copied,
  onCopyPublicKey,
  isRegenerating,
  onRegenerate,
  showPrivateKey = false,
}) => {
  const toggleFormat = () => {
    const formats: DisplayFormat[] = ['base32', 'qr'];
    const currentIndex = formats.indexOf(displayFormat);
    setDisplayFormat(formats[(currentIndex + 1) % 2]);
  };

  return (
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
          <br/>
          <small style={{fontSize:12, fontStyle:'italic', fontWeight:'normal'}}>Your private key is encrypted and hidden</small>
        </h3>
        <button
          onClick={onRegenerate}
          disabled={isRegenerating}
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
        {userId && (
          <>
            <strong>User ID:</strong> {userId}
            {'\n\n'}
          </>
        )}
        {keypair?.epoch ? (
          <>
            <div style={{ marginBottom: '15px' }}>
              <strong style={{ color: '#666' }}>Identity Key (X25519 - 32 bytes):</strong>
              <div style={{ 
                fontFamily: 'monospace', 
                fontSize: '12px',
                marginTop: '5px',
                padding: '8px',
                backgroundColor: 'white',
                borderRadius: '4px',
                border: '1px solid #e0e0e0'
              }}>
                {keypair.publicKey ? formatBytesAsHex(keypair.publicKey) : 'Not available'}
              </div>
            </div>
            
            <div style={{ marginBottom: '15px' }}>
              <strong style={{ color: '#666' }}>Epoch Parameter A (Ed25519 Point - 32 bytes):</strong>
              <div style={{ 
                fontFamily: 'monospace', 
                fontSize: '12px',
                marginTop: '5px',
                padding: '8px',
                backgroundColor: 'white',
                borderRadius: '4px',
                border: '1px solid #e0e0e0'
              }}>
                {keypair.epoch.A ? formatBytesAsHex(keypair.epoch.A) : 'Not available'}
              </div>
            </div>
            
            <div style={{ marginBottom: '15px' }}>
              <strong style={{ color: '#666' }}>Epoch Parameter B (Ed25519 Point - 32 bytes):</strong>
              <div style={{ 
                fontFamily: 'monospace', 
                fontSize: '12px',
                marginTop: '5px',
                padding: '8px',
                backgroundColor: 'white',
                borderRadius: '4px',
                border: '1px solid #e0e0e0'
              }}>
                {keypair.epoch.B ? formatBytesAsHex(keypair.epoch.B) : 'Not available'}
              </div>
            </div>

            <div style={{ marginBottom: '10px' }}>
              <strong style={{ color: '#666', fontSize: '12px' }}>
                Epoch ID: {keypair.epoch.epochId?.substring(0, 16)}... | 
                Valid Until: {new Date(keypair.epoch.validUntil).toLocaleDateString()}
              </strong>
            </div>

            <div style={{ 
              marginTop: '15px',
              paddingTop: '15px',
              borderTop: '1px solid #e0e0e0'
            }}>
              <div style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                marginBottom: '10px'
              }}>
                <strong style={{ color: '#333' }}>Shareable Bundle (All Parameters):</strong>
                <button
                  onClick={onCopyPublicKey}
                  style={{
                    background: 'transparent',
                    border: '1px solid #ddd',
                    borderRadius: '4px',
                    padding: '4px 8px',
                    cursor: 'pointer',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '4px',
                    fontSize: '12px'
                  }}
                >
                  {copied ? <IconCheck size={14} /> : <IconCopy size={14} />}
                  {copied ? 'Copied!' : 'Copy Bundle'}
                </button>
              </div>
              <div style={{ 
                fontFamily: 'monospace', 
                fontSize: '12px',
                padding: '8px',
                backgroundColor: 'white',
                borderRadius: '4px',
                border: '1px solid #e0e0e0',
                wordBreak: 'break-all'
              }}>
                {keypairDisplay?.publicKey || 'Generating...'}
              </div>
            </div>
          </>
        ) : (
          <>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
              <strong>Public Key (Share this with your recipient):</strong>
              <div style={{ display: 'flex', gap: '6px' }}>
                <button
                  onClick={toggleFormat}
                  style={{
                    background: 'transparent',
                    border: '1px solid #ddd',
                    borderRadius: '4px',
                    padding: '2px 6px',
                    cursor: 'pointer',
                    fontSize: '12px'
                  }}
                >
                  {displayFormat === 'base32' ? 'Base32' : 'QR'}
                </button>
                <button
                  onClick={onCopyPublicKey}
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
            {displayFormat === 'qr' && keypairDisplay ? (
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
              <div style={{ fontFamily: 'monospace', fontSize: '13px' }}>
                {keypairDisplay?.publicKey || 'Generating...'}
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
};
