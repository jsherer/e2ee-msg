import React from 'react';
import { IconRefresh, IconCopy, IconCheck } from '@tabler/icons-react';
import { QRCodeSVG } from 'qrcode.react';
import { DisplayFormat, KeyPairDisplay } from '../types';

interface KeysDisplayProps {
  userId: string | null;
  encryptedPrivateKey: string | null;
  keypairDisplay: KeyPairDisplay | null;
  publicKeyWords: string | null;
  displayFormat: DisplayFormat;
  setDisplayFormat: (format: DisplayFormat) => void;
  copied: boolean;
  onCopyPublicKey: () => void;
  isRegenerating: boolean;
  onRegenerate: () => void;
}

export const KeysDisplay: React.FC<KeysDisplayProps> = ({
  userId,
  encryptedPrivateKey,
  keypairDisplay,
  publicKeyWords,
  displayFormat,
  setDisplayFormat,
  copied,
  onCopyPublicKey,
  isRegenerating,
  onRegenerate
}) => {
  const toggleFormat = () => {
    const formats: DisplayFormat[] = ['base36', 'words', 'qr'];
    const currentIndex = formats.indexOf(displayFormat);
    setDisplayFormat(formats[(currentIndex + 1) % 3]);
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
        <strong>Private Key (Encrypted):</strong> {encryptedPrivateKey || 'Generating...'}
        {'\n\n'}
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <strong>Public Key:</strong>
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
              {displayFormat === 'base36' ? 'Base36' : displayFormat === 'words' ? 'Words' : 'QR'}
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
          keypairDisplay?.publicKey || 'Generating...'
        )}
      </div>
    </div>
  );
};