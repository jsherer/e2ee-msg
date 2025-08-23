import React from 'react';
import { IconX } from '@tabler/icons-react';

interface QRScannerModalProps {
  videoRef: React.RefObject<HTMLVideoElement>;
  onClose: () => void;
}

export const QRScannerModal: React.FC<QRScannerModalProps> = ({ videoRef, onClose }) => {
  return (
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
            onClick={onClose} 
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
  );
};