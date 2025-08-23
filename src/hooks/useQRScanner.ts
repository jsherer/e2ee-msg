/**
 * Hook for QR code scanning functionality
 */

import { useState, useRef, useEffect } from 'react';
import QrScanner from 'qr-scanner';

export const useQRScanner = (onScanSuccess: (data: string) => void) => {
  const [showScanner, setShowScanner] = useState(false);
  const [hasCamera, setHasCamera] = useState<boolean | null>(null);
  const videoRef = useRef<HTMLVideoElement>(null);
  const scannerRef = useRef<QrScanner | null>(null);

  // Check for camera availability on mount
  useEffect(() => {
    QrScanner.hasCamera().then(setHasCamera).catch(() => setHasCamera(false));
  }, []);

  const startScanner = async () => {
    if (!videoRef.current) return;
    
    try {
      // First check if camera is available
      const hasCam = await QrScanner.hasCamera();
      if (!hasCam) {
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
        
        // Check if we're on HTTPS
        const isSecure = window.location.protocol === 'https:' || 
                       window.location.hostname === 'localhost' || 
                       window.location.hostname === '127.0.0.1';
        
        let errorMessage = 'Camera access denied. ';
        if (!isSecure) {
          errorMessage += 'Camera access requires HTTPS. Please use HTTPS or run on localhost.';
        } else {
          errorMessage += 'Please enable camera permissions for this site in your browser settings.';
        }
        
        alert(errorMessage);
        setShowScanner(false);
        return;
      }

      const scanner = new QrScanner(
        videoRef.current,
        (result: QrScanner.ScanResult) => {
          const scannedText = result.data;
          if (scannedText) {
            onScanSuccess(scannedText.trim());
            stopScanner();
          }
        },
        {
          returnDetailedScanResult: true,
          highlightScanRegion: true,
          highlightCodeOutline: true,
          preferredCamera: 'environment',
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

  const openScanner = () => {
    // Check if we're on HTTPS or localhost
    const isSecure = window.location.protocol === 'https:' || 
                   window.location.hostname === 'localhost' || 
                   window.location.hostname === '127.0.0.1';
    
    if (!isSecure) {
      alert('Camera access requires HTTPS. Please use HTTPS or run on localhost.');
      return;
    }
    
    setShowScanner(true);
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

  return {
    showScanner,
    hasCamera,
    videoRef,
    openScanner,
    stopScanner
  };
};