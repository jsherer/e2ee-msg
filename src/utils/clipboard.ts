/**
 * Clipboard utility functions
 */

export const copyTextToClipboard = async (text: string): Promise<boolean> => {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch (error) {
    console.error('Failed to copy to clipboard:', error);
    return false;
  }
};

export const copyImageToClipboard = async (svgElement: SVGElement): Promise<boolean> => {
  try {
    const svgData = new XMLSerializer().serializeToString(svgElement);
    const canvas = document.createElement('canvas');
    const ctx = canvas.getContext('2d');
    const img = new Image();
    
    return new Promise((resolve) => {
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
              resolve(true);
            } catch {
              resolve(false);
            }
          } else {
            resolve(false);
          }
        }, 'image/png');
      };
      
      img.onerror = () => resolve(false);
      img.src = 'data:image/svg+xml;base64,' + btoa(svgData);
    });
  } catch (error) {
    console.error('Failed to copy image to clipboard:', error);
    return false;
  }
};