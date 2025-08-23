import { copyTextToClipboard, copyImageToClipboard } from '../../utils/clipboard';

describe('clipboard utilities', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('copyTextToClipboard', () => {
    it('should copy text to clipboard', async () => {
      const text = 'test text';
      const result = await copyTextToClipboard(text);
      
      expect(navigator.clipboard.writeText).toHaveBeenCalledWith(text);
      expect(result).toBe(true);
    });

    it('should return false on error', async () => {
      (navigator.clipboard.writeText as jest.Mock).mockRejectedValueOnce(new Error('Failed'));
      
      const result = await copyTextToClipboard('test');
      
      expect(result).toBe(false);
    });
  });

  describe('copyImageToClipboard', () => {
    it('should return false when Image fails to load', async () => {
      const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
      
      // Mock Image to immediately error
      const mockImage = {
        onerror: null as any,
        onload: null as any,
        set src(value: string) {
          // Trigger error when src is set
          setTimeout(() => {
            if (this.onerror) this.onerror();
          }, 0);
        }
      };
      
      global.Image = jest.fn(() => mockImage) as any;
      
      const result = await copyImageToClipboard(svg);
      
      expect(result).toBe(false);
    });
  });
});