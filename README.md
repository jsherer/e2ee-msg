# E2EE MSG

Serverless end-to-end encrypted messaging that runs entirely in your browser. Share public keys, exchange encrypted messages, no server required.

## Features

- 🔐 **E2E Encryption** using TweetNaCl (Curve25519)
- 🔑 **Master password** protects your private keys  
- 📝 **BIP39 words** - Share public keys as 24 memorable words
- 💾 **URL persistence** - Encrypted keys in URL hash
- 📦 **Single file** - Distribute as standalone HTML or data URI

## Usage

1. Open `dist/index.html` in a browser
2. Enter a master password
3. Share your public key (base36 or words format)
4. Paste recipient's public key to encrypt messages
5. Paste sender's public key to decrypt messages

## Building

```bash
npm install
npm run build              # Standard build
npm run build:standalone   # Single HTML file + data URI
npm run build:compressed   # LZ-compressed version (smaller)
```

### Output Files
- `dist/bundle.js` - Compiled JavaScript (205KB minified)
- `dist/standalone.html` - Single HTML file with embedded JS (206KB)
- `dist/ultra.html` - LZ-compressed single file (135KB, 35% smaller)
- `dist/datauri.txt` - Base64 data URI (274KB - too large for browsers)
- `dist/datauri-ultra.txt` - Compressed data URI (139KB - still too large)


## Key Formats

**Base36**: `3jk2l 9xm4p q8r7s...` (compact)  
**BIP39**: `abandon ability able...` (24 words, speakable)

## Tech Stack

- **Crypto**: TweetNaCl (Curve25519, XSalsa20, Poly1305)
- **Frontend**: React + TypeScript  
- **Build**: esbuild
- **Size**: ~206KB standalone

## License

See [LICENSE](LICENSE)

## Disclaimer

Built with TweetNaCl.js and React. Use at your own risk. This is experimental software.
