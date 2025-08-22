const fs = require('fs');
const path = require('path');
const zlib = require('zlib');

// First, create the standalone HTML by combining index.html and bundle.js
const distDir = path.join(__dirname, '..', 'dist');
const indexHtml = fs.readFileSync(path.join(distDir, 'index.html'), 'utf8');
const bundleJs = fs.readFileSync(path.join(distDir, 'bundle.js'), 'utf8');

// Replace the script tag with inline JavaScript
const standaloneHtml = indexHtml.replace(
    '<script src="bundle.js"></script>',
    `<script>${bundleJs}</script>`
);

// Write standalone HTML
fs.writeFileSync(path.join(distDir, 'standalone.html'), standaloneHtml);

// Try different compression methods for data URI
const htmlContent = standaloneHtml;

// Aggressive minification first
const minifiedHtml = htmlContent
    .replace(/\n/g, '')           // Remove newlines
    .replace(/\s+/g, ' ')         // Collapse whitespace
    .replace(/> </g, '><')        // Remove spaces between tags
    .replace(/<!--.*?-->/g, '')   // Remove comments
    .replace(/;\s*}/g, '}')       // Remove trailing semicolons before }
    .replace(/{\s+/g, '{')        // Remove space after {
    .replace(/}\s+/g, '}')        // Remove space after }
    .replace(/:\s+/g, ':')        // Remove space after :
    .replace(/,\s+/g, ',')        // Remove space after ,
    .trim();

// Method 1: Regular base64 (no compression)
const base64 = Buffer.from(htmlContent).toString('base64');
const dataUri = `data:text/html;base64,${base64}`;

// Method 2: URL-safe characters (percent encoding)
const percentEncoded = encodeURIComponent(htmlContent);
const dataUriPercent = `data:text/html;charset=utf-8,${percentEncoded}`;

// Method 3: Minified + base64
const minifiedBase64 = Buffer.from(minifiedHtml).toString('base64');
const dataUriMinified = `data:text/html;base64,${minifiedBase64}`;

// Method 4: Minified + percent encoding (often smallest)
const percentEncodedMin = encodeURIComponent(minifiedHtml);
const dataUriPercentMin = `data:text/html;charset=utf-8,${percentEncodedMin}`;

// Compare all versions to find the smallest
const versions = [
    { uri: dataUri, type: 'base64' },
    { uri: dataUriPercent, type: 'percent-encoded' },
    { uri: dataUriMinified, type: 'minified+base64' },
    { uri: dataUriPercentMin, type: 'minified+percent' }
];

// Find the smallest
let smallest = versions[0];
for (const v of versions) {
    if (v.uri.length < smallest.uri.length) {
        smallest = v;
    }
}

// Write the smallest version
fs.writeFileSync(path.join(distDir, 'datauri.txt'), smallest.uri);

console.log(`✅ Created files:`);
console.log(`   - dist/standalone.html (${(standaloneHtml.length / 1024).toFixed(1)} KB)`);
console.log(`\n📊 Data URI comparison:`);
console.log(`   - Base64: ${(dataUri.length / 1024).toFixed(1)} KB`);
console.log(`   - Percent-encoded: ${(dataUriPercent.length / 1024).toFixed(1)} KB`);
console.log(`   - Minified+Base64: ${(dataUriMinified.length / 1024).toFixed(1)} KB`);
console.log(`   - Minified+Percent: ${(dataUriPercentMin.length / 1024).toFixed(1)} KB`);
console.log(`\n✨ Using ${smallest.type}: ${(smallest.uri.length / 1024).toFixed(1)} KB (saved to datauri.txt)`);