const fs = require('fs');
const path = require('path');

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

// Read the standalone HTML file for data URI conversion
const htmlContent = standaloneHtml;

// Convert to base64
const base64 = Buffer.from(htmlContent).toString('base64');

// Create data URI
const dataUri = `data:text/html;base64,${base64}`;

// Write to file
fs.writeFileSync(path.join(distDir, 'datauri.txt'), dataUri);

// Also create a small HTML file that redirects to the data URI for testing
const redirectHtml = `<!DOCTYPE html>
<html>
<head>
    <title>E2EE Messenger Launcher</title>
</head>
<body>
    <h3>E2EE Local Messenger - Data URI Version</h3>
    <p>Click the link below to launch the app from a data URI:</p>
    <a href="${dataUri}">Launch E2EE Messenger</a>
    <br><br>
    <details>
        <summary>Data URI (click to show)</summary>
        <textarea readonly style="width: 100%; height: 200px; font-family: monospace; font-size: 10px;">${dataUri}</textarea>
    </details>
    <br>
    <p style="color: #666; font-size: 12px;">
        Note: The data URI is ${(dataUri.length / 1024).toFixed(1)} KB (base64 encoded).<br>
        You can bookmark the data URI link or save it as a file.
    </p>
</body>
</html>`;

fs.writeFileSync(path.join(distDir, 'launcher.html'), redirectHtml);

console.log(`✅ Created data URI files:`);
console.log(`   - dist/standalone.html (${(standaloneHtml.length / 1024).toFixed(1)} KB) - single HTML with embedded JS`);
console.log(`   - dist/datauri.txt (${(dataUri.length / 1024).toFixed(1)} KB) - base64 data URI`);
console.log(`   - dist/launcher.html - test page with clickable link`);
console.log(`\n📋 The data URI has been saved to dist/datauri.txt`);
console.log(`🚀 Open dist/launcher.html in a browser to test the data URI`);
console.log(`\n💡 You can also open dist/standalone.html directly as a single file app`);