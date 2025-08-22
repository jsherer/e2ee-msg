const fs = require('fs');
const path = require('path');
const LZString = require('lz-string');

const distDir = path.join(__dirname, '..', 'dist');

// Read the bundle.js file
const bundleJs = fs.readFileSync(path.join(distDir, 'bundle.js'), 'utf8');

// Try different compression methods
const compressedBase64 = LZString.compressToBase64(bundleJs);
const compressedUTF16 = LZString.compressToUTF16(bundleJs);
const compressedEncodedURI = LZString.compressToEncodedURIComponent(bundleJs);

// Use the most compact for embedding
const compressedJs = compressedBase64; // We'll use Base64 for compatibility

// Create a bootstrap HTML that decompresses and runs the code
const bootstrapHtml = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>E2EE Local Messenger</title>
    <style>
        body, html {
            margin: 0;
            padding: 0;
            height: 100%;
        }
        #root {
            height: 100%;
        }
    </style>
</head>
<body>
    <div id="root"></div>
    <script>
    // LZ-String decompression (minified version)
    var LZString=function(){var r=String.fromCharCode,o="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=",n="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+-$",e={};function t(r,o){if(!e[r]){e[r]={};for(var n=0;n<r.length;n++)e[r][r.charAt(n)]=n}return e[r][o]}var i={decompressFromBase64:function(r){return null==r?"":""==r?null:i._decompress(r.length,32,function(n){return t(o,r.charAt(n))})},_decompress:function(o,n,e){var t,i,s,p,a,u,c,l=[],f=4,h=4,d=3,m="",v=[],g={val:e(0),position:n,index:1};for(t=0;t<3;t+=1)l[t]=t;for(s=0,a=Math.pow(2,2),u=1;u!=a;)p=g.val&g.position,g.position>>=1,0==g.position&&(g.position=n,g.val=e(g.index++)),s|=(p>0?1:0)*u,u<<=1;switch(s){case 0:for(s=0,a=Math.pow(2,8),u=1;u!=a;)p=g.val&g.position,g.position>>=1,0==g.position&&(g.position=n,g.val=e(g.index++)),s|=(p>0?1:0)*u,u<<=1;c=r(s);break;case 1:for(s=0,a=Math.pow(2,16),u=1;u!=a;)p=g.val&g.position,g.position>>=1,0==g.position&&(g.position=n,g.val=e(g.index++)),s|=(p>0?1:0)*u,u<<=1;c=r(s);break;case 2:return""}for(l[3]=c,i=c,v.push(c);;){if(g.index>o)return"";for(s=0,a=Math.pow(2,d),u=1;u!=a;)p=g.val&g.position,g.position>>=1,0==g.position&&(g.position=n,g.val=e(g.index++)),s|=(p>0?1:0)*u,u<<=1;switch(c=s){case 0:for(s=0,a=Math.pow(2,8),u=1;u!=a;)p=g.val&g.position,g.position>>=1,0==g.position&&(g.position=n,g.val=e(g.index++)),s|=(p>0?1:0)*u,u<<=1;l[h++]=r(s),c=h-1,f--;break;case 1:for(s=0,a=Math.pow(2,16),u=1;u!=a;)p=g.val&g.position,g.position>>=1,0==g.position&&(g.position=n,g.val=e(g.index++)),s|=(p>0?1:0)*u,u<<=1;l[h++]=r(s),c=h-1,f--;break;case 2:return v.join("")}if(0==f&&(f=Math.pow(2,d),d++),l[c])m=l[c];else{if(c!==h)return null;m=i+i.charAt(0)}v.push(m),l[h++]=i+m.charAt(0),i=m,0==--f&&(f=Math.pow(2,d),d++)}}};return i}();
    
    // Compressed JavaScript data
    var compressed = '${compressedJs}';
    
    // Decompress and execute
    var decompressed = LZString.decompressFromBase64(compressed);
    var script = document.createElement('script');
    script.textContent = decompressed;
    document.head.appendChild(script);
    </script>
</body>
</html>`;

// Write the compressed standalone HTML
fs.writeFileSync(path.join(distDir, 'standalone-compressed.html'), bootstrapHtml);

// Create data URI from the compressed version
const dataUri = `data:text/html;base64,${Buffer.from(bootstrapHtml).toString('base64')}`;
fs.writeFileSync(path.join(distDir, 'datauri-compressed.txt'), dataUri);

// Calculate sizes
const originalSize = bundleJs.length;
const compressedSize = compressedJs.length;
const bootstrapSize = bootstrapHtml.length;
const dataUriSize = dataUri.length;

console.log('📊 Compression Results:');
console.log(`   Original JS: ${(originalSize / 1024).toFixed(1)} KB`);
console.log(`   Compressed Base64: ${(compressedBase64.length / 1024).toFixed(1)} KB`);
console.log(`   Compressed UTF16: ${(compressedUTF16.length / 1024).toFixed(1)} KB`);
console.log(`   Compressed URI: ${(compressedEncodedURI.length / 1024).toFixed(1)} KB`);
console.log(`   Compression ratio: ${((1 - compressedSize / originalSize) * 100).toFixed(1)}%`);
console.log(`\n📦 Output Files:`);
console.log(`   standalone-compressed.html: ${(bootstrapSize / 1024).toFixed(1)} KB`);
console.log(`   datauri-compressed.txt: ${(dataUriSize / 1024).toFixed(1)} KB`);

// Check if it's under browser limits
if (dataUriSize < 65536) {
    console.log(`\n✅ Data URI is under 64KB browser limit!`);
} else {
    console.log(`\n⚠️  Data URI (${(dataUriSize / 1024).toFixed(1)} KB) still exceeds 64KB browser limit`);
}