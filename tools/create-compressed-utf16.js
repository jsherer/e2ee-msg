const fs = require('fs');
const path = require('path');
const LZString = require('lz-string');

const distDir = path.join(__dirname, '..', 'dist');

// Read the bundle.js file
const bundleJs = fs.readFileSync(path.join(distDir, 'bundle.js'), 'utf8');

// Compress using UTF16 (most compact)
const compressedUTF16 = LZString.compressToUTF16(bundleJs);

// Escape the UTF16 string for embedding in JavaScript
const escapedCompressed = compressedUTF16
    .replace(/\\/g, '\\\\')
    .replace(/'/g, "\\'")
    .replace(/\n/g, '\\n')
    .replace(/\r/g, '\\r')
    .replace(/\u2028/g, '\\u2028')
    .replace(/\u2029/g, '\\u2029');

// Create a minimal bootstrap HTML
const bootstrapHtml = `<!DOCTYPE html>
<html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>E2EE Local Messenger</title><style>body,html{margin:0;padding:0;height:100%}#root{height:100%}</style></head><body><div id="root"></div><script>
// LZ-String UTF16 decompressor (minified)
var LZString=function(){var r=String.fromCharCode,f={decompressFromUTF16:function(o){return null==o?"":""==o?null:f._decompress(o.length,16384,function(r){return o.charCodeAt(r)})},_decompress:function(o,n,e){var t,i,s,p,a,u,c,l=[],f=4,h=4,d=3,m="",v=[],g={val:e(0),position:n,index:1};for(t=0;t<3;t+=1)l[t]=t;for(s=0,a=Math.pow(2,2),u=1;u!=a;)p=g.val&g.position,g.position>>=1,0==g.position&&(g.position=n,g.val=e(g.index++)),s|=(p>0?1:0)*u,u<<=1;switch(s){case 0:for(s=0,a=Math.pow(2,8),u=1;u!=a;)p=g.val&g.position,g.position>>=1,0==g.position&&(g.position=n,g.val=e(g.index++)),s|=(p>0?1:0)*u,u<<=1;c=r(s);break;case 1:for(s=0,a=Math.pow(2,16),u=1;u!=a;)p=g.val&g.position,g.position>>=1,0==g.position&&(g.position=n,g.val=e(g.index++)),s|=(p>0?1:0)*u,u<<=1;c=r(s);break;case 2:return""}for(l[3]=c,i=c,v.push(c);;){if(g.index>o)return"";for(s=0,a=Math.pow(2,d),u=1;u!=a;)p=g.val&g.position,g.position>>=1,0==g.position&&(g.position=n,g.val=e(g.index++)),s|=(p>0?1:0)*u,u<<=1;switch(c=s){case 0:for(s=0,a=Math.pow(2,8),u=1;u!=a;)p=g.val&g.position,g.position>>=1,0==g.position&&(g.position=n,g.val=e(g.index++)),s|=(p>0?1:0)*u,u<<=1;l[h++]=r(s),c=h-1,f--;break;case 1:for(s=0,a=Math.pow(2,16),u=1;u!=a;)p=g.val&g.position,g.position>>=1,0==g.position&&(g.position=n,g.val=e(g.index++)),s|=(p>0?1:0)*u,u<<=1;l[h++]=r(s),c=h-1,f--;break;case 2:return v.join("")}if(0==f&&(f=Math.pow(2,d),d++),l[c])m=l[c];else{if(c!==h)return null;m=i+i.charAt(0)}v.push(m),l[h++]=i+m.charAt(0),i=m,0==--f&&(f=Math.pow(2,d),d++)}}};return f}();
// Decompress and run
eval(LZString.decompressFromUTF16('${escapedCompressed}'));
</script></body></html>`;

// Write files
fs.writeFileSync(path.join(distDir, 'standalone-utf16.html'), bootstrapHtml);

// Create data URI
const dataUri = `data:text/html;base64,${Buffer.from(bootstrapHtml).toString('base64')}`;
fs.writeFileSync(path.join(distDir, 'datauri-utf16.txt'), dataUri);

// Also try percent encoding
const dataUriPercent = `data:text/html;charset=utf-8,${encodeURIComponent(bootstrapHtml)}`;

// Calculate sizes
console.log('📊 UTF16 Compression Results:');
console.log(`   Original JS: ${(bundleJs.length / 1024).toFixed(1)} KB`);
console.log(`   Compressed UTF16: ${(compressedUTF16.length / 1024).toFixed(1)} KB`);
console.log(`   Compression ratio: ${((1 - compressedUTF16.length / bundleJs.length) * 100).toFixed(1)}%`);
console.log(`\n📦 Output Files:`);
console.log(`   standalone-utf16.html: ${(bootstrapHtml.length / 1024).toFixed(1)} KB`);
console.log(`   datauri-utf16.txt (base64): ${(dataUri.length / 1024).toFixed(1)} KB`);
console.log(`   datauri-utf16 (percent): ${(dataUriPercent.length / 1024).toFixed(1)} KB`);

// Save the smaller one
if (dataUriPercent.length < dataUri.length) {
    fs.writeFileSync(path.join(distDir, 'datauri-utf16.txt'), dataUriPercent);
    console.log(`\n✨ Using percent-encoded version: ${(dataUriPercent.length / 1024).toFixed(1)} KB`);
} else {
    console.log(`\n✨ Using base64 version: ${(dataUri.length / 1024).toFixed(1)} KB`);
}

// Check if it's under browser limits
const finalSize = Math.min(dataUri.length, dataUriPercent.length);
if (finalSize < 65536) {
    console.log(`✅ Data URI is under 64KB browser limit!`);
} else if (finalSize < 131072) {
    console.log(`⚠️  Data URI (${(finalSize / 1024).toFixed(1)} KB) is under 128KB (works in some browsers)`);
} else {
    console.log(`❌ Data URI (${(finalSize / 1024).toFixed(1)} KB) exceeds most browser limits`);
}