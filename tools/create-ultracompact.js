const fs = require('fs');
const path = require('path');
const LZString = require('lz-string');

const distDir = path.join(__dirname, '..', 'dist');

// Read the bundle.js file  
const bundleJs = fs.readFileSync(path.join(distDir, 'bundle.js'), 'utf8');

// Compress using EncodedURIComponent (URI-safe)
const compressed = LZString.compressToEncodedURIComponent(bundleJs);

// Create ultra-minimal bootstrap
const html = `<meta charset=utf8><style>body,html{margin:0;height:100%}#root{height:100%}</style><div id=root></div><script>
eval(function(){var r=String.fromCharCode,o="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+-$",e={},t=function(r,t){if(!e[r]){e[r]={};for(var n=0;n<r.length;n++)e[r][r.charAt(n)]=n}return e[r][t]};return{d:function(e){if(null==e)return"";if(""==e)return null;return this.x(e.length,32,function(r){return t(o,e.charAt(r))})},x:function(o,e,t){var n,i,a,s,u,c,f,l=[],p=4,h=4,d=3,g="",m=[],v={val:t(0),position:e,index:1};for(n=0;n<3;n+=1)l[n]=n;for(a=0,u=Math.pow(2,2),c=1;c!=u;)s=v.val&v.position,v.position>>=1,0==v.position&&(v.position=e,v.val=t(v.index++)),a|=(s>0?1:0)*c,c<<=1;switch(a){case 0:for(a=0,u=Math.pow(2,8),c=1;c!=u;)s=v.val&v.position,v.position>>=1,0==v.position&&(v.position=e,v.val=t(v.index++)),a|=(s>0?1:0)*c,c<<=1;f=r(a);break;case 1:for(a=0,u=Math.pow(2,16),c=1;c!=u;)s=v.val&v.position,v.position>>=1,0==v.position&&(v.position=e,v.val=t(v.index++)),a|=(s>0?1:0)*c,c<<=1;f=r(a);break;case 2:return""}for(l[3]=f,i=f,m.push(f);;){if(v.index>o)return"";for(a=0,u=Math.pow(2,d),c=1;c!=u;)s=v.val&v.position,v.position>>=1,0==v.position&&(v.position=e,v.val=t(v.index++)),a|=(s>0?1:0)*c,c<<=1;switch(f=a){case 0:for(a=0,u=Math.pow(2,8),c=1;c!=u;)s=v.val&v.position,v.position>>=1,0==v.position&&(v.position=e,v.val=t(v.index++)),a|=(s>0?1:0)*c,c<<=1;l[h++]=r(a),f=h-1,p--;break;case 1:for(a=0,u=Math.pow(2,16),c=1;c!=u;)s=v.val&v.position,v.position>>=1,0==v.position&&(v.position=e,v.val=t(v.index++)),a|=(s>0?1:0)*c,c<<=1;l[h++]=r(a),f=h-1,p--;break;case 2:return m.join("")}if(0==p&&(p=Math.pow(2,d),d++),l[f])g=l[f];else{if(f!==h)return null;g=i+i.charAt(0)}m.push(g),l[h++]=i+g.charAt(0),i=g,0==--p&&(p=Math.pow(2,d),d++)}}}}().d('${compressed}'))
</script>`;

// Write standalone
fs.writeFileSync(path.join(distDir, 'ultra.html'), html);

// Create data URI with percent encoding (no base64)
const dataUri = `data:text/html,${encodeURIComponent(html)}`;
fs.writeFileSync(path.join(distDir, 'datauri-ultra.txt'), dataUri);

// Stats
console.log('🚀 Ultra-Compact Build:');
console.log(`   Original: ${(bundleJs.length / 1024).toFixed(1)} KB`);
console.log(`   Compressed: ${(compressed.length / 1024).toFixed(1)} KB`);
console.log(`   HTML: ${(html.length / 1024).toFixed(1)} KB`);
console.log(`   Data URI: ${(dataUri.length / 1024).toFixed(1)} KB`);

if (dataUri.length < 65536) {
    console.log(`\n✅ SUCCESS! Data URI is under 64KB!`);
} else if (dataUri.length < 131072) {
    console.log(`\n⚠️  ${(dataUri.length / 1024).toFixed(1)} KB - Works in Chrome/Firefox`);
} else {
    console.log(`\n❌ ${(dataUri.length / 1024).toFixed(1)} KB - Too large`);
}