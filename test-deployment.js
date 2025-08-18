/**
 * Quick deployment test - verify app is accessible
 */
const https = require('https');

async function testDeployment() {
  const url = 'https://4fc77172-459a-4da7-8c33-5014abb1b73e-00-dqhtnud4ismj.worf.replit.dev/';
  
  return new Promise((resolve, reject) => {
    const req = https.get(url, (res) => {
      let data = '';
      
      res.on('data', (chunk) => {
        data += chunk;
      });
      
      res.on('end', () => {
        console.log('✅ Deployment Status:', res.statusCode);
        console.log('✅ Content-Type:', res.headers['content-type']);
        console.log('✅ Response Size:', data.length, 'bytes');
        
        if (data.includes('<div id="root">') && data.includes('React')) {
          console.log('✅ HTML structure correct - React app ready');
        } else if (data.includes('<div id="root">')) {
          console.log('✅ HTML structure correct - Root div found');
        }
        
        if (data.includes('Meta Pixel')) {
          console.log('✅ Meta Pixel loaded');
        }
        
        resolve({
          status: res.statusCode,
          size: data.length,
          hasRoot: data.includes('<div id="root">'),
          hasReact: data.includes('React')
        });
      });
    });
    
    req.on('error', (err) => {
      console.error('❌ Request failed:', err.message);
      reject(err);
    });
    
    req.setTimeout(5000, () => {
      console.error('❌ Request timed out');
      req.destroy();
      reject(new Error('Timeout'));
    });
  });
}

testDeployment()
  .then(result => {
    console.log('\n🎉 DEPLOYMENT TEST RESULTS:');
    console.log('Status Code:', result.status);
    console.log('Response Size:', result.size, 'bytes');
    console.log('Has Root Element:', result.hasRoot);
    console.log('React Ready:', result.hasReact);
    
    if (result.status === 200 && result.hasRoot) {
      console.log('\n✅ DEPLOYMENT IS WORKING CORRECTLY');
    } else {
      console.log('\n❌ Deployment has issues');
    }
  })
  .catch(err => {
    console.error('❌ Test failed:', err.message);
  });