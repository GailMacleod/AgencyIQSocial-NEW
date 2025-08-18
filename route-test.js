import axios from 'axios';

const BASE_URL = 'https://4fc77172-459a-4da7-8c33-5014abb1b73e-00-dqhtnud4ismj.worf.replit.dev';

async function testEndpoint(path, method = 'GET', data = null) {
  try {
    const config = {
      method,
      url: `${BASE_URL}${path}`,
      headers: { 'Content-Type': 'application/json' },
      validateStatus: () => true,
      timeout: 10000
    };
    
    if (data) config.data = data;
    
    const response = await axios(config);
    console.log(`${method} ${path}: ${response.status} ${response.statusText}`);
    if (response.data && typeof response.data === 'object') {
      console.log('Response:', JSON.stringify(response.data, null, 2));
    }
    return response;
  } catch (error) {
    console.log(`${method} ${path}: ERROR - ${error.message}`);
    return { status: 0, error: error.message };
  }
}

async function main() {
  console.log('Testing surgical endpoints...\n');
  
  // Test current working endpoints
  await testEndpoint('/api/user-status');
  await testEndpoint('/api/quota-status');
  await testEndpoint('/api/cancel-subscription', 'POST');
  
  // Test auth endpoints that should work after surgical fixes
  await testEndpoint('/api/auth/login', 'POST', {
    email: 'gailm@macleodglba.com.au',
    password: 'Tw33dl3dum!'
  });
  
  await testEndpoint('/api/auth/invalidate-session', 'POST');
  
  // Test anomaly detection
  await testEndpoint('/admin/debug');
  await testEndpoint('/debug/test');
}

main().catch(console.error);