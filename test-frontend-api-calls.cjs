/**
 * Test Frontend API Calls - Simulate exactly what the frontend does
 */

const axios = require('axios');
const tough = require('tough-cookie');

const BASE_URL = 'https://4fc77172-459a-4da7-8c33-5014abb1b73e-00-dqhtnud4ismj.worf.replit.dev';

async function testFrontendAPIPattern() {
  console.log('🔍 TESTING FRONTEND API PATTERN');
  console.log('='.repeat(50));
  
  // Create cookie jar to simulate browser behavior
  const cookieJar = new tough.CookieJar();
  const client = axios.create({
    withCredentials: true,
    timeout: 10000,
    headers: {
      'Content-Type': 'application/json',
      'Accept': 'application/json'
    }
  });
  
  // Add interceptors to handle cookies like a browser
  client.interceptors.request.use(config => {
    const cookies = cookieJar.getCookiesSync(BASE_URL);
    if (cookies.length > 0) {
      config.headers.Cookie = cookies.map(cookie => `${cookie.key}=${cookie.value}`).join('; ');
    }
    return config;
  });
  
  client.interceptors.response.use(response => {
    const setCookieHeader = response.headers['set-cookie'];
    if (setCookieHeader) {
      setCookieHeader.forEach(cookie => {
        cookieJar.setCookieSync(cookie, BASE_URL);
      });
    }
    return response;
  });
  
  try {
    // Step 1: Establish session (simulating frontend)
    console.log('1️⃣ Establishing session...');
    const sessionResponse = await client.post(BASE_URL + '/api/establish-session', {
      email: 'gailm@macleodglba.com.au',
      phone: '+61424835189'
    });
    
    console.log('✅ Session established:', sessionResponse.data.message);
    
    // Check cookies
    const cookies = cookieJar.getCookiesSync(BASE_URL);
    console.log('🍪 Cookies stored:', cookies.length);
    
    // Step 2: Test API calls that were failing
    console.log('\n2️⃣ Testing API calls...');
    
    const endpoints = [
      '/api/user',
      '/api/user-status',
      '/api/platform-connections'
    ];
    
    for (const endpoint of endpoints) {
      try {
        const response = await client.get(BASE_URL + endpoint);
        console.log(`✅ ${endpoint}: SUCCESS (${response.status})`);
      } catch (error) {
        console.log(`❌ ${endpoint}: FAILED (${error.response?.status || 'ERROR'})`);
        console.log(`   Error: ${error.response?.data?.message || error.message}`);
      }
    }
    
  } catch (error) {
    console.error('❌ Test failed:', error.message);
  }
}

testFrontendAPIPattern();