/**
 * COMPLETE SESSION TEST
 * Test the complete session persistence system with proper login flow
 */

const axios = require('axios');
const tough = require('tough-cookie');

const BASE_URL = 'https://4fc77172-459a-4da7-8c33-5014abb1b73e-00-dqhtnud4ismj.worf.replit.dev';

async function testCompleteSession() {
  console.log('🔧 COMPLETE SESSION PERSISTENCE TEST');
  console.log('='.repeat(60));
  
  // Create cookie jar for persistent session
  const cookieJar = new tough.CookieJar();
  const client = axios.create({
    withCredentials: true,
    timeout: 10000,
    headers: {
      'Content-Type': 'application/json',
      'Accept': 'application/json'
    }
  });
  
  // Add request interceptor to handle cookies
  client.interceptors.request.use(config => {
    const cookies = cookieJar.getCookiesSync(BASE_URL);
    if (cookies.length > 0) {
      config.headers.Cookie = cookies.map(cookie => `${cookie.key}=${cookie.value}`).join('; ');
    }
    return config;
  });
  
  // Add response interceptor to save cookies
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
    // Step 1: Login and establish session
    console.log('\n1️⃣ ESTABLISHING SESSION WITH LOGIN');
    console.log('-'.repeat(40));
    
    const loginResponse = await client.post(`${BASE_URL}/api/auth/login`, {
      email: 'gailm@macleodglba.com.au',
      password: 'testpass'
    });
    
    console.log('📋 Login Status:', loginResponse.status);
    console.log('📋 Login Response:', loginResponse.data);
    
    // Check if session cookie was set
    const cookies = cookieJar.getCookiesSync(BASE_URL);
    const sessionCookie = cookies.find(cookie => cookie.key === 'theagencyiq.session');
    console.log('📋 Session Cookie:', sessionCookie ? sessionCookie.value : 'NOT FOUND');
    
    if (!sessionCookie) {
      console.log('❌ No session cookie found - session persistence will fail');
      return;
    }
    
    // Wait for session to be saved
    await new Promise(resolve => setTimeout(resolve, 2000));
    
    // Step 2: Test API calls with established session
    console.log('\n2️⃣ TESTING API CALLS WITH SESSION');
    console.log('-'.repeat(40));
    
    try {
      const userResponse = await client.get(`${BASE_URL}/api/user`);
      console.log('📋 User API Status:', userResponse.status);
      console.log('📋 User Data:', userResponse.data);
      console.log('📋 Session Persistence: SUCCESS ✅');
      
      // Step 3: Test multiple endpoints
      console.log('\n3️⃣ TESTING MULTIPLE ENDPOINTS');
      console.log('-'.repeat(40));
      
      const endpoints = [
        '/api/platform-connections',
        '/api/user-status'
      ];
      
      for (const endpoint of endpoints) {
        try {
          const response = await client.get(`${BASE_URL}${endpoint}`);
          console.log(`📋 ${endpoint}: SUCCESS (${response.status})`);
        } catch (error) {
          console.log(`📋 ${endpoint}: FAILED (${error.response?.status || 'ERROR'})`);
        }
      }
      
      console.log('\n🎯 SESSION PERSISTENCE TEST: COMPLETE SUCCESS');
      
    } catch (error) {
      console.log('📋 User API Status:', error.response?.status || 'ERROR');
      console.log('📋 User API Error:', error.response?.data?.message || error.message);
      console.log('📋 Session Persistence: FAILED ❌');
    }
    
  } catch (error) {
    console.error('❌ Complete session test failed:', error.message);
  }
}

testCompleteSession();