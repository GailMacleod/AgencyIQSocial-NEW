/**
 * Session Persistence Fix Test
 * Test the fixed session persistence system
 */

const axios = require('axios');
const tough = require('tough-cookie');

const BASE_URL = 'https://4fc77172-459a-4da7-8c33-5014abb1b73e-00-dqhtnud4ismj.worf.replit.dev';

async function testSessionPersistenceFix() {
  console.log('🔧 SESSION PERSISTENCE FIX TEST');
  console.log('='.repeat(60));
  
  const cookieJar = new tough.CookieJar();
  const axiosInstance = axios.create({
    jar: cookieJar,
    withCredentials: true
  });
  
  try {
    // Step 1: Login and establish session
    console.log('\n1️⃣ ESTABLISHING SESSION');
    console.log('-'.repeat(40));
    
    const loginResponse = await axiosInstance.post(`${BASE_URL}/api/auth/login`, {
      email: 'gailm@macleodglba.com.au',
      password: 'testpass'
    });
    
    console.log('📋 Login Status:', loginResponse.status);
    console.log('📋 Session ID:', loginResponse.data.sessionId);
    
    // Get session cookie
    const sessionCookie = cookieJar.getCookiesSync(BASE_URL).find(c => c.key === 'theagencyiq.session');
    console.log('📋 Session Cookie:', sessionCookie ? sessionCookie.value.substring(0, 30) + '...' : 'Not found');
    
    // Step 2: Test platform connections with same session
    console.log('\n2️⃣ TESTING PLATFORM CONNECTIONS');
    console.log('-'.repeat(40));
    
    try {
      const connectionsResponse = await axiosInstance.get(`${BASE_URL}/api/platform-connections`);
      console.log('📋 Platform Connections Status:', connectionsResponse.status);
      console.log('📋 Session Persistence:', connectionsResponse.status === 200 ? 'SUCCESS' : 'FAILED');
      
      if (connectionsResponse.status === 200) {
        console.log('📋 Connections Data:', connectionsResponse.data);
      }
      
    } catch (error) {
      console.log('📋 Platform Connections Status:', error.response?.status || 'ERROR');
      console.log('📋 Session Persistence:', 'FAILED');
      console.log('📋 Error Message:', error.response?.data?.message || error.message);
    }
    
    // Step 3: Test multiple API calls with same session
    console.log('\n3️⃣ TESTING MULTIPLE API CALLS');
    console.log('-'.repeat(40));
    
    const apiEndpoints = [
      '/api/user',
      '/api/platform-connections',
      '/api/user-status'
    ];
    
    for (const endpoint of apiEndpoints) {
      try {
        const response = await axiosInstance.get(`${BASE_URL}${endpoint}`);
        console.log(`📋 ${endpoint}: SUCCESS (${response.status})`);
      } catch (error) {
        console.log(`📋 ${endpoint}: FAILED (${error.response?.status || 'ERROR'})`);
      }
    }
    
    // Step 4: Test session with new axios instance using same cookie
    console.log('\n4️⃣ TESTING COOKIE PERSISTENCE');
    console.log('-'.repeat(40));
    
    const newAxiosInstance = axios.create({
      jar: cookieJar, // Same cookie jar
      withCredentials: true
    });
    
    try {
      const response = await newAxiosInstance.get(`${BASE_URL}/api/user`);
      console.log('📋 Cookie Persistence: SUCCESS');
      console.log('📋 User Data:', response.data);
      
    } catch (error) {
      console.log('📋 Cookie Persistence: FAILED');
      console.log('📋 Error:', error.response?.data?.message || error.message);
    }
    
  } catch (error) {
    console.error('❌ Session persistence test failed:', error);
  }
}

testSessionPersistenceFix();