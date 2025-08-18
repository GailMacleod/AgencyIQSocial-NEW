/**
 * Final Session Fix Test
 * Test the complete session fix with proper cookie handling
 */

const axios = require('axios');

const BASE_URL = 'https://4fc77172-459a-4da7-8c33-5014abb1b73e-00-dqhtnud4ismj.worf.replit.dev';

async function testFinalSessionFix() {
  console.log('🔧 FINAL SESSION FIX TEST');
  console.log('='.repeat(60));
  
  // Create axios instance with proper cookie handling
  const client = axios.create({
    baseURL: BASE_URL,
    withCredentials: true,
    timeout: 10000,
    headers: {
      'Content-Type': 'application/json',
      'Accept': 'application/json'
    }
  });

  try {
    // Step 1: Login 
    console.log('\n1️⃣ TESTING LOGIN');
    console.log('-'.repeat(40));
    
    const loginResponse = await client.post('/api/auth/login', {
      email: 'gailm@macleodglba.com.au',
      password: 'testpass'
    });
    
    console.log('📋 Login Status:', loginResponse.status);
    console.log('📋 Login Response:', loginResponse.data);
    
    // Extract session info from response
    const sessionCookie = loginResponse.headers['set-cookie']?.find(cookie => 
      cookie.includes('theagencyiq.session')
    );
    console.log('📋 Session Cookie Set:', sessionCookie ? 'YES' : 'NO');
    
    // Wait a moment for session to be saved
    await new Promise(resolve => setTimeout(resolve, 1000));
    
    // Step 2: Test API calls immediately after login
    console.log('\n2️⃣ TESTING API CALLS');
    console.log('-'.repeat(40));
    
    try {
      const userResponse = await client.get('/api/user');
      console.log('📋 User API Status:', userResponse.status);
      console.log('📋 User Data:', userResponse.data);
      console.log('📋 Session Persistence: SUCCESS');
      
    } catch (error) {
      console.log('📋 User API Status:', error.response?.status || 'ERROR');
      console.log('📋 User API Error:', error.response?.data?.message || error.message);
      console.log('📋 Session Persistence: FAILED');
    }
    
    // Step 3: Test platform connections
    console.log('\n3️⃣ TESTING PLATFORM CONNECTIONS');
    console.log('-'.repeat(40));
    
    try {
      const connectionsResponse = await client.get('/api/platform-connections');
      console.log('📋 Platform Connections Status:', connectionsResponse.status);
      console.log('📋 Platform Connections Data:', connectionsResponse.data);
      console.log('📋 Platform API: SUCCESS');
      
    } catch (error) {
      console.log('📋 Platform Connections Status:', error.response?.status || 'ERROR');
      console.log('📋 Platform Connections Error:', error.response?.data?.message || error.message);
      console.log('📋 Platform API: FAILED');
    }
    
    // Step 4: Test multiple endpoints
    console.log('\n4️⃣ TESTING MULTIPLE ENDPOINTS');
    console.log('-'.repeat(40));
    
    const endpoints = [
      '/api/user-status',
      '/api/platform-connections',
      '/api/user'
    ];
    
    for (const endpoint of endpoints) {
      try {
        const response = await client.get(endpoint);
        console.log(`📋 ${endpoint}: SUCCESS (${response.status})`);
      } catch (error) {
        console.log(`📋 ${endpoint}: FAILED (${error.response?.status || 'ERROR'})`);
      }
    }
    
    console.log('\n🎯 SESSION FIX TEST COMPLETE');
    console.log('='.repeat(60));
    
  } catch (error) {
    console.error('❌ Session fix test failed:', error.message);
  }
}

testFinalSessionFix();