/**
 * Cookie Verification Test - Debug browser cookie transmission
 */

const axios = require('axios');

const BASE_URL = 'https://4fc77172-459a-4da7-8c33-5014abb1b73e-00-dqhtnud4ismj.worf.replit.dev';

async function testCookieVerification() {
  console.log('🔍 TESTING COOKIE VERIFICATION');
  console.log('='.repeat(50));
  
  try {
    // Create axios instance with withCredentials
    const client = axios.create({
      baseURL: BASE_URL,
      withCredentials: true,
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
      }
    });
    
    // Step 1: Establish session
    console.log('1️⃣ Establishing session with withCredentials: true...');
    
    const sessionResponse = await client.post('/api/establish-session', {
      email: 'gailm@macleodglba.com.au',
      phone: '+61424835189'
    });
    
    console.log('✅ Session established:', sessionResponse.data.message);
    console.log('📋 Response headers:', Object.keys(sessionResponse.headers));
    
    // Log cookies from response
    const setCookieHeader = sessionResponse.headers['set-cookie'];
    if (setCookieHeader) {
      console.log('🍪 Set-Cookie headers:', setCookieHeader);
    } else {
      console.log('❌ No Set-Cookie headers found');
    }
    
    // Step 2: Test automatic cookie transmission
    console.log('\n2️⃣ Testing automatic cookie transmission...');
    
    try {
      const userResponse = await client.get('/api/user');
      console.log('✅ /api/user: SUCCESS (', userResponse.status, ')');
      console.log('📋 User data:', userResponse.data);
    } catch (error) {
      console.log('❌ /api/user: FAILED (', error.response?.status, ')');
      console.log('📋 Error:', error.response?.data?.message);
    }
    
    try {
      const statusResponse = await client.get('/api/user-status');
      console.log('✅ /api/user-status: SUCCESS (', statusResponse.status, ')');
      console.log('📋 Status data:', statusResponse.data);
    } catch (error) {
      console.log('❌ /api/user-status: FAILED (', error.response?.status, ')');
      console.log('📋 Error:', error.response?.data?.message);
    }
    
  } catch (error) {
    console.error('❌ Test failed:', error.message);
  }
}

testCookieVerification();