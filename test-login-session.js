/**
 * Test Login Session and OAuth Prerequisites
 */

import axios from 'axios';
const BASE_URL = 'https://4fc77172-459a-4da7-8c33-5014abb1b73e-00-dqhtnud4ismj.worf.replit.dev';

async function testLoginSession() {
  console.log('🔐 Testing login session establishment...\n');
  
  try {
    // Step 1: Test existing session first
    console.log('1️⃣ Testing existing session...');
    try {
      const existingSession = await axios.post(`${BASE_URL}/api/establish-session`, {
        userId: 2,
        email: 'gailm@macleodglba.com.au'
      }, {
        withCredentials: true
      });
      
      if (existingSession.data.success) {
        console.log('✅ Session established:', existingSession.data);
        
        // Test session cookie
        const sessionCookie = existingSession.headers['set-cookie']?.[0]?.split(';')[0];
        console.log('🍪 Session cookie:', sessionCookie);
        
        // Test session validation
        const userCheck = await axios.get(`${BASE_URL}/api/user`, {
          headers: {
            'Cookie': sessionCookie
          }
        });
        
        console.log('✅ Session valid:', userCheck.data);
        return { sessionCookie, user: userCheck.data };
      }
    } catch (error) {
      console.log('ℹ️  Session establishment failed, trying login...', error.response?.data);
    }
    
    // Step 2: Test login endpoint as fallback
    console.log('2️⃣ Testing login endpoint...');
    const loginResponse = await axios.post(`${BASE_URL}/api/auth/login`, {
      phone: '+61424835189',
      password: 'password123'
    }, {
      withCredentials: true
    });
    
    console.log('✅ Login successful:', loginResponse.data);
    
    // Extract session cookie
    const sessionCookie = loginResponse.headers['set-cookie']?.[0]?.split(';')[0];
    console.log('🍪 Session cookie:', sessionCookie);
    
    // Step 2: Test session persistence
    console.log('\n2️⃣ Testing session persistence...');
    const userResponse = await axios.get(`${BASE_URL}/api/user`, {
      headers: {
        'Cookie': sessionCookie
      }
    });
    
    console.log('✅ Session persisted:', userResponse.data);
    
    // Step 3: Test platform connections endpoint
    console.log('\n3️⃣ Testing platform connections with session...');
    const connectionsResponse = await axios.get(`${BASE_URL}/api/platform-connections`, {
      headers: {
        'Cookie': sessionCookie
      }
    });
    
    console.log('✅ Platform connections accessible:', connectionsResponse.data);
    
    console.log('\n🎉 Session authentication working correctly!');
    console.log('🔑 User ID:', loginResponse.data.user.id);
    console.log('📧 Email:', loginResponse.data.user.email);
    console.log('🔄 Session ID:', loginResponse.data.sessionId);
    
  } catch (error) {
    console.error('❌ Test failed:', error.response?.data || error.message);
    if (error.response?.status === 401) {
      console.log('🚨 Authentication failed - check credentials or session handling');
    }
  }
}

testLoginSession();