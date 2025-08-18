/**
 * Test Session Establishment for gailm@macleodglba.com.au
 * Tests the complete session flow to fix authentication issues
 */

import { exec } from 'child_process';

async function testSessionEstablishment() {
  console.log('🔍 Testing session establishment for gailm@macleodglba.com.au...');
  
  try {
    // Step 1: Test /api/establish-session
    console.log('\n1. Testing /api/establish-session...');
    const establishResponse = await fetch('http://localhost:3000/api/establish-session', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        email: 'gailm@macleodglba.com.au',
        phone: '+61424835189'
      }),
      credentials: 'include'
    });
    
    const establishData = await establishResponse.json();
    console.log('Session establishment response:', establishData);
    
    // Extract session cookie
    const setCookieHeader = establishResponse.headers.get('set-cookie');
    console.log('Session cookie:', setCookieHeader);
    
    // Step 2: Test /api/user with session cookie
    console.log('\n2. Testing /api/user with session...');
    const userResponse = await fetch('http://localhost:3000/api/user', {
      method: 'GET',
      headers: {
        'Cookie': setCookieHeader || '',
      },
      credentials: 'include'
    });
    
    const userData = await userResponse.json();
    console.log('User API response:', userData);
    
    // Step 3: Test /api/user-status with session cookie
    console.log('\n3. Testing /api/user-status with session...');
    const statusResponse = await fetch('http://localhost:3000/api/user-status', {
      method: 'GET',
      headers: {
        'Cookie': setCookieHeader || '',
      },
      credentials: 'include'
    });
    
    const statusData = await statusResponse.json();
    console.log('User status response:', statusData);
    
    // Final report
    console.log('\n📊 SESSION TEST RESULTS:');
    console.log('Session establishment:', establishResponse.ok ? '✅ Success' : '❌ Failed');
    console.log('User API:', userResponse.ok ? '✅ Success' : '❌ Failed');
    console.log('User status:', statusResponse.ok ? '✅ Success' : '❌ Failed');
    
    if (!userResponse.ok) {
      console.log('\n🔍 User API Error Details:');
      console.log('Status:', userResponse.status);
      console.log('Response:', userData);
    }
    
  } catch (error) {
    console.error('Test failed:', error);
  }
}

// Run the test
testSessionEstablishment();