/**
 * Test Session Establishment and Platform Connections
 * Tests the full authentication flow and platform connection retrieval
 */

import axios from 'axios';

const BASE_URL = 'https://4fc77172-459a-4da7-8c33-5014abb1b73e-00-dqhtnud4ismj.worf.replit.dev';

async function testSessionAndConnections() {
  console.log('🔧 Testing Session Establishment and Platform Connections...\n');
  
  try {
    // Step 1: Establish session
    console.log('1. Establishing session...');
    const sessionResponse = await axios.post(`${BASE_URL}/api/establish-session`, {
      email: 'gailm@macleodglba.com.au',
      phone: '+61424835189'
    }, {
      withCredentials: true,
      headers: {
        'Content-Type': 'application/json'
      }
    });
    
    console.log('✅ Session established:', sessionResponse.data);
    
    // Extract cookies for subsequent requests
    const cookies = sessionResponse.headers['set-cookie'];
    const cookieString = cookies ? cookies.join('; ') : '';
    
    console.log('🍪 Session cookies:', cookieString);
    
    // Step 2: Test platform connections
    console.log('\n2. Testing platform connections...');
    const connectionsResponse = await axios.get(`${BASE_URL}/api/platform-connections`, {
      withCredentials: true,
      headers: {
        'Content-Type': 'application/json',
        'Cookie': cookieString
      }
    });
    
    console.log('✅ Platform connections retrieved:', connectionsResponse.data);
    console.log('📊 Connection count:', connectionsResponse.data.length);
    
    // Step 3: Test direct publish endpoint
    console.log('\n3. Testing direct publish endpoint...');
    const publishResponse = await axios.post(`${BASE_URL}/api/direct-publish`, {
      action: 'test_publish_all',
      content: 'TEST: Session authentication working'
    }, {
      withCredentials: true,
      headers: {
        'Content-Type': 'application/json',
        'Cookie': cookieString
      }
    });
    
    console.log('✅ Direct publish test:', publishResponse.data);
    
    console.log('\n🎉 Session establishment and platform connections working correctly!');
    
  } catch (error) {
    console.error('❌ Test failed:', error.response?.data || error.message);
    console.error('Status:', error.response?.status);
  }
}

testSessionAndConnections();