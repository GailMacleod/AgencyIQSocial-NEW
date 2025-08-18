/**
 * Simple Single-Client Authentication Test
 * Tests bypassing session cookies and using simple token authentication
 */

import axios from 'axios';
const axiosConfig = {
  baseURL: 'https://4fc77172-459a-4da7-8c33-5014abb1b73e-00-dqhtnud4ismj.worf.replit.dev',
  timeout: 10000,
  withCredentials: true
};

async function testSimpleAuth() {
  console.log('🔧 Testing simple single-client authentication...\n');
  
  try {
    // Step 1: Test session establishment
    console.log('📋 Step 1: Testing session establishment...');
    const sessionResponse = await axios.post('/api/establish-session', {}, axiosConfig);
    console.log('✅ Session establishment response:', sessionResponse.status);
    console.log('📋 Response data:', sessionResponse.data);
    
    // Extract session info
    const sessionId = sessionResponse.data.sessionId;
    const userId = sessionResponse.data.user.id;
    
    console.log(`🔑 Session ID: ${sessionId}`);
    console.log(`👤 User ID: ${userId}`);
    
    // Step 2: Test with manual cookie header
    console.log('\n📋 Step 2: Testing with manual cookie header...');
    const testConfig = {
      ...axiosConfig,
      headers: {
        'Cookie': `theagencyiq.session=${sessionId}`,
        'Content-Type': 'application/json'
      }
    };
    
    const userResponse = await axios.get('/api/user', testConfig);
    console.log('✅ User data retrieved successfully:', userResponse.status);
    console.log('📋 User data:', userResponse.data);
    
    // Step 3: Test platform connections
    console.log('\n📋 Step 3: Testing platform connections...');
    const platformResponse = await axios.get('/api/platform-connections', testConfig);
    console.log('✅ Platform connections retrieved successfully:', platformResponse.status);
    console.log('📋 Platform connections:', platformResponse.data.length, 'connections');
    
    console.log('\n🎯 Simple authentication test SUCCESSFUL! ✅');
    
  } catch (error) {
    console.error('❌ Simple authentication test failed:', error.response?.status || error.message);
    if (error.response?.data) {
      console.error('Response data:', error.response.data);
    }
  }
}

testSimpleAuth();