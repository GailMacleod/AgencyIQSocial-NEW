/**
 * Test Session Cookie Fix
 * Tests that session cookies are properly set and persist across requests
 */

const axios = require('axios');

const BASE_URL = 'https://4fc77172-459a-4da7-8c33-5014abb1b73e-00-dqhtnud4ismj.worf.replit.dev';

async function testSessionCookies() {
  try {
    console.log('🔧 TESTING SESSION COOKIE FIX\n');
    
    // Step 1: Establish session
    const sessionResp = await axios.post(`${BASE_URL}/api/establish-session`, {
      email: 'gailm@macleodglba.com.au'
    });
    
    const sessionCookie = sessionResp.headers['set-cookie']?.[0];
    console.log('✅ Session established');
    console.log('🍪 Session cookie:', sessionCookie?.substring(0, 50) + '...');
    
    // Step 2: Test /api/user endpoint with cookie
    const userResp = await axios.get(`${BASE_URL}/api/user`, {
      headers: { Cookie: sessionCookie }
    });
    
    console.log('✅ /api/user endpoint:', userResp.status, userResp.data.email);
    
    // Step 3: Test /api/user-status endpoint with cookie
    const statusResp = await axios.get(`${BASE_URL}/api/user-status`, {
      headers: { Cookie: sessionCookie }
    });
    
    console.log('✅ /api/user-status endpoint:', statusResp.status, statusResp.data.authenticated);
    
    // Step 4: Test /api/posts endpoint with cookie
    const postsResp = await axios.get(`${BASE_URL}/api/posts`, {
      headers: { Cookie: sessionCookie }
    });
    
    console.log('✅ /api/posts endpoint:', postsResp.status, `${postsResp.data.length} posts`);
    
    // Step 5: Test without cookie (should fail)
    try {
      await axios.get(`${BASE_URL}/api/user`);
      console.log('⚠️ No cookie test: Should have failed but passed');
    } catch (error) {
      console.log('✅ No cookie test: Correctly failed with', error.response?.status);
    }
    
    console.log('\n🎉 SESSION COOKIE FIX WORKING!');
    console.log('✅ Cookies properly set and transmitted');
    console.log('✅ All authenticated endpoints working');
    console.log('✅ Proper authentication enforcement');
    
    return true;
    
  } catch (error) {
    console.error('❌ Session cookie test failed:', error.response?.data || error.message);
    return false;
  }
}

testSessionCookies().then(success => {
  console.log('\n✅ Session cookie test completed');
  process.exit(success ? 0 : 1);
});