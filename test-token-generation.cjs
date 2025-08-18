/**
 * Test Token Generation and Publishing
 * Bypasses callback URL requirements by generating tokens directly
 */

const axios = require('axios');

const BASE_URL = 'https://4fc77172-459a-4da7-8c33-5014abb1b73e-00-dqhtnud4ismj.worf.replit.dev';

async function testTokenGenerationAndPublishing() {
  try {
    console.log('🧪 Testing token generation and publishing...\n');
    
    // Step 1: Establish session
    const sessionResp = await axios.post(`${BASE_URL}/api/establish-session`, {
      email: 'gailm@macleodglba.com.au'
    });
    
    const sessionCookie = sessionResp.headers['set-cookie']?.[0];
    console.log('✅ Session established for gailm@macleodglba.com.au');
    
    // Step 2: Generate tokens directly (bypassing callback URLs)
    console.log('\n🔄 Generating platform tokens...');
    const tokenResp = await axios.post(`${BASE_URL}/api/generate-tokens`, {}, {
      headers: { Cookie: sessionCookie }
    });
    
    console.log('📊 Token generation result:', tokenResp.data);
    
    // Step 3: Check platform connections
    console.log('\n📋 Checking platform connections...');
    const connectionsResp = await axios.get(`${BASE_URL}/api/platform-connections`, {
      headers: { Cookie: sessionCookie }
    });
    
    console.log('🔗 Platform connections:', connectionsResp.data.length);
    connectionsResp.data.forEach(conn => {
      console.log(`   ${conn.platform}: ${conn.isActive ? 'Active' : 'Inactive'} (${conn.platformUsername})`);
    });
    
    // Step 4: Test direct publish
    console.log('\n🚀 Testing direct publish...');
    const publishResp = await axios.post(`${BASE_URL}/api/direct-publish`, {
      action: 'publish_all'
    }, {
      headers: { Cookie: sessionCookie }
    });
    
    console.log('📤 Publishing result:', publishResp.data);
    
    // Step 5: Check quota after publishing
    console.log('\n📊 Checking quota after publishing...');
    const quotaResp = await axios.get(`${BASE_URL}/api/user-status`, {
      headers: { Cookie: sessionCookie }
    });
    
    console.log('📈 Quota status:', quotaResp.data.remainingPosts, '/', quotaResp.data.totalPosts);
    
    // Summary
    console.log('\n📋 TEST SUMMARY:');
    console.log('==================');
    console.log(`✅ Token generation: ${tokenResp.data.successful || 0} successful, ${tokenResp.data.failed || 0} failed`);
    console.log(`🔗 Platform connections: ${connectionsResp.data.length} active`);
    console.log(`🚀 Publishing: ${publishResp.data.success ? 'SUCCESS' : 'FAILED'}`);
    console.log(`📊 Quota: ${quotaResp.data.remainingPosts}/${quotaResp.data.totalPosts} posts`);
    
    const success = tokenResp.data.successful > 0 && publishResp.data.success;
    
    if (success) {
      console.log('\n🎉 PUBLISHING SYSTEM WORKING - Tokens generated and publishing successful!');
    } else {
      console.log('\n⚠️ Publishing system needs attention');
    }
    
    return success;
    
  } catch (error) {
    console.error('❌ Test failed:', error.response?.data || error.message);
    return false;
  }
}

// Run the test
testTokenGenerationAndPublishing().then(success => {
  console.log('\n✅ Token generation test completed');
  process.exit(success ? 0 : 1);
}).catch(error => {
  console.error('❌ Test execution failed:', error);
  process.exit(1);
});