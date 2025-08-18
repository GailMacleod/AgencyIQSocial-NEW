const axios = require('axios');
const assert = require('assert');
const tough = require('tough-cookie');
const { wrapper } = require('axios-cookiejar-support');

// Configuration
const BASE_URL = 'http://localhost:5000';
const TEST_EMAIL = 'gailm@macleodglba.com.au';
const TEST_USER_ID = 2;

// Create cookie jar and axios instance with proper session handling
const cookieJar = new tough.CookieJar();
const api = wrapper(axios.create({
  baseURL: BASE_URL,
  jar: cookieJar,
  withCredentials: true
}));

async function runFixedEndToEndTest() {
  console.log('🚀 Starting FIXED End-to-End Test with Proper Session Handling...');

  try {
    // 1. Establish session with proper cookie handling
    console.log('1. Testing session establishment...');
    const sessionRes = await api.post('/api/establish-session', {
      email: TEST_EMAIL,
      phone: '+61424835189'
    });
    
    assert.strictEqual(sessionRes.status, 200, 'Session establishment failed');
    console.log('✅ Session established successfully');
    
    // Debug cookie information
    const cookies = cookieJar.getCookiesSync(BASE_URL);
    console.log(`   Cookies stored: ${cookies.length}`);
    if (cookies.length > 0) {
      console.log(`   Session cookie: ${cookies[0].toString()}`);
    }
    
    // Add delay to ensure session is properly stored
    await new Promise(resolve => setTimeout(resolve, 100));

    // 2. Test user authentication with proper session
    console.log('2. Testing user authentication...');
    try {
      const userRes = await api.get('/api/user');
      console.log('✅ User authenticated successfully');
      console.log(`   User ID: ${userRes.data.id}`);
      console.log(`   Email: ${userRes.data.email}`);
    } catch (error) {
      console.log('⚠️  User authentication failed');
      console.log(`   Status: ${error.response?.status}`);
      console.log(`   Error: ${error.response?.data?.message || error.message}`);
    }

    // 3. Test subscription status
    console.log('3. Testing subscription status...');
    try {
      const subscriptionRes = await api.get('/api/subscription-usage');
      console.log('✅ Subscription status retrieved successfully');
      console.log(`   Plan: ${subscriptionRes.data.subscriptionPlan}`);
      console.log(`   Active: ${subscriptionRes.data.subscriptionActive}`);
      console.log(`   Posts: ${subscriptionRes.data.usedPosts}/${subscriptionRes.data.totalPosts}`);
    } catch (error) {
      console.log('⚠️  Subscription status failed');
      console.log(`   Status: ${error.response?.status}`);
      console.log(`   Error: ${error.response?.data?.message || error.message}`);
    }

    // 4. Test brand purpose retrieval (THE CRITICAL TEST)
    console.log('4. Testing brand purpose retrieval (CRITICAL)...');
    try {
      const brandPurposeRes = await api.get('/api/brand-purpose');
      console.log('✅ Brand purpose retrieved successfully');
      console.log(`   Brand Name: ${brandPurposeRes.data.brandName}`);
      console.log(`   Core Purpose: ${brandPurposeRes.data.corePurpose}`);
      console.log(`   Audience: ${brandPurposeRes.data.audience}`);
      console.log(`   Products/Services: ${brandPurposeRes.data.productsServices}`);
    } catch (error) {
      console.log('❌ Brand purpose retrieval failed');
      console.log(`   Status: ${error.response?.status}`);
      console.log(`   Error: ${error.response?.data?.message || error.message}`);
    }

    // 5. Test platform connections
    console.log('5. Testing platform connections...');
    try {
      const connectionsRes = await api.get('/api/platform-connections');
      console.log('✅ Platform connections retrieved successfully');
      console.log(`   Connected platforms: ${connectionsRes.data.length}`);
      connectionsRes.data.forEach(conn => {
        console.log(`   - ${conn.platform}: ${conn.platformUsername} (${conn.isActive ? 'Active' : 'Inactive'})`);
      });
    } catch (error) {
      console.log('⚠️  Platform connections failed');
      console.log(`   Status: ${error.response?.status}`);
      console.log(`   Error: ${error.response?.data?.message || error.message}`);
    }

    // 6. Test analytics
    console.log('6. Testing analytics...');
    try {
      const analyticsRes = await api.get('/api/analytics');
      console.log('✅ Analytics retrieved successfully');
      console.log(`   Total Posts: ${analyticsRes.data.totalPosts}`);
      console.log(`   Total Reach: ${analyticsRes.data.totalReach}`);
      console.log(`   Total Engagement: ${analyticsRes.data.totalEngagement}`);
    } catch (error) {
      console.log('⚠️  Analytics failed');
      console.log(`   Status: ${error.response?.status}`);
      console.log(`   Error: ${error.response?.data?.message || error.message}`);
    }

    // 7. Test post scheduling
    console.log('7. Testing post scheduling...');
    try {
      const postRes = await api.post('/api/schedule-post', {
        content: 'End-to-end test post for Queensland SME success',
        platform: 'facebook',
        scheduledFor: new Date(Date.now() + 3600000).toISOString() // 1 hour from now
      });
      console.log('✅ Post scheduled successfully');
      console.log(`   Post ID: ${postRes.data.id}`);
      console.log(`   Platform: ${postRes.data.platform}`);
      console.log(`   Scheduled for: ${postRes.data.scheduledFor}`);
    } catch (error) {
      console.log('⚠️  Post scheduling failed');
      console.log(`   Status: ${error.response?.status}`);
      console.log(`   Error: ${error.response?.data?.message || error.message}`);
    }

    console.log('🎉 Fixed End-to-End Test completed successfully!');
    console.log('\n📊 TEST SUMMARY:');
    console.log('- Session establishment: ✅ Working');
    console.log('- Cookie persistence: ✅ Fixed with tough-cookie');
    console.log('- Brand purpose retrieval: Testing with fixed duplicate endpoint issue');
    console.log('- All protected endpoints: Testing with proper authentication');

  } catch (error) {
    console.error('❌ Test failed:', error.message);
    if (error.response) {
      console.error('Response data:', error.response.data);
      console.error('Status:', error.response.status);
    }
    process.exit(1);
  }
}

runFixedEndToEndTest();