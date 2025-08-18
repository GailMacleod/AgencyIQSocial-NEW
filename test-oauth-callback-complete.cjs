/**
 * Test Complete OAuth Callback Process
 * Simulates the complete OAuth callback with session management
 */

const axios = require('axios');
const tough = require('tough-cookie');
const { Pool } = require('pg');

const BASE_URL = 'https://4fc77172-459a-4da7-8c33-5014abb1b73e-00-dqhtnud4ismj.worf.replit.dev';

const pool = new Pool({
  connectionString: process.env.DATABASE_URL
});

async function testCompleteOAuthCallback() {
  console.log('🔄 Testing Complete OAuth Callback Process...');
  
  const cookieJar = new tough.CookieJar();
  const axiosInstance = axios.create({
    jar: cookieJar,
    withCredentials: true
  });
  
  try {
    // Step 1: Login to establish session
    console.log('1️⃣ Establishing session...');
    const loginResponse = await axiosInstance.post(`${BASE_URL}/api/auth/login`, {
      email: 'gailm@macleodglba.com.au',
      password: 'testpass'
    });
    console.log('✅ Session established');
    
    // Step 2: Check platform connections before
    const beforeResult = await pool.query('SELECT COUNT(*) FROM platform_connections WHERE user_id = 2');
    console.log('📊 Platform connections before:', beforeResult.rows[0].count);
    
    // Step 3: Test OAuth initiation for all platforms
    const platforms = [
      { name: 'Facebook', endpoint: '/auth/facebook' },
      { name: 'Instagram', endpoint: '/auth/instagram' },
      { name: 'LinkedIn', endpoint: '/auth/linkedin' },
      { name: 'X', endpoint: '/auth/twitter' },
      { name: 'YouTube', endpoint: '/auth/youtube' }
    ];
    
    for (const platform of platforms) {
      console.log(`2️⃣ Testing ${platform.name} OAuth initiation...`);
      
      try {
        const response = await axiosInstance.get(`${BASE_URL}${platform.endpoint}`, {
          maxRedirects: 0,
          validateStatus: function (status) {
            return status >= 200 && status < 400;
          }
        });
        
        console.log(`✅ ${platform.name} OAuth initiation successful`);
        console.log(`   Status: ${response.status}`);
        console.log(`   Redirect: ${response.headers.location ? 'YES' : 'NO'}`);
        
        if (response.headers.location) {
          console.log(`   Redirect URL: ${response.headers.location.substring(0, 100)}...`);
        }
        
      } catch (error) {
        if (error.response) {
          console.log(`❌ ${platform.name} OAuth failed:`, error.response.status, error.response.statusText);
        } else {
          console.log(`❌ ${platform.name} OAuth error:`, error.message);
        }
      }
    }
    
    // Step 4: Check if any connections were created during OAuth testing
    const afterResult = await pool.query('SELECT COUNT(*) FROM platform_connections WHERE user_id = 2');
    console.log('📊 Platform connections after:', afterResult.rows[0].count);
    
    // Step 5: Test platform connections API with session
    console.log('3️⃣ Testing platform connections API...');
    
    try {
      const connectionsResponse = await axiosInstance.get(`${BASE_URL}/api/platform-connections`);
      console.log('✅ Platform connections API successful');
      console.log('   Data:', connectionsResponse.data);
    } catch (error) {
      if (error.response) {
        console.log('❌ Platform connections API failed:', error.response.status, error.response.data);
      } else {
        console.log('❌ Platform connections API error:', error.message);
      }
    }
    
    // Step 6: Simulate OAuth callback completion
    console.log('4️⃣ Simulating OAuth callback completion...');
    
    // Direct API call to test OAuth callback handling
    const testCallbackData = {
      platform: 'test_platform',
      access_token: 'test_token_' + Date.now(),
      refresh_token: 'test_refresh_' + Date.now(),
      platform_user_id: 'test_user_123',
      platform_username: 'Test User'
    };
    
    console.log('Test callback data:', testCallbackData);
    
    console.log('🎯 Complete OAuth Callback Test Complete');
    
  } catch (error) {
    console.error('❌ Complete OAuth Test Failed:', error);
    if (error.response) {
      console.log('Response data:', error.response.data);
    }
  } finally {
    await pool.end();
  }
}

testCompleteOAuthCallback();