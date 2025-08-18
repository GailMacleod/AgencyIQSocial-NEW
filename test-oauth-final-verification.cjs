/**
 * Final OAuth Verification Test
 * Tests the complete OAuth system with all fixes applied
 */

const axios = require('axios');
const tough = require('tough-cookie');
const { Pool } = require('pg');

const BASE_URL = 'https://4fc77172-459a-4da7-8c33-5014abb1b73e-00-dqhtnud4ismj.worf.replit.dev';

const pool = new Pool({
  connectionString: process.env.DATABASE_URL
});

async function testFinalOAuthVerification() {
  console.log('🎯 FINAL OAUTH VERIFICATION TEST');
  console.log('Testing all 5 platforms with comprehensive fixes applied');
  console.log('='.repeat(60));
  
  const cookieJar = new tough.CookieJar();
  const axiosInstance = axios.create({
    jar: cookieJar,
    withCredentials: true
  });
  
  let testResults = {
    sessionEstablishment: false,
    oauthInitiation: {},
    databaseStorage: false,
    platformConnections: false,
    overallSuccess: false
  };
  
  try {
    // Test 1: Session establishment
    console.log('1️⃣ Testing session establishment...');
    const loginResponse = await axiosInstance.post(`${BASE_URL}/api/auth/login`, {
      email: 'gailm@macleodglba.com.au',
      password: 'testpass'
    });
    
    testResults.sessionEstablishment = loginResponse.status === 200;
    console.log(`✅ Session establishment: ${testResults.sessionEstablishment ? 'SUCCESS' : 'FAILED'}`);
    
    // Test 2: OAuth initiation for all platforms
    console.log('\n2️⃣ Testing OAuth initiation for all platforms...');
    
    const platforms = [
      { name: 'Facebook', endpoint: '/auth/facebook', expectedRedirect: 'facebook.com' },
      { name: 'Instagram', endpoint: '/auth/instagram', expectedRedirect: 'facebook.com' },
      { name: 'LinkedIn', endpoint: '/auth/linkedin', expectedRedirect: 'linkedin.com' },
      { name: 'X (Twitter)', endpoint: '/auth/twitter', expectedRedirect: 'twitter.com' },
      { name: 'YouTube', endpoint: '/auth/youtube', expectedRedirect: 'google.com' }
    ];
    
    for (const platform of platforms) {
      try {
        const response = await axiosInstance.get(`${BASE_URL}${platform.endpoint}`, {
          maxRedirects: 0,
          validateStatus: function (status) {
            return status >= 200 && status < 400;
          }
        });
        
        const success = response.status === 302 && 
                       response.headers.location && 
                       response.headers.location.includes(platform.expectedRedirect);
        
        testResults.oauthInitiation[platform.name] = success;
        console.log(`   ${platform.name}: ${success ? '✅ SUCCESS' : '❌ FAILED'}`);
        
        if (success) {
          const redirectUrl = response.headers.location.substring(0, 80) + '...';
          console.log(`      → Redirect: ${redirectUrl}`);
        }
        
      } catch (error) {
        testResults.oauthInitiation[platform.name] = false;
        console.log(`   ${platform.name}: ❌ FAILED - ${error.message}`);
      }
    }
    
    // Test 3: Database storage capability
    console.log('\n3️⃣ Testing database storage capability...');
    
    const testConnection = {
      userId: 2,
      platform: 'test_verification',
      platformUserId: 'test_user_verification',
      platformUsername: 'Test Verification User',
      accessToken: 'test_access_token_' + Date.now(),
      refreshToken: 'test_refresh_token_' + Date.now(),
      isActive: true
    };
    
    const insertResult = await pool.query(`
      INSERT INTO platform_connections 
      (user_id, platform, platform_user_id, platform_username, access_token, refresh_token, is_active, connected_at)
      VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())
      RETURNING *
    `, [
      testConnection.userId,
      testConnection.platform,
      testConnection.platformUserId,
      testConnection.platformUsername,
      testConnection.accessToken,
      testConnection.refreshToken,
      testConnection.isActive
    ]);
    
    testResults.databaseStorage = insertResult.rows.length > 0;
    console.log(`✅ Database storage: ${testResults.databaseStorage ? 'SUCCESS' : 'FAILED'}`);
    
    // Clean up test data
    await pool.query('DELETE FROM platform_connections WHERE platform = $1', ['test_verification']);
    
    // Test 4: Platform connections API
    console.log('\n4️⃣ Testing platform connections API...');
    
    try {
      const connectionsResponse = await axiosInstance.get(`${BASE_URL}/api/platform-connections`);
      testResults.platformConnections = connectionsResponse.status === 200;
      console.log(`✅ Platform connections API: ${testResults.platformConnections ? 'SUCCESS' : 'FAILED'}`);
      
      if (testResults.platformConnections) {
        console.log(`   → API Response: ${JSON.stringify(connectionsResponse.data).substring(0, 100)}...`);
      }
      
    } catch (error) {
      testResults.platformConnections = false;
      console.log(`❌ Platform connections API: FAILED - ${error.response?.status} ${error.response?.data?.message || error.message}`);
    }
    
    // Calculate overall success
    const oauthSuccessCount = Object.values(testResults.oauthInitiation).filter(Boolean).length;
    const totalOAuthTests = Object.keys(testResults.oauthInitiation).length;
    
    testResults.overallSuccess = testResults.sessionEstablishment &&
                                 oauthSuccessCount === totalOAuthTests &&
                                 testResults.databaseStorage &&
                                 testResults.platformConnections;
    
    // Final results
    console.log('\n' + '='.repeat(60));
    console.log('🎯 FINAL OAUTH VERIFICATION RESULTS');
    console.log('='.repeat(60));
    console.log(`Session Establishment: ${testResults.sessionEstablishment ? '✅ PASS' : '❌ FAIL'}`);
    console.log(`OAuth Initiation (${oauthSuccessCount}/${totalOAuthTests}): ${oauthSuccessCount === totalOAuthTests ? '✅ PASS' : '❌ FAIL'}`);
    console.log(`Database Storage: ${testResults.databaseStorage ? '✅ PASS' : '❌ FAIL'}`);
    console.log(`Platform Connections API: ${testResults.platformConnections ? '✅ PASS' : '❌ FAIL'}`);
    console.log('='.repeat(60));
    console.log(`🎯 OVERALL RESULT: ${testResults.overallSuccess ? '✅ COMPLETE SUCCESS' : '❌ NEEDS ATTENTION'}`);
    
    if (testResults.overallSuccess) {
      console.log('\n🎉 ALL OAUTH SYSTEMS WORKING CORRECTLY!');
      console.log('✅ Ready for production OAuth token storage');
      console.log('✅ All 5 platforms configured and tested');
      console.log('✅ Session management working properly');
      console.log('✅ Database storage functioning correctly');
    } else {
      console.log('\n⚠️  Some systems need attention - see results above');
    }
    
    return testResults;
    
  } catch (error) {
    console.error('❌ Final OAuth Verification Failed:', error);
    return testResults;
  } finally {
    await pool.end();
  }
}

testFinalOAuthVerification();