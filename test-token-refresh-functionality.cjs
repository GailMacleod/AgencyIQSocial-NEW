/**
 * TEST TOKEN REFRESH FUNCTIONALITY
 * Tests the complete token refresh workflow for expired platforms
 */

const axios = require('axios');
const BASE_URL = 'https://4fc77172-459a-4da7-8c33-5014abb1b73e-00-dqhtnud4ismj.worf.replit.dev';

async function testTokenRefreshWorkflow() {
  console.log('🔄 TESTING TOKEN REFRESH FUNCTIONALITY');
  console.log('=====================================');
  
  try {
    // Step 1: Establish session
    console.log('\n📝 STEP 1: Establishing authenticated session...');
    const sessionResponse = await axios.post(`${BASE_URL}/api/establish-session`, {
      email: 'gailm@macleodglba.com.au',
      phone: '+61424835189'
    }, {
      withCredentials: true
    });
    
    console.log('✅ Session established:', sessionResponse.data.message);
    
    // Step 2: Check platform connections to identify expired tokens
    console.log('\n🔗 STEP 2: Checking platform connections for expired tokens...');
    const connectionsResponse = await axios.get(`${BASE_URL}/api/platform-connections`, {
      withCredentials: true
    });
    
    const connections = connectionsResponse.data;
    console.log(`📊 Found ${connections.length} platform connections`);
    
    const expiredConnections = connections.filter(conn => 
      conn.oauthStatus && !conn.oauthStatus.isValid
    );
    
    console.log(`⚠️  Found ${expiredConnections.length} expired connections:`);
    expiredConnections.forEach(conn => {
      console.log(`  - ${conn.platform}: ${conn.oauthStatus.error}`);
    });
    
    // Step 3: Test token refresh for each expired platform
    console.log('\n🔄 STEP 3: Testing token refresh for expired platforms...');
    
    for (const connection of expiredConnections) {
      const platform = connection.platform;
      
      console.log(`\n🔄 Testing token refresh for ${platform}...`);
      
      try {
        const refreshResponse = await axios.post(`${BASE_URL}/api/platform-connections/${platform}/refresh`, {}, {
          withCredentials: true
        });
        
        const refreshData = refreshResponse.data;
        
        if (refreshData.success) {
          console.log(`✅ ${platform} token refresh successful!`);
          console.log(`   Message: ${refreshData.message}`);
        } else {
          console.log(`❌ ${platform} token refresh failed:`);
          console.log(`   Error: ${refreshData.error}`);
          console.log(`   Requires reconnection: ${refreshData.requiresReconnection}`);
        }
        
      } catch (error) {
        console.log(`❌ ${platform} token refresh request failed:`);
        console.log(`   Status: ${error.response?.status}`);
        console.log(`   Message: ${error.response?.data?.error || error.message}`);
      }
    }
    
    // Step 4: Verify platform connections after refresh attempts
    console.log('\n✅ STEP 4: Verifying platform connections after refresh...');
    
    const updatedConnectionsResponse = await axios.get(`${BASE_URL}/api/platform-connections`, {
      withCredentials: true
    });
    
    const updatedConnections = updatedConnectionsResponse.data;
    console.log(`📊 Updated platform connections status:`);
    
    updatedConnections.forEach(conn => {
      const status = conn.oauthStatus?.isValid ? 'VALID' : 'EXPIRED';
      console.log(`  - ${conn.platform}: ${status} (${conn.platformUsername})`);
      if (!conn.oauthStatus?.isValid) {
        console.log(`    Error: ${conn.oauthStatus?.error}`);
      }
    });
    
    // Step 5: Generate final report
    console.log('\n📋 FINAL REPORT:');
    console.log('================');
    
    const validConnections = updatedConnections.filter(conn => conn.oauthStatus?.isValid).length;
    const totalConnections = updatedConnections.length;
    
    console.log(`🔗 Total Connections: ${totalConnections}`);
    console.log(`✅ Valid Connections: ${validConnections}`);
    console.log(`❌ Expired Connections: ${totalConnections - validConnections}`);
    
    if (validConnections === totalConnections) {
      console.log('🎉 ALL TOKENS REFRESHED SUCCESSFULLY!');
    } else {
      console.log('⚠️  Some tokens still require manual reconnection');
    }
    
  } catch (error) {
    console.error('❌ Test failed:', error.message);
    if (error.response) {
      console.error('Response:', error.response.data);
    }
  }
}

// Run the test
testTokenRefreshWorkflow();