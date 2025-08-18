/**
 * Test Publishing System with Optimized Connections
 * Verify 100% publishing success rate with clean connection state
 */

import axios from 'axios';

async function testPublishingSystem() {
  console.log('🧪 PUBLISHING SYSTEM TEST - Testing optimized connections');
  
  try {
    // Establish session first
    console.log('\n🔐 Establishing session...');
    const sessionResponse = await axios.post('http://localhost:5000/api/establish-session', {
      email: 'gailm@macleodglba.com.au',
      phone: '+61424835189'
    });
    
    const sessionCookie = sessionResponse.headers['set-cookie']?.[0];
    console.log('✅ Session established');
    
    // Get platform connections
    console.log('\n🔗 Getting platform connections...');
    const connectionsResponse = await axios.get('http://localhost:5000/api/platform-connections', {
      headers: { Cookie: sessionCookie }
    });
    
    const connections = connectionsResponse.data;
    console.log(`✅ Found ${connections.length} platform connections:`);
    
    connections.forEach(conn => {
      console.log(`   📱 ${conn.platform}: ${conn.isActive ? 'Active' : 'Inactive'} (OAuth: ${conn.oauthStatus?.isValid ? 'Valid' : 'Invalid'})`);
    });
    
    // Test direct publishing to all platforms
    console.log('\n🚀 Testing direct publishing...');
    
    const testContent = {
      content: "TEST - Optimized connection system verification",
      platforms: connections.filter(c => c.isActive).map(c => c.platform)
    };
    
    console.log(`📝 Publishing to ${testContent.platforms.length} platforms: ${testContent.platforms.join(', ')}`);
    
    try {
      const publishResponse = await axios.post('http://localhost:5000/api/direct-publish', testContent, {
        headers: { 
          Cookie: sessionCookie,
          'Content-Type': 'application/json'
        }
      });
      
      const results = publishResponse.data;
      console.log('\n📊 Publishing Results:');
      
      if (results.results) {
        results.results.forEach(result => {
          const status = result.success ? '✅' : '❌';
          console.log(`   ${status} ${result.platform}: ${result.success ? 'Success' : result.error}`);
        });
        
        const successCount = results.results.filter(r => r.success).length;
        const totalCount = results.results.length;
        const successRate = (successCount / totalCount * 100).toFixed(1);
        
        console.log(`\n📈 Success Rate: ${successCount}/${totalCount} (${successRate}%)`);
        
        if (successRate === '100.0') {
          console.log('🎉 PERFECT! 100% publishing success rate achieved');
        } else {
          console.log(`⚠️  ${100 - parseFloat(successRate)}% of platforms need OAuth refresh`);
        }
      }
      
    } catch (publishError) {
      console.error('❌ Publishing test failed:', publishError.response?.data || publishError.message);
    }
    
    // Test OAuth status validation
    console.log('\n🔍 Testing OAuth validation...');
    
    try {
      const oauthResponse = await axios.get('http://localhost:5000/api/oauth/validate-tokens', {
        headers: { Cookie: sessionCookie }
      });
      
      const oauthResults = oauthResponse.data;
      
      if (oauthResults.validationResults) {
        console.log('📋 OAuth Validation Results:');
        oauthResults.validationResults.forEach(result => {
          const status = result.success ? '✅' : '❌';
          console.log(`   ${status} ${result.platform}: ${result.success ? 'Valid' : result.error}`);
        });
      }
      
    } catch (oauthError) {
      console.error('❌ OAuth validation failed:', oauthError.response?.data || oauthError.message);
    }
    
    console.log('\n🏁 Publishing system test completed!');
    
  } catch (error) {
    console.error('\n❌ Test failed:', error.message);
  }
}

// Run the test
testPublishingSystem().catch(console.error);