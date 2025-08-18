/**
 * Enhanced Authenticated Platform Publishing Test
 * Tests publishing "TEST" to all platforms with automatic token refresh
 */

async function establishSession() {
  console.log('🔑 Authenticating session...');
  
  const response = await fetch('http://localhost:5000/api/establish-session', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      email: 'gailm@macleodglba.com.au',
      password: 'password123'
    })
  });

  if (response.ok) {
    const setCookie = response.headers.get('set-cookie');
    console.log('✅ Session established successfully');
    return setCookie;
  } else {
    throw new Error(`Session establishment failed: ${response.status}`);
  }
}

async function checkPlatformConnections(cookies) {
  console.log('🔗 Checking platform connections...');
  
  const response = await fetch('http://localhost:5000/api/platform-connections', {
    method: 'GET',
    headers: { 'Cookie': cookies }
  });
  
  if (response.ok) {
    const connections = await response.json();
    const activeConnections = connections.filter(conn => conn.isActive);
    
    console.log(`📊 Found ${connections.length} total connections, ${activeConnections.length} active`);
    
    const platformSummary = connections.reduce((acc, conn) => {
      if (!acc[conn.platform]) acc[conn.platform] = { total: 0, active: 0, valid: 0 };
      acc[conn.platform].total++;
      if (conn.isActive) acc[conn.platform].active++;
      if (conn.oauthStatus?.isValid) acc[conn.platform].valid++;
      return acc;
    }, {});
    
    console.log('🔍 Platform Connection Status:');
    Object.entries(platformSummary).forEach(([platform, stats]) => {
      console.log(`  ${platform}: ${stats.total} total, ${stats.active} active, ${stats.valid} valid`);
    });
    
    return connections;
  } else {
    console.log('❌ Failed to get platform connections');
    return [];
  }
}

async function testAuthenticatedPublishing() {
  console.log('🚀 ENHANCED AUTHENTICATED PUBLISHING TEST');
  console.log('========================================');
  
  try {
    const cookies = await establishSession();
    
    // Check platform connections first
    const connections = await checkPlatformConnections(cookies);
    
    console.log('\n📤 Publishing "TEST" to all platforms with automatic token refresh...');
    
    const response = await fetch('http://localhost:5000/api/direct-publish', {
      method: 'POST',
      headers: {
        'Cookie': cookies,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        action: 'test_publish_all',
        content: 'TEST',
        platforms: ['facebook', 'instagram', 'linkedin', 'x', 'youtube']
      })
    });
    
    if (response.ok) {
      const result = await response.json();
      
      console.log('\n📊 PUBLISHING RESULTS WITH TOKEN REFRESH:');
      console.log(`✅ Successful: ${result.summary?.successCount || 0}`);
      console.log(`❌ Failed: ${result.summary?.failureCount || 0}`);
      
      console.log('\n📝 Platform Details:');
      Object.entries(result.results).forEach(([platform, details]) => {
        const emoji = details.success ? '✅' : '❌';
        const status = details.success ? 'SUCCESS' : details.error || 'FAILED';
        console.log(`${emoji} ${platform.toUpperCase()}: ${status}`);
        
        if (details.platformPostId) {
          console.log(`   📍 Post ID: ${details.platformPostId}`);
        }
        
        // Show specific OAuth fixes needed
        if (!details.success && details.error) {
          if (details.error.includes('Token requires regeneration')) {
            console.log(`   🔧 FIX: Generate new Facebook Page Access Token`);
          } else if (details.error.includes('Invalid OAuth access token')) {
            console.log(`   🔧 FIX: Reconnect Instagram via OAuth popup`);
          } else if (details.error.includes('valid access token')) {
            console.log(`   🔧 FIX: Reconnect LinkedIn via OAuth popup`);
          } else if (details.error.includes('OAuth 2.0 User Context')) {
            console.log(`   🔧 FIX: Reconnect X with User Context permissions`);
          } else if (details.error.includes('YouTube')) {
            console.log(`   🔧 FIX: Reconnect YouTube via OAuth popup`);
          }
        }
      });
      
      if (result.summary?.successCount > 0) {
        console.log('\n🎉 SUCCESS! "TEST" has been published to platforms!');
        console.log(`   📊 Quota deducted: ${result.summary.quotaDeducted ? 'Yes' : 'No'}`);
      } else {
        console.log('\n⚠️  No platforms were successfully published to.');
        console.log('   💡 SOLUTION: Use OAuth reconnection system in platform connections page');
        console.log('   🔄 Token refresh attempted but requires fresh OAuth authorization');
      }
      
    } else {
      console.log(`❌ Publishing request failed: ${response.status}`);
      const error = await response.json().catch(() => ({}));
      console.log('Error details:', error);
    }
    
  } catch (error) {
    console.error('❌ Test failed:', error.message);
  }
}

// Run the test
testAuthenticatedPublishing();