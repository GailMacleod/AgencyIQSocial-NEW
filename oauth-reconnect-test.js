/**
 * OAuth Reconnection Test
 * Tests the OAuth reconnection system for specific platforms needing refresh
 */

async function establishSession() {
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
    return setCookie;
  } else {
    throw new Error(`Session establishment failed: ${response.status}`);
  }
}

async function testOAuthReconnection() {
  console.log('🔄 OAUTH RECONNECTION TEST');
  console.log('=========================');
  
  try {
    const cookies = await establishSession();
    console.log('✅ Session established');
    
    // Test manual OAuth refresh for each platform
    const platforms = ['facebook', 'instagram', 'linkedin', 'x', 'youtube'];
    
    for (const platform of platforms) {
      console.log(`\n🔧 Testing ${platform} OAuth refresh...`);
      
      const response = await fetch(`http://localhost:5000/api/oauth/refresh/${platform}`, {
        method: 'POST',
        headers: { 'Cookie': cookies }
      });
      
      if (response.ok) {
        const result = await response.json();
        if (result.success) {
          console.log(`✅ ${platform} token refreshed successfully`);
        } else {
          console.log(`❌ ${platform} refresh failed: ${result.error}`);
          if (result.requiresReauth) {
            console.log(`   💡 Solution: Reconnect via /api/auth/${platform}`);
          }
        }
      } else {
        console.log(`❌ ${platform} refresh request failed: ${response.status}`);
      }
    }
    
    console.log('\n🧪 Testing publishing after refresh attempts...');
    
    // Test publishing after refresh attempts
    const publishResponse = await fetch('http://localhost:5000/api/direct-publish', {
      method: 'POST',
      headers: {
        'Cookie': cookies,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        action: 'test_publish_all',
        content: 'OAuth Reconnection Test',
        platforms: platforms
      })
    });
    
    if (publishResponse.ok) {
      const result = await publishResponse.json();
      console.log('\n📊 POST-REFRESH PUBLISHING RESULTS:');
      console.log(`✅ Successful: ${result.summary?.successCount || 0}`);
      console.log(`❌ Failed: ${result.summary?.failureCount || 0}`);
      
      Object.entries(result.results).forEach(([platform, details]) => {
        const emoji = details.success ? '✅' : '❌';
        console.log(`${emoji} ${platform.toUpperCase()}: ${details.success ? 'SUCCESS' : details.error}`);
      });
    }
    
  } catch (error) {
    console.error('❌ Test failed:', error.message);
  }
}

testOAuthReconnection();