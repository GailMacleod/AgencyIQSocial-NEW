/**
 * Test Publishing to All Platforms
 * Sends "Test" message to all 5 platforms with OAuth token validation
 */

async function testPublishToAllPlatforms() {
  const baseUrl = 'https://4fc77172-459a-4da7-8c33-5014abb1b73e-00-dqhtnud4ismj.worf.replit.dev';
  
  console.log('🚀 PUBLISHING TEST TO ALL PLATFORMS');
  console.log('===================================');
  
  // Create test post data
  const testPost = {
    content: 'Test',
    platforms: ['facebook', 'instagram', 'linkedin', 'x', 'youtube'],
    userId: 2
  };
  
  try {
    // First, check current token status
    console.log('\n🔍 Checking current token status...');
    const connectionsResponse = await fetch(`${baseUrl}/api/platform-connections`, {
      credentials: 'include'
    });
    
    if (!connectionsResponse.ok) {
      throw new Error(`Failed to fetch connections: ${connectionsResponse.status}`);
    }
    
    const connections = await connectionsResponse.json();
    
    // Get latest connection per platform
    const latestConnections = {};
    connections.forEach(conn => {
      if (!latestConnections[conn.platform] || 
          new Date(conn.connectedAt) > new Date(latestConnections[conn.platform].connectedAt)) {
        latestConnections[conn.platform] = conn;
      }
    });
    
    console.log('\n📊 Current Platform Status:');
    const platforms = ['facebook', 'instagram', 'linkedin', 'x', 'youtube'];
    
    platforms.forEach(platform => {
      const conn = latestConnections[platform];
      if (conn) {
        const status = conn.oauthStatus?.isValid ? 'Valid' : 'Invalid';
        const error = conn.oauthStatus?.error || 'None';
        console.log(`  ${platform.toUpperCase()}: ${status} | Error: ${error}`);
      } else {
        console.log(`  ${platform.toUpperCase()}: No connection found`);
      }
    });
    
    // Attempt to publish test post
    console.log('\n🚀 Publishing test post...');
    const publishResponse = await fetch(`${baseUrl}/api/post/publish-direct`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      credentials: 'include',
      body: JSON.stringify(testPost)
    });
    
    const publishResult = await publishResponse.json();
    
    console.log('\n📈 Publishing Results:');
    console.log('Status:', publishResponse.status);
    console.log('Response:', JSON.stringify(publishResult, null, 2));
    
    if (publishResult.results) {
      console.log('\n📋 Platform-Specific Results:');
      publishResult.results.forEach(result => {
        const status = result.success ? '✅ SUCCESS' : '❌ FAILED';
        console.log(`  ${result.platform.toUpperCase()}: ${status}`);
        if (result.error) {
          console.log(`    Error: ${result.error}`);
        }
        if (result.postId) {
          console.log(`    Post ID: ${result.postId}`);
        }
      });
    }
    
    // Check for token refresh needs
    if (publishResult.results) {
      const needsRefresh = publishResult.results.filter(r => r.error && r.error.includes('token'));
      if (needsRefresh.length > 0) {
        console.log('\n🔄 Platforms needing token refresh:');
        needsRefresh.forEach(r => {
          console.log(`  ${r.platform.toUpperCase()}: ${r.error}`);
        });
        console.log('\n💡 Recommendation: Visit /connect-platforms and reconnect expired platforms');
      }
    }
    
  } catch (error) {
    console.error('❌ Test publishing failed:', error.message);
  }
}

testPublishToAllPlatforms();