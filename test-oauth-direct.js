/**
 * Direct OAuth Token Refresh Test - Real Publishing Test
 * Tests OAuth token refresh by calling the API endpoints directly
 */

async function testOAuthWithDirectPublishing() {
  const baseUrl = 'https://4fc77172-459a-4da7-8c33-5014abb1b73e-00-dqhtnud4ismj.worf.replit.dev';
  
  console.log('🔗 DIRECT OAUTH TOKEN REFRESH TEST');
  console.log('==================================');
  
  try {
    // Test the OAuth refresh endpoint for Facebook
    console.log('Testing Facebook OAuth refresh...');
    const facebookRefreshResponse = await fetch(`${baseUrl}/api/oauth/refresh/facebook`, {
      method: 'POST',
      credentials: 'include',
      headers: {
        'Content-Type': 'application/json'
      }
    });
    
    const facebookRefreshResult = await facebookRefreshResponse.json();
    console.log('Facebook refresh result:', facebookRefreshResult);
    
    // Test the OAuth refresh endpoint for Instagram
    console.log('\nTesting Instagram OAuth refresh...');
    const instagramRefreshResponse = await fetch(`${baseUrl}/api/oauth/refresh/instagram`, {
      method: 'POST',
      credentials: 'include',
      headers: {
        'Content-Type': 'application/json'
      }
    });
    
    const instagramRefreshResult = await instagramRefreshResponse.json();
    console.log('Instagram refresh result:', instagramRefreshResult);
    
    // Test platform connections after refresh
    console.log('\n📊 Checking connection status after refresh...');
    const connectionsResponse = await fetch(`${baseUrl}/api/platform-connections`, {
      credentials: 'include'
    });
    
    const connections = await connectionsResponse.json();
    const recentConnections = connections.filter(c => 
      new Date(c.connectedAt) > new Date(Date.now() - 2 * 60 * 60 * 1000) // Last 2 hours
    );
    
    console.log(`Recent connections: ${recentConnections.length}`);
    recentConnections.forEach(connection => {
      console.log(`${connection.platform}: ${connection.oauthStatus?.isValid ? '✅ Valid' : '❌ Invalid'}`);
      if (connection.oauthStatus?.error) {
        console.log(`  Error: ${connection.oauthStatus.error}`);
      }
    });
    
    // Test direct publishing to see if tokens work
    console.log('\n📝 Testing direct publishing with current tokens...');
    const testPost = {
      content: 'Test post from OAuth validation system',
      platforms: ['facebook', 'instagram']
    };
    
    const publishResponse = await fetch(`${baseUrl}/api/publish-post`, {
      method: 'POST',
      credentials: 'include',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(testPost)
    });
    
    const publishResult = await publishResponse.json();
    console.log('Publishing test result:', publishResult);
    
  } catch (error) {
    console.error('❌ Direct OAuth test failed:', error.message);
  }
}

testOAuthWithDirectPublishing();