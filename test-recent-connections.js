/**
 * Test most recent platform connections to see if Facebook OAuth was successful
 */

async function testRecentConnections() {
  const baseUrl = 'https://4fc77172-459a-4da7-8c33-5014abb1b73e-00-dqhtnud4ismj.worf.replit.dev';
  
  console.log('🔗 CHECKING RECENT PLATFORM CONNECTIONS');
  console.log('=====================================');
  
  try {
    const response = await fetch(`${baseUrl}/api/platform-connections`, {
      credentials: 'include'
    });
    
    if (!response.ok) {
      console.error('Failed to get connections:', response.status);
      return;
    }
    
    const connections = await response.json();
    
    // Sort by most recent first
    const sortedConnections = connections.sort((a, b) => 
      new Date(b.connectedAt).getTime() - new Date(a.connectedAt).getTime()
    );
    
    console.log('📅 Most Recent 10 Connections:');
    console.log('==============================');
    
    sortedConnections.slice(0, 10).forEach((connection, index) => {
      const connectedTime = new Date(connection.connectedAt).toLocaleString();
      const tokenPreview = connection.accessToken ? 
        connection.accessToken.substring(0, 20) + '...' : 'No token';
      
      console.log(`${index + 1}. ${connection.platform.toUpperCase()} - ${connectedTime}`);
      console.log(`   User: ${connection.platformUsername}`);
      console.log(`   Token: ${tokenPreview}`);
      console.log(`   Valid: ${connection.oauthStatus?.isValid ? '✅' : '❌'}`);
      if (connection.oauthStatus?.error) {
        console.log(`   Error: ${connection.oauthStatus.error}`);
      }
      console.log('');
    });
    
    // Check if there are any connections from the last hour
    const oneHourAgo = new Date(Date.now() - 60 * 60 * 1000);
    const recentConnections = connections.filter(c => 
      new Date(c.connectedAt) > oneHourAgo
    );
    
    console.log(`🕐 Connections from last hour: ${recentConnections.length}`);
    
    if (recentConnections.length > 0) {
      console.log('Recent connections:');
      recentConnections.forEach(c => {
        console.log(`  - ${c.platform}: ${c.oauthStatus?.isValid ? '✅ Valid' : '❌ Invalid'}`);
        if (c.oauthStatus?.error) {
          console.log(`    Error: ${c.oauthStatus.error}`);
        }
      });
    }
    
  } catch (error) {
    console.error('❌ Test failed:', error.message);
  }
}

testRecentConnections();