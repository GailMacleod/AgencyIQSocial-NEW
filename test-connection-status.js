/**
 * Test current platform connection status
 */

async function testConnectionStatus() {
  const baseUrl = 'https://4fc77172-459a-4da7-8c33-5014abb1b73e-00-dqhtnud4ismj.worf.replit.dev';
  
  console.log('🔗 TESTING PLATFORM CONNECTION STATUS');
  console.log('====================================');
  
  try {
    // Test platform connections endpoint
    const response = await fetch(`${baseUrl}/api/platform-connections`, {
      credentials: 'include'
    });
    
    console.log(`Response status: ${response.status}`);
    
    if (!response.ok) {
      const errorText = await response.text();
      console.error('Failed to get connections:', errorText);
      return;
    }
    
    const connections = await response.json();
    console.log(`Found ${connections.length} platform connections:`);
    
    if (connections.length === 0) {
      console.log('❌ No platform connections found');
      return;
    }
    
    // Display connection details
    connections.forEach((connection, index) => {
      console.log(`\n${index + 1}. ${connection.platform.toUpperCase()}`);
      console.log(`   Platform User: ${connection.platformUsername}`);
      console.log(`   Active: ${connection.isActive ? '✅' : '❌'}`);
      console.log(`   Connected: ${connection.connectedAt}`);
      console.log(`   Has Token: ${connection.accessToken ? '✅' : '❌'}`);
      
      if (connection.oauthStatus) {
        console.log(`   OAuth Status: ${connection.oauthStatus.isValid ? '✅ Valid' : '❌ Invalid'}`);
        if (connection.oauthStatus.error) {
          console.log(`   OAuth Error: ${connection.oauthStatus.error}`);
        }
      }
    });
    
    // Summary
    const activePlatforms = connections.filter(c => c.isActive);
    const validTokens = connections.filter(c => c.oauthStatus?.isValid);
    
    console.log('\n📊 SUMMARY');
    console.log('==========');
    console.log(`Total Platforms: ${connections.length}`);
    console.log(`Active Platforms: ${activePlatforms.length}`);
    console.log(`Valid Tokens: ${validTokens.length}`);
    console.log(`Needs Reconnection: ${connections.length - validTokens.length}`);
    
    if (validTokens.length > 0) {
      console.log('\n✅ Platforms Ready for Publishing:');
      validTokens.forEach(c => console.log(`  - ${c.platform}`));
    }
    
    if (connections.length > validTokens.length) {
      console.log('\n🔄 Platforms Needing Reconnection:');
      connections.filter(c => !c.oauthStatus?.isValid).forEach(c => {
        console.log(`  - ${c.platform}: ${c.oauthStatus?.error || 'Token invalid'}`);
      });
    }
    
  } catch (error) {
    console.error('❌ Connection test failed:', error.message);
  }
}

testConnectionStatus();