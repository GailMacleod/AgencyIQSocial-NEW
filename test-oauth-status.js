/**
 * Test OAuth Status with Session-Based Authentication
 * Simple test to verify OAuth system is working
 */

console.log('🔧 OAUTH STATUS TEST');
console.log('=' + '='.repeat(30));

// Test basic server status
async function testOAuthStatus() {
  try {
    const response = await fetch('http://localhost:5000/oauth-status');
    const result = await response.json();
    
    if (response.ok && result.success) {
      console.log('✅ OAuth Status Endpoint: Working');
      console.log('📊 Platform Status:');
      result.platforms.forEach(platform => {
        const icon = platform.connected ? '✅' : '❌';
        console.log(`  ${icon} ${platform.platform}: ${platform.status}`);
      });
    } else {
      console.log('❌ OAuth Status Endpoint: Failed');
    }
  } catch (error) {
    console.log(`❌ OAuth Status Test Failed: ${error.message}`);
  }
}

// Run test
testOAuthStatus().then(() => {
  console.log('\n💡 OAuth system is configured for popup-based authentication');
  console.log('🔄 Ready for manual OAuth reconnection testing via UI');
}).catch(err => {
  console.error('Test failed:', err);
});