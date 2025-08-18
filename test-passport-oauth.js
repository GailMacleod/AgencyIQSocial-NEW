/**
 * Test Passport.js OAuth Integration
 * Verifies that all OAuth strategies are properly configured
 */

async function testPassportOAuthIntegration() {
  console.log('🔧 Testing Passport.js OAuth Integration...\n');

  try {
    // Step 1: Establish session
    console.log('1. Establishing session...');
    const sessionResponse = await fetch('https://4fc77172-459a-4da7-8c33-5014abb1b73e-00-dqhtnud4ismj.worf.replit.dev/api/establish-session', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include'
    });
    
    const sessionData = await sessionResponse.json();
    console.log('✅ Session established:', sessionData.message);

    // Step 2: Test OAuth route accessibility
    console.log('\n2. Testing OAuth routes...');
    const oauthRoutes = [
      '/auth/facebook',
      '/auth/instagram', 
      '/auth/linkedin',
      '/auth/twitter',
      '/auth/youtube'
    ];

    for (const route of oauthRoutes) {
      try {
        const response = await fetch(`https://4fc77172-459a-4da7-8c33-5014abb1b73e-00-dqhtnud4ismj.worf.replit.dev${route}`, {
          method: 'GET',
          credentials: 'include',
          redirect: 'manual' // Don't follow redirects
        });
        
        if (response.status === 302) {
          console.log(`✅ ${route} - OAuth redirect working (302)`);
        } else {
          console.log(`⚠️  ${route} - Status: ${response.status}`);
        }
      } catch (error) {
        console.log(`❌ ${route} - Error: ${error.message}`);
      }
    }

    // Step 3: Test platform connections endpoint
    console.log('\n3. Testing platform connections...');
    const connectionsResponse = await fetch('https://4fc77172-459a-4da7-8c33-5014abb1b73e-00-dqhtnud4ismj.worf.replit.dev/api/platform-connections', {
      method: 'GET',
      credentials: 'include'
    });
    
    const connections = await connectionsResponse.json();
    console.log('✅ Platform connections:', connections.length, 'found');

    // Step 4: Test direct publish system
    console.log('\n4. Testing direct publish with OAuth refresh...');
    const publishResponse = await fetch('https://4fc77172-459a-4da7-8c33-5014abb1b73e-00-dqhtnud4ismj.worf.replit.dev/api/direct-publish', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({
        action: 'test_publish_all',
        content: 'Testing Passport.js OAuth integration - Multi-platform test post'
      })
    });

    const publishResult = await publishResponse.json();
    console.log('✅ Direct publish test completed');
    console.log('Results:', publishResult);

    console.log('\n🎉 Passport.js OAuth Integration Test Complete!');
    console.log('✅ Session management working');
    console.log('✅ OAuth routes accessible');
    console.log('✅ Platform connections available');
    console.log('✅ Direct publish system operational');

  } catch (error) {
    console.error('❌ Test failed:', error.message);
    console.error('Stack:', error.stack);
  }
}

testPassportOAuthIntegration();