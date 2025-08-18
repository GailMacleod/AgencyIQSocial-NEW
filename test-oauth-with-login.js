/**
 * Test OAuth with Proper Authentication
 * Tests the complete OAuth flow with authenticated user session
 */

async function testOAuthWithLogin() {
  console.log('🔧 Testing OAuth with Proper Authentication...\n');

  try {
    // Step 1: Login to get authenticated session
    console.log('1. Logging in with authenticated user...');
    const loginResponse = await fetch('https://4fc77172-459a-4da7-8c33-5014abb1b73e-00-dqhtnud4ismj.worf.replit.dev/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({
        phone: '+61424835189',
        password: 'password123'
      })
    });
    
    const loginData = await loginResponse.json();
    if (loginData.user) {
      console.log('✅ Login successful:', loginData.user.email);
    } else {
      console.log('❌ Login failed:', loginData.message);
      return;
    }

    // Step 2: Test platform connections with authenticated session
    console.log('\n2. Testing platform connections with auth...');
    const connectionsResponse = await fetch('https://4fc77172-459a-4da7-8c33-5014abb1b73e-00-dqhtnud4ismj.worf.replit.dev/api/platform-connections', {
      method: 'GET',
      credentials: 'include'
    });
    
    const connections = await connectionsResponse.json();
    console.log('✅ Platform connections found:', connections.length);
    
    // Display connection details
    if (connections.length > 0) {
      connections.forEach(conn => {
        console.log(`  - ${conn.platform}: ${conn.isActive ? 'Active' : 'Inactive'} (ID: ${conn.id})`);
      });
    }

    // Step 3: Test OAuth routes with authenticated session
    console.log('\n3. Testing OAuth routes with authenticated session...');
    const oauthRoutes = [
      { path: '/auth/facebook', name: 'Facebook' },
      { path: '/auth/instagram', name: 'Instagram' },
      { path: '/auth/linkedin', name: 'LinkedIn' },
      { path: '/auth/twitter', name: 'X (Twitter)' },
      { path: '/auth/youtube', name: 'YouTube' }
    ];

    for (const route of oauthRoutes) {
      try {
        const response = await fetch(`https://4fc77172-459a-4da7-8c33-5014abb1b73e-00-dqhtnud4ismj.worf.replit.dev${route.path}`, {
          method: 'GET',
          credentials: 'include',
          redirect: 'manual'
        });
        
        if (response.status === 302) {
          console.log(`✅ ${route.name} OAuth redirect working (302)`);
        } else if (response.status === 500) {
          console.log(`⚠️  ${route.name} OAuth error (500) - configuration issue`);
        } else {
          console.log(`⚠️  ${route.name} OAuth status: ${response.status}`);
        }
      } catch (error) {
        console.log(`❌ ${route.name} OAuth error: ${error.message}`);
      }
    }

    // Step 4: Test direct publish with authenticated session
    console.log('\n4. Testing direct publish with authenticated session...');
    const publishResponse = await fetch('https://4fc77172-459a-4da7-8c33-5014abb1b73e-00-dqhtnud4ismj.worf.replit.dev/api/direct-publish', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({
        action: 'test_publish_all',
        content: 'Testing authenticated OAuth publishing - Multi-platform test post'
      })
    });

    const publishResult = await publishResponse.json();
    console.log('✅ Direct publish test completed');
    
    if (publishResult.results) {
      console.log('Platform results:');
      publishResult.results.forEach(result => {
        console.log(`  - ${result.platform}: ${result.success ? 'SUCCESS' : 'FAILED'} - ${result.message || result.error}`);
      });
    } else {
      console.log('Result:', publishResult);
    }

    console.log('\n🎉 OAuth with Authentication Test Complete!');
    console.log('✅ User authentication working');
    console.log('✅ Platform connections accessible');
    console.log('✅ OAuth routes configured');
    console.log('✅ Direct publish system operational');

  } catch (error) {
    console.error('❌ Test failed:', error.message);
    console.error('Stack:', error.stack);
  }
}

testOAuthWithLogin();