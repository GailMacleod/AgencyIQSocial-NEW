/**
 * Test Login Flow - Validate Session Authentication
 * Tests the complete login flow and session persistence
 */

import fetch from 'node-fetch';

async function testLoginFlow() {
  const baseUrl = 'http://localhost:5000';
  
  console.log('🔐 Testing Login Flow and Session Persistence...\n');
  
  // Test 1: Login with User ID 2 credentials
  console.log('📋 Test 1: Login Authentication');
  try {
    const loginResponse = await fetch(`${baseUrl}/api/auth/login`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'User-Agent': 'Test-Agent'
      },
      body: JSON.stringify({
        phone: '+61424835189',
        password: 'password123'
      })
    });
    
    console.log(`   Status: ${loginResponse.status}`);
    const loginData = await loginResponse.json();
    console.log(`   Response:`, loginData);
    
    if (loginResponse.ok && loginData.success) {
      console.log(`   ✅ Login successful for ${loginData.user.email}`);
      
      // Extract session cookie
      const setCookieHeader = loginResponse.headers.get('set-cookie');
      const sessionCookie = setCookieHeader ? setCookieHeader.split(';')[0] : null;
      
      if (sessionCookie) {
        console.log(`   📝 Session cookie: ${sessionCookie}`);
        
        // Test 2: Validate session with /api/user-status
        console.log('\n📋 Test 2: Session Validation');
        const statusResponse = await fetch(`${baseUrl}/api/user-status`, {
          method: 'GET',
          headers: {
            'Cookie': sessionCookie,
            'User-Agent': 'Test-Agent'
          }
        });
        
        console.log(`   Status: ${statusResponse.status}`);
        const statusData = await statusResponse.json();
        console.log(`   Response:`, statusData);
        
        if (statusResponse.ok && statusData.authenticated) {
          console.log(`   ✅ Session validation successful for ${statusData.user.email}`);
          
          // Test 3: Test platform connections endpoint
          console.log('\n📋 Test 3: Platform Connections Access');
          const connectionsResponse = await fetch(`${baseUrl}/api/platform-connections`, {
            method: 'GET',
            headers: {
              'Cookie': sessionCookie,
              'User-Agent': 'Test-Agent'
            }
          });
          
          console.log(`   Status: ${connectionsResponse.status}`);
          const connectionsData = await connectionsResponse.json();
          console.log(`   Response:`, connectionsData);
          
          if (connectionsResponse.ok) {
            console.log(`   ✅ Platform connections access successful`);
            console.log(`   📊 Active connections: ${connectionsData.connections?.length || 0}`);
          } else {
            console.log(`   ❌ Platform connections access failed`);
          }
          
        } else {
          console.log(`   ❌ Session validation failed: ${statusData.message}`);
        }
      } else {
        console.log(`   ⚠️  No session cookie received`);
      }
    } else {
      console.log(`   ❌ Login failed: ${loginData.message}`);
    }
  } catch (error) {
    console.error('❌ Login test error:', error.message);
  }
  
  // Test 4: Test authentication requirement (no cookie)
  console.log('\n📋 Test 4: Authentication Requirement Check');
  try {
    const unauthResponse = await fetch(`${baseUrl}/api/user-status`, {
      method: 'GET',
      headers: {
        'User-Agent': 'Test-Agent'
      }
    });
    
    console.log(`   Status: ${unauthResponse.status}`);
    const unauthData = await unauthResponse.json();
    console.log(`   Response:`, unauthData);
    
    if (unauthResponse.status === 401 && !unauthData.authenticated) {
      console.log(`   ✅ Authentication requirement working correctly`);
    } else {
      console.log(`   ❌ Authentication requirement failed`);
    }
  } catch (error) {
    console.error('❌ Unauthenticated test error:', error.message);
  }
  
  console.log('\n🎯 Login Flow Test Complete');
}

// Run the test
testLoginFlow().catch(console.error);