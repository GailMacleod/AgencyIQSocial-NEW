/**
 * Test Platform Connection Status Fix
 * Tests unified platform connection state across all components
 */

import fetch from 'node-fetch';

async function testConnectionStatusFix() {
  console.log('🧪 Testing Platform Connection Status Fix...\n');
  
  // Establish session
  const loginResponse = await fetch('http://localhost:5000/api/auth/login', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      phone: '+61424835189',
      password: 'gailm123'
    }),
  });

  const cookies = loginResponse.headers.get('set-cookie');
  const cookieHeader = cookies ? cookies.split(';')[0] : '';
  
  if (!cookieHeader) {
    console.error('❌ Failed to establish session');
    return;
  }

  console.log('✅ Session established successfully');

  // Test platform connections endpoint
  const connectionsResponse = await fetch('http://localhost:5000/api/platform-connections', {
    headers: {
      'Cookie': cookieHeader
    }
  });

  const connections = await connectionsResponse.json();
  console.log('\n📊 Platform Connections API Response:');
  console.log(`Total connections: ${connections.length}`);
  
  connections.forEach((conn, index) => {
    console.log(`\n${index + 1}. ${conn.platform.toUpperCase()}`);
    console.log(`   - Database Active: ${conn.isActive}`);
    console.log(`   - Platform User: ${conn.platformUsername}`);
    console.log(`   - Connected At: ${conn.connectedAt}`);
    
    if (conn.oauthStatus) {
      console.log(`   - OAuth Valid: ${conn.oauthStatus.isValid}`);
      console.log(`   - Needs Refresh: ${conn.oauthStatus.needsRefresh}`);
      if (conn.oauthStatus.error) {
        console.log(`   - OAuth Error: ${conn.oauthStatus.error}`);
      }
    } else {
      console.log(`   - OAuth Status: Not available`);
    }
  });

  // Test what useTokenValidation hook would see
  const tokenValidationData = connections
    .filter(conn => conn.oauthStatus)
    .map(conn => ({
      platform: conn.oauthStatus.platform,
      isValid: conn.oauthStatus.isValid,
      needsRefresh: conn.oauthStatus.needsRefresh,
      error: conn.oauthStatus.error
    }));

  console.log('\n🔍 Token Validation Hook Data:');
  console.log(`Valid tokens: ${tokenValidationData.filter(t => t.isValid).length}`);
  console.log(`Expired tokens: ${tokenValidationData.filter(t => !t.isValid).length}`);
  
  tokenValidationData.forEach(token => {
    console.log(`   - ${token.platform}: ${token.isValid ? 'Valid' : 'Expired'}`);
  });

  // Test what PlatformStatusWidget would see
  const platformStatusData = connections.map(conn => ({
    platform: conn.platform,
    connected: conn.isActive,
    status: conn.oauthStatus?.isValid ? 'healthy' : (conn.oauthStatus?.needsRefresh ? 'warning' : 'error')
  }));

  console.log('\n📱 Platform Status Widget Data:');
  console.log(`Connected platforms: ${platformStatusData.filter(p => p.connected).length}/${platformStatusData.length}`);
  
  platformStatusData.forEach(platform => {
    console.log(`   - ${platform.platform}: ${platform.connected ? 'Connected' : 'Disconnected'} (${platform.status})`);
  });

  // Test what connect-platforms.tsx would see
  const connectPlatformsData = connections.map(conn => ({
    platform: conn.platform,
    isActive: conn.isActive,
    platformUsername: conn.platformUsername
  }));

  console.log('\n🔗 Connect Platforms Page Data:');
  console.log(`Active connections: ${connectPlatformsData.filter(c => c.isActive).length}/${connectPlatformsData.length}`);
  
  connectPlatformsData.forEach(conn => {
    console.log(`   - ${conn.platform}: ${conn.isActive ? 'Active' : 'Inactive'} (${conn.platformUsername})`);
  });

  // Summary
  console.log('\n📋 SUMMARY:');
  console.log(`✅ Database Active Connections: ${connections.filter(c => c.isActive).length}/5`);
  console.log(`✅ OAuth Valid Connections: ${connections.filter(c => c.oauthStatus?.isValid).length}/5`);
  console.log(`✅ Data Consistency: ${connections.filter(c => c.isActive).length === connections.filter(c => c.oauthStatus?.isValid).length ? 'CONSISTENT' : 'INCONSISTENT'}`);
  
  console.log('\n🎯 All components should now show unified connection state!');
}

testConnectionStatusFix().catch(console.error);