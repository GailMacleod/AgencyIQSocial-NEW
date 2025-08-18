/**
 * Test OAuth System After Cleanup
 * Tests the simplified OAuth implementation using only Passport.js strategies
 */

import axios from 'axios';
import tough from 'tough-cookie';

const BASE_URL = 'https://4fc77172-459a-4da7-8c33-5014abb1b73e-00-dqhtnud4ismj.worf.replit.dev';

class OAuthCleanupTest {
  constructor() {
    this.cookieJar = new tough.CookieJar();
    this.sessionCookie = null;
    this.results = [];
  }

  async establishSession() {
    try {
      const response = await axios.post(`${BASE_URL}/api/establish-session`, {
        email: 'gailm@macleodglba.com.au'
      });
      
      console.log('✅ Session established:', response.data.success);
      this.sessionCookie = response.headers['set-cookie']?.[0];
      return true;
    } catch (error) {
      console.error('❌ Session establishment failed:', error.response?.data || error.message);
      return false;
    }
  }

  async testOAuthEndpoints() {
    console.log('\n🔍 Testing OAuth endpoints with Passport.js strategies...');
    
    const platforms = ['facebook', 'instagram', 'linkedin', 'x', 'youtube'];
    const results = [];
    
    for (const platform of platforms) {
      try {
        const response = await axios.get(`${BASE_URL}/api/auth/${platform}`, {
          headers: {
            Cookie: this.sessionCookie
          },
          maxRedirects: 0,
          validateStatus: (status) => status < 400
        });
        
        if (response.status === 302) {
          const redirectUrl = response.headers.location;
          console.log(`✅ ${platform}: OAuth redirect successful`);
          console.log(`   Redirect URL: ${redirectUrl}`);
          results.push({ platform, status: 'success', redirectUrl });
        } else {
          console.log(`⚠️ ${platform}: Unexpected response status ${response.status}`);
          results.push({ platform, status: 'unexpected', statusCode: response.status });
        }
      } catch (error) {
        console.log(`❌ ${platform}: OAuth failed - ${error.response?.status || error.message}`);
        results.push({ platform, status: 'failed', error: error.response?.data || error.message });
      }
    }
    
    return results;
  }

  async testPlatformConnections() {
    try {
      const response = await axios.get(`${BASE_URL}/api/platform-connections`, {
        headers: {
          Cookie: this.sessionCookie
        }
      });
      
      console.log('\n📊 Current platform connections:', response.data.length);
      response.data.forEach(conn => {
        console.log(`   ${conn.platform}: ${conn.isActive ? 'Active' : 'Inactive'} (${conn.platformUsername})`);
      });
      
      return response.data;
    } catch (error) {
      console.error('❌ Platform connections fetch failed:', error.response?.data || error.message);
      return [];
    }
  }

  async runTest() {
    console.log('🧪 OAUTH CLEANUP TEST - Testing Passport.js only implementation\n');
    
    // Step 1: Establish session
    const sessionSuccess = await this.establishSession();
    if (!sessionSuccess) {
      console.log('❌ Test failed: Could not establish session');
      return;
    }
    
    // Step 2: Test OAuth endpoints
    const oauthResults = await this.testOAuthEndpoints();
    
    // Step 3: Test platform connections
    const connections = await this.testPlatformConnections();
    
    // Step 4: Generate report
    console.log('\n📋 OAUTH CLEANUP TEST RESULTS:');
    console.log('=====================================');
    
    const successful = oauthResults.filter(r => r.status === 'success');
    const failed = oauthResults.filter(r => r.status === 'failed');
    
    console.log(`✅ Successful OAuth endpoints: ${successful.length}/5`);
    console.log(`❌ Failed OAuth endpoints: ${failed.length}/5`);
    console.log(`📊 Current platform connections: ${connections.length}`);
    
    if (successful.length === 5) {
      console.log('\n🎉 ALL OAUTH ENDPOINTS WORKING - Passport.js cleanup successful!');
    } else {
      console.log('\n⚠️ Some OAuth endpoints need attention:');
      failed.forEach(f => console.log(`   - ${f.platform}: ${f.error}`));
    }
    
    return {
      success: successful.length === 5,
      oauthResults,
      connections,
      summary: {
        successful: successful.length,
        failed: failed.length,
        totalConnections: connections.length
      }
    };
  }
}

// Run the test
const test = new OAuthCleanupTest();
test.runTest().then(result => {
  console.log('\n✅ OAuth cleanup test completed');
  process.exit(result.success ? 0 : 1);
}).catch(error => {
  console.error('❌ Test execution failed:', error);
  process.exit(1);
});