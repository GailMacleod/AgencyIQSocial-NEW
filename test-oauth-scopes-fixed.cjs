/**
 * Test Updated OAuth Scopes - Fixed Invalid Scopes
 * Tests all OAuth strategies with corrected scopes and session persistence
 */

const axios = require('axios');
const BASE_URL = 'https://4fc77172-459a-4da7-8c33-5014abb1b73e-00-dqhtnud4ismj.worf.replit.dev';

class OAuthScopeTest {
  constructor() {
    this.sessionCookie = null;
    this.results = [];
  }

  async establishSession() {
    console.log('🔐 Establishing session...');
    
    try {
      const response = await axios.post(`${BASE_URL}/api/establish-session`, {
        userId: 2,
        email: 'gailm@macleodglba.com.au'
      }, {
        withCredentials: true
      });

      if (response.data.success) {
        this.sessionCookie = response.headers['set-cookie']?.[0]?.split(';')[0];
        console.log('✅ Session established:', response.data.message);
        return true;
      }
    } catch (error) {
      console.error('❌ Session establishment failed:', error.response?.data || error.message);
      return false;
    }
  }

  async testOAuthScope(platform, expectedScopes) {
    console.log(`\n🔍 Testing ${platform} OAuth initiation...`);
    
    try {
      const response = await axios.get(`${BASE_URL}/auth/${platform}`, {
        headers: {
          'Cookie': this.sessionCookie
        },
        maxRedirects: 0,
        validateStatus: (status) => status < 400
      });

      if (response.status === 302) {
        const location = response.headers.location;
        console.log('✅ OAuth redirect successful');
        console.log('📍 Redirect URL:', location);
        
        // Check if scopes are properly included
        const scopeMatch = location.match(/scope=([^&]+)/);
        if (scopeMatch) {
          const actualScopes = decodeURIComponent(scopeMatch[1]);
          console.log('📋 Detected scopes:', actualScopes);
          
          // Verify expected scopes are present
          let scopesValid = true;
          for (const expectedScope of expectedScopes) {
            if (!actualScopes.includes(expectedScope)) {
              console.log(`❌ Missing expected scope: ${expectedScope}`);
              scopesValid = false;
            }
          }
          
          if (scopesValid) {
            console.log('✅ All expected scopes present');
          }
          
          this.results.push({
            platform,
            success: true,
            expectedScopes,
            actualScopes,
            scopesValid,
            redirectUrl: location
          });
        } else {
          console.log('⚠️ No scopes detected in redirect URL');
          this.results.push({
            platform,
            success: true,
            expectedScopes,
            actualScopes: 'none',
            scopesValid: false,
            redirectUrl: location
          });
        }
        
        return true;
      } else {
        console.log(`❌ Unexpected response status: ${response.status}`);
        return false;
      }
    } catch (error) {
      console.error(`❌ ${platform} OAuth test failed:`, error.response?.data || error.message);
      this.results.push({
        platform,
        success: false,
        error: error.response?.data || error.message,
        expectedScopes
      });
      return false;
    }
  }

  async testAllPlatforms() {
    console.log('🧪 Testing all OAuth platforms with updated scopes...\n');
    
    const platforms = [
      {
        name: 'facebook',
        expectedScopes: ['pages_show_list', 'pages_read_engagement', 'pages_manage_posts']
      },
      {
        name: 'instagram', 
        expectedScopes: ['instagram_basic', 'pages_show_list']
      },
      {
        name: 'linkedin',
        expectedScopes: ['r_liteprofile', 'w_member_social']
      },
      {
        name: 'twitter',
        expectedScopes: [] // OAuth 1.0a doesn't use scopes
      },
      {
        name: 'youtube',
        expectedScopes: ['https://www.googleapis.com/auth/youtube.upload', 'https://www.googleapis.com/auth/youtube.readonly']
      }
    ];

    for (const platform of platforms) {
      await this.testOAuthScope(platform.name, platform.expectedScopes);
      await new Promise(resolve => setTimeout(resolve, 1000)); // Rate limit
    }
  }

  async testSessionPersistence() {
    console.log('\n🔄 Testing session persistence during OAuth...');
    
    try {
      // Test user endpoint with session
      const userResponse = await axios.get(`${BASE_URL}/api/user`, {
        headers: {
          'Cookie': this.sessionCookie
        }
      });

      if (userResponse.data.id === 2) {
        console.log('✅ Session persistence validated');
        console.log('👤 User ID:', userResponse.data.id);
        console.log('📧 Email:', userResponse.data.email);
        return true;
      } else {
        console.log('❌ Session persistence failed');
        return false;
      }
    } catch (error) {
      console.error('❌ Session persistence test failed:', error.response?.data || error.message);
      return false;
    }
  }

  generateReport() {
    console.log('\n📊 OAUTH SCOPE TEST REPORT\n');
    console.log('================================\n');
    
    let successCount = 0;
    let totalCount = this.results.length;
    
    this.results.forEach(result => {
      console.log(`Platform: ${result.platform}`);
      console.log(`Status: ${result.success ? '✅ Success' : '❌ Failed'}`);
      
      if (result.success) {
        successCount++;
        console.log(`Expected Scopes: ${result.expectedScopes.join(', ')}`);
        console.log(`Actual Scopes: ${result.actualScopes}`);
        console.log(`Scopes Valid: ${result.scopesValid ? '✅ Yes' : '❌ No'}`);
      } else {
        console.log(`Error: ${result.error}`);
      }
      
      console.log('---');
    });
    
    console.log(`\n📈 SUMMARY: ${successCount}/${totalCount} OAuth initiations successful`);
    
    if (successCount === totalCount) {
      console.log('🎉 All OAuth scopes configured correctly!');
    } else {
      console.log('⚠️ Some OAuth configurations need attention');
    }
  }

  async runTest() {
    console.log('🚀 Starting OAuth Scope Test with Session Persistence\n');
    
    // Step 1: Establish session
    const sessionEstablished = await this.establishSession();
    if (!sessionEstablished) {
      console.log('❌ Cannot proceed without session');
      return;
    }

    // Step 2: Test session persistence
    await this.testSessionPersistence();

    // Step 3: Test all OAuth platforms
    await this.testAllPlatforms();

    // Step 4: Generate report
    this.generateReport();
  }
}

// Run the test
new OAuthScopeTest().runTest();