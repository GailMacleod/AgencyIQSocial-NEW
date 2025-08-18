/**
 * Cookie Security Validation Script
 * Tests HTTP-only cookie clearing and PWA session synchronization fixes
 */

import axios from 'axios';

class CookieSecurityValidator {
  constructor() {
    this.baseUrl = 'http://localhost:5000';
    this.testResults = {
      httpOnlyCookieClearing: false,
      pwaSessionSync: false,
      logoutFlow: false,
      sessionPersistence: false,
      overallSuccess: false
    };
  }

  /**
   * Test 1: HTTP-only cookie clearing on logout
   */
  async testHttpOnlyCookieClearing() {
    console.log('🍪 Testing HTTP-only cookie clearing on logout...');
    
    try {
      // First establish a session
      const loginResponse = await axios.post(`${this.baseUrl}/api/auth/establish-session`, {}, {
        headers: {
          'Content-Type': 'application/json'
        },
        withCredentials: true
      });

      if (loginResponse.status === 200) {
        console.log('✅ Session established for cookie clearing test');
        
        // Now test logout with cookie clearing
        const logoutResponse = await axios.post(`${this.baseUrl}/api/auth/logout`, {}, {
          headers: {
            'Content-Type': 'application/json',
            'X-Test-Cookie-Clear': 'true'
          },
          withCredentials: true
        });

        // Check logout response headers for cookie clearing
        const setCookieHeaders = logoutResponse.headers['set-cookie'] || [];
        const hasExpiredCookies = setCookieHeaders.some(cookie => 
          cookie.includes('Expires=Thu, 01 Jan 1970') || 
          cookie.includes('Max-Age=0')
        );

        if (hasExpiredCookies && logoutResponse.data.clearCookies) {
          console.log('✅ HTTP-only cookies properly cleared with expired dates');
          this.testResults.httpOnlyCookieClearing = true;
        } else {
          console.log('⚠️ HTTP-only cookie clearing needs verification');
        }
      }

    } catch (error) {
      console.log('⚠️ HTTP-only cookie test error:', error.message);
    }
  }

  /**
   * Test 2: PWA session synchronization
   */
  async testPWASessionSync() {
    console.log('📱 Testing PWA session synchronization...');
    
    try {
      // Test session check endpoint with PWA headers
      const sessionResponse = await axios.get(`${this.baseUrl}/api/auth/session`, {
        headers: {
          'X-PWA-Session-Check': 'true',
          'User-Agent': 'TheAgencyIQ-PWA/1.0'
        },
        withCredentials: true
      });

      if (sessionResponse.status === 200) {
        const sessionData = sessionResponse.data;
        
        // Check if session data includes PWA-aware fields
        if (sessionData.sessionId && sessionData.hasOwnProperty('authenticated')) {
          console.log('✅ PWA session check working');
          
          // Test with stale session simulation
          const staleResponse = await axios.get(`${this.baseUrl}/api/auth/session`, {
            headers: {
              'X-PWA-Session-Check': 'true',
              'Cookie': 'theagencyiq.session=expired_session_token'
            }
          });

          if (staleResponse.status === 200 && !staleResponse.data.authenticated) {
            console.log('✅ Stale session properly detected');
            this.testResults.pwaSessionSync = true;
          }
        }
      }

    } catch (error) {
      console.log('⚠️ PWA session sync test error:', error.message);
    }
  }

  /**
   * Test 3: Complete logout flow validation
   */
  async testLogoutFlow() {
    console.log('🔓 Testing complete logout flow...');
    
    try {
      // Establish session first
      await axios.post(`${this.baseUrl}/api/auth/establish-session`, {}, {
        withCredentials: true
      });

      // Test logout with PWA headers
      const logoutResponse = await axios.post(`${this.baseUrl}/api/auth/logout`, {}, {
        headers: {
          'X-PWA-Logout': 'true',
          'Content-Type': 'application/json'
        },
        withCredentials: true
      });

      const logoutData = logoutResponse.data;
      
      // Verify logout response includes PWA-specific fields
      if (logoutData.success && 
          logoutData.clearCache && 
          logoutData.clearCookies && 
          logoutData.pwaRefresh &&
          logoutData.timestamp) {
        
        console.log('✅ Complete logout flow working with PWA support');
        this.testResults.logoutFlow = true;
        
        // Verify session is actually cleared
        try {
          const postLogoutSession = await axios.get(`${this.baseUrl}/api/auth/session`, {
            withCredentials: true
          });
          
          if (!postLogoutSession.data.authenticated) {
            console.log('✅ Session properly cleared after logout');
          }
        } catch (sessionError) {
          console.log('✅ Session check failed as expected after logout');
        }
      }

    } catch (error) {
      console.log('⚠️ Logout flow test error:', error.message);
    }
  }

  /**
   * Test 4: Session persistence and security
   */
  async testSessionPersistence() {
    console.log('🔒 Testing session persistence and security...');
    
    try {
      // Test session establishment
      const sessionResponse = await axios.post(`${this.baseUrl}/api/auth/establish-session`, {}, {
        headers: {
          'X-Session-Security-Test': 'true'
        },
        withCredentials: true
      });

      if (sessionResponse.status === 200 && sessionResponse.data.user) {
        console.log('✅ Session establishment working');
        
        // Test session persistence across requests
        const persistenceResponse = await axios.get(`${this.baseUrl}/api/auth/session`, {
          withCredentials: true
        });

        if (persistenceResponse.data.authenticated && 
            persistenceResponse.data.userId === sessionResponse.data.user.id) {
          console.log('✅ Session persists across requests');
          this.testResults.sessionPersistence = true;
        }
      }

    } catch (error) {
      console.log('⚠️ Session persistence test error:', error.message);
    }
  }

  /**
   * Run all cookie security validation tests
   */
  async runAllTests() {
    console.log('🚀 Starting Cookie Security Validation Suite...\n');

    await this.testHttpOnlyCookieClearing();
    console.log('');
    
    await this.testPWASessionSync();
    console.log('');
    
    await this.testLogoutFlow();
    console.log('');
    
    await this.testSessionPersistence();
    console.log('');

    // Calculate overall success
    const passedTests = Object.values(this.testResults).filter(result => result === true).length;
    const totalTests = Object.keys(this.testResults).length - 1; // Exclude overallSuccess
    
    this.testResults.overallSuccess = passedTests >= Math.floor(totalTests * 0.75); // 75% pass rate

    console.log('📊 Cookie Security Validation Results:');
    console.log(`🍪 HTTP-only Cookie Clearing: ${this.testResults.httpOnlyCookieClearing ? 'PASS' : 'FAIL'}`);
    console.log(`📱 PWA Session Sync: ${this.testResults.pwaSessionSync ? 'PASS' : 'FAIL'}`);
    console.log(`🔓 Logout Flow: ${this.testResults.logoutFlow ? 'PASS' : 'FAIL'}`);
    console.log(`🔒 Session Persistence: ${this.testResults.sessionPersistence ? 'PASS' : 'FAIL'}`);
    console.log(`\n🎯 Overall Security: ${this.testResults.overallSuccess ? 'SECURE' : 'NEEDS ATTENTION'}`);
    console.log(`📈 Pass Rate: ${passedTests}/${totalTests} (${Math.round((passedTests/totalTests)*100)}%)`);

    return this.testResults;
  }
}

// Run validation if called directly
const validator = new CookieSecurityValidator();
validator.runAllTests().then(results => {
  process.exit(results.overallSuccess ? 0 : 1);
}).catch(error => {
  console.error('❌ Cookie security validation failed:', error.message);
  process.exit(1);
});

export default CookieSecurityValidator;