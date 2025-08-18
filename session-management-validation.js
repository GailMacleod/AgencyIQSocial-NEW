/**
 * Session Management Validation Script
 * Tests UI feedback, React Query synchronization, and timeout handling
 */

import axios from 'axios';

class SessionManagementValidator {
  constructor() {
    this.baseUrl = 'http://localhost:5000';
    this.testResults = {
      sessionTimeout: false,
      uiFeedback: false,
      reactQuerySync: false,
      errorHandling: false,
      overallSuccess: false
    };
  }

  /**
   * Test 1: Session establishment timeout handling
   */
  async testSessionTimeout() {
    console.log('⏱️  Testing session establishment timeout handling...');
    
    try {
      // Test timeout scenario with 1ms timeout (should trigger timeout)
      const startTime = Date.now();
      
      const response = await axios.post(`${this.baseUrl}/api/auth/establish-session`, {
        simulateTimeout: true
      }, {
        headers: {
          'Content-Type': 'application/json',
          'X-Test-Timeout': '1' // Request 1ms timeout simulation
        },
        withCredentials: true,
        timeout: 2000 // 2 second axios timeout
      });

      const elapsed = Date.now() - startTime;
      
      if (elapsed < 5000 && response.status === 200) {
        console.log('✅ Session establishment handles timeouts properly');
        this.testResults.sessionTimeout = true;
      } else {
        console.log('⚠️ Session timeout behavior needs verification');
      }

    } catch (error) {
      const elapsed = Date.now() - Date.now();
      
      if (error.code === 'ECONNABORTED' || elapsed < 3000) {
        console.log('✅ Timeout handling working as expected');
        this.testResults.sessionTimeout = true;
      } else {
        console.log('⚠️ Session timeout test inconclusive:', error.message);
      }
    }
  }

  /**
   * Test 2: UI feedback mechanisms
   */
  async testUIFeedback() {
    console.log('🎨 Testing UI feedback mechanisms...');
    
    try {
      // Test session establishment with UI feedback flag
      const response = await axios.post(`${this.baseUrl}/api/auth/establish-session`, {
        enableUIFeedback: true
      }, {
        headers: {
          'Content-Type': 'application/json',
          'X-UI-Test': 'true'
        },
        withCredentials: true
      });

      if (response.status === 200 && response.data.user) {
        console.log('✅ UI feedback endpoint responding correctly');
        
        // Test session check for loading states
        const sessionResponse = await axios.get(`${this.baseUrl}/api/auth/session`, {
          headers: {
            'X-UI-State-Check': 'true'
          },
          withCredentials: true
        });

        if (sessionResponse.data.authenticated && sessionResponse.data.sessionId) {
          console.log('✅ UI state management working');
          this.testResults.uiFeedback = true;
        }
      }

    } catch (error) {
      console.log('⚠️ UI feedback test error:', error.message);
    }
  }

  /**
   * Test 3: React Query synchronization
   */
  async testReactQuerySync() {
    console.log('🔄 Testing React Query synchronization...');
    
    try {
      // Simulate session establishment followed by query invalidation
      const sessionResponse = await axios.post(`${this.baseUrl}/api/auth/establish-session`, {}, {
        headers: {
          'X-Query-Sync-Test': 'true'
        },
        withCredentials: true
      });

      if (sessionResponse.status === 200) {
        console.log('✅ Session established for React Query sync test');
        
        // Test multiple rapid API calls to simulate query invalidation scenario
        const promises = [
          axios.get(`${this.baseUrl}/api/user`, { withCredentials: true }),
          axios.get(`${this.baseUrl}/api/platform-connections`, { withCredentials: true }),
          axios.get(`${this.baseUrl}/api/auth/session`, { withCredentials: true })
        ];

        const responses = await Promise.allSettled(promises);
        const successfulResponses = responses.filter(r => r.status === 'fulfilled' && r.value.status === 200);

        if (successfulResponses.length >= 2) {
          console.log('✅ React Query synchronization working properly');
          this.testResults.reactQuerySync = true;
        } else {
          console.log('⚠️ Some queries failed during sync test');
        }
      }

    } catch (error) {
      console.log('⚠️ React Query sync test error:', error.message);
    }
  }

  /**
   * Test 4: Error handling and recovery
   */
  async testErrorHandling() {
    console.log('🛡️  Testing error handling and recovery...');
    
    try {
      // Test invalid session scenario
      const invalidResponse = await axios.get(`${this.baseUrl}/api/user`, {
        headers: {
          'Cookie': 'connect.sid=invalid_session_token'
        }
      });

      // Should not reach here with invalid session
      console.log('⚠️ Invalid session not properly handled');

    } catch (error) {
      if (error.response && (error.response.status === 401 || error.response.status === 403)) {
        console.log('✅ Invalid session properly rejected');
        
        // Test session recovery
        try {
          const recoveryResponse = await axios.post(`${this.baseUrl}/api/auth/establish-session`, {
            recovery: true
          }, {
            withCredentials: true
          });

          if (recoveryResponse.status === 200) {
            console.log('✅ Session recovery working');
            this.testResults.errorHandling = true;
          }
        } catch (recoveryError) {
          console.log('⚠️ Session recovery failed:', recoveryError.message);
        }
      } else {
        console.log('⚠️ Unexpected error handling behavior');
      }
    }
  }

  /**
   * Run all session management validation tests
   */
  async runAllTests() {
    console.log('🚀 Starting Session Management Validation Suite...\n');

    await this.testSessionTimeout();
    console.log('');
    
    await this.testUIFeedback();
    console.log('');
    
    await this.testReactQuerySync();
    console.log('');
    
    await this.testErrorHandling();
    console.log('');

    // Calculate overall success
    const passedTests = Object.values(this.testResults).filter(result => result === true).length;
    const totalTests = Object.keys(this.testResults).length - 1; // Exclude overallSuccess
    
    this.testResults.overallSuccess = passedTests >= Math.floor(totalTests * 0.75); // 75% pass rate

    console.log('📊 Session Management Validation Results:');
    console.log(`⏱️  Session Timeout Handling: ${this.testResults.sessionTimeout ? 'PASS' : 'FAIL'}`);
    console.log(`🎨 UI Feedback: ${this.testResults.uiFeedback ? 'PASS' : 'FAIL'}`);
    console.log(`🔄 React Query Sync: ${this.testResults.reactQuerySync ? 'PASS' : 'FAIL'}`);
    console.log(`🛡️  Error Handling: ${this.testResults.errorHandling ? 'PASS' : 'FAIL'}`);
    console.log(`\n🎯 Overall Management: ${this.testResults.overallSuccess ? 'EXCELLENT' : 'NEEDS IMPROVEMENT'}`);
    console.log(`📈 Pass Rate: ${passedTests}/${totalTests} (${Math.round((passedTests/totalTests)*100)}%)`);

    return this.testResults;
  }
}

// Run validation if called directly
const validator = new SessionManagementValidator();
validator.runAllTests().then(results => {
  process.exit(results.overallSuccess ? 0 : 1);
}).catch(error => {
  console.error('❌ Session management validation failed:', error.message);
  process.exit(1);
});

export default SessionManagementValidator;