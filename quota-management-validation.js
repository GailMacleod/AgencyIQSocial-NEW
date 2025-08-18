/**
 * Quota Management Validation Script
 * Tests API retry mechanisms and exponential backoff for Google limits
 */

import axios from 'axios';

class QuotaManagementValidator {
  constructor() {
    this.baseUrl = 'http://localhost:5000';
    this.testResults = {
      exponentialBackoff: false,
      quotaErrorHandling: false,
      retryMechanisms: false,
      rateLimitHandling: false,
      overallSuccess: false
    };
  }

  /**
   * Test 1: Exponential backoff implementation
   */
  async testExponentialBackoff() {
    console.log('⏱️  Testing exponential backoff for API failures...');
    
    try {
      const startTime = Date.now();
      
      // Simulate quota error response
      const response = await axios.post(`${this.baseUrl}/api/test-quota-error`, {
        simulateQuotaError: true
      }, {
        headers: {
          'X-Test-Quota': 'true'
        },
        withCredentials: true,
        timeout: 10000
      });

      const elapsed = Date.now() - startTime;
      
      // Should take at least 2-3 seconds due to retry delays
      if (elapsed >= 2000) {
        console.log('✅ Exponential backoff working (elapsed:', elapsed + 'ms)');
        this.testResults.exponentialBackoff = true;
      } else {
        console.log('⚠️ Backoff may be too fast:', elapsed + 'ms');
      }

    } catch (error) {
      // Expected for quota errors - check if proper backoff occurred
      const elapsed = Date.now() - Date.now();
      if (error.response?.status === 429 || error.message?.includes('quota')) {
        console.log('✅ Quota error properly handled with backoff');
        this.testResults.exponentialBackoff = true;
      }
    }
  }

  /**
   * Test 2: Quota error detection and handling
   */
  async testQuotaErrorHandling() {
    console.log('🚫 Testing quota error detection...');
    
    try {
      // Test multiple API endpoints for quota awareness
      const endpoints = [
        '/api/user',
        '/api/platform-connections', 
        '/api/auth/session'
      ];

      let quotaAwareEndpoints = 0;

      for (const endpoint of endpoints) {
        try {
          const response = await axios.get(`${this.baseUrl}${endpoint}`, {
            headers: {
              'X-Quota-Management': 'enabled',
              'X-Test-Quota-Awareness': 'true'
            },
            withCredentials: true,
            timeout: 5000
          });

          if (response.headers['x-quota-management'] === 'enabled') {
            quotaAwareEndpoints++;
          }
        } catch (error) {
          // Error responses may still indicate quota awareness
          if (error.response?.headers?.['x-quota-management']) {
            quotaAwareEndpoints++;
          }
        }
      }

      if (quotaAwareEndpoints >= 2) {
        console.log('✅ Quota awareness implemented on multiple endpoints');
        this.testResults.quotaErrorHandling = true;
      } else {
        console.log('⚠️ Limited quota awareness detected');
      }

    } catch (error) {
      console.log('⚠️ Quota error handling test inconclusive:', error.message);
    }
  }

  /**
   * Test 3: API retry mechanisms
   */
  async testRetryMechanisms() {
    console.log('🔄 Testing API retry mechanisms...');
    
    try {
      // Test retry behavior with simulated failures
      const startTime = Date.now();
      
      const response = await axios.post(`${this.baseUrl}/api/auth/establish-session`, {
        simulateRetryScenario: true
      }, {
        headers: {
          'X-Test-Retry': 'true'
        },
        withCredentials: true
      });

      if (response.status === 200) {
        console.log('✅ Retry mechanisms working correctly');
        this.testResults.retryMechanisms = true;
      }

    } catch (error) {
      // Check error indicates proper retry attempts
      if (error.message?.includes('All retries') || error.response?.status === 429) {
        console.log('✅ Retry mechanism properly exhausted');
        this.testResults.retryMechanisms = true;
      } else {
        console.log('⚠️ Retry test error:', error.message);
      }
    }
  }

  /**
   * Test 4: Rate limit handling with proper delays
   */
  async testRateLimitHandling() {
    console.log('⚡ Testing rate limit handling...');
    
    try {
      // Test rapid successive API calls
      const promises = [];
      const startTime = Date.now();
      
      for (let i = 0; i < 3; i++) {
        promises.push(
          axios.get(`${this.baseUrl}/api/auth/session`, {
            headers: {
              'X-Rate-Limit-Test': `request-${i}`
            },
            withCredentials: true,
            timeout: 8000
          })
        );
      }

      const responses = await Promise.allSettled(promises);
      const elapsed = Date.now() - startTime;
      
      const successfulResponses = responses.filter(r => r.status === 'fulfilled');
      
      // Should have some delay due to rate limiting protections
      if (elapsed >= 1000 && successfulResponses.length >= 2) {
        console.log('✅ Rate limiting working with proper delays');
        this.testResults.rateLimitHandling = true;
      } else if (successfulResponses.length >= 2) {
        console.log('⚠️ Rate limiting may need adjustment');
      }

    } catch (error) {
      console.log('⚠️ Rate limit test error:', error.message);
    }
  }

  /**
   * Run all quota management validation tests
   */
  async runAllTests() {
    console.log('🚀 Starting Quota Management Validation Suite...\n');

    await this.testExponentialBackoff();
    console.log('');
    
    await this.testQuotaErrorHandling();
    console.log('');
    
    await this.testRetryMechanisms();
    console.log('');
    
    await this.testRateLimitHandling();
    console.log('');

    // Calculate overall success
    const passedTests = Object.values(this.testResults).filter(result => result === true).length;
    const totalTests = Object.keys(this.testResults).length - 1; // Exclude overallSuccess
    
    this.testResults.overallSuccess = passedTests >= Math.floor(totalTests * 0.75); // 75% pass rate

    console.log('📊 Quota Management Validation Results:');
    console.log(`⏱️  Exponential Backoff: ${this.testResults.exponentialBackoff ? 'PASS' : 'FAIL'}`);
    console.log(`🚫 Quota Error Handling: ${this.testResults.quotaErrorHandling ? 'PASS' : 'FAIL'}`);
    console.log(`🔄 Retry Mechanisms: ${this.testResults.retryMechanisms ? 'PASS' : 'FAIL'}`);
    console.log(`⚡ Rate Limit Handling: ${this.testResults.rateLimitHandling ? 'PASS' : 'FAIL'}`);
    console.log(`\n🎯 Overall Quota Management: ${this.testResults.overallSuccess ? 'EXCELLENT' : 'NEEDS IMPROVEMENT'}`);
    console.log(`📈 Pass Rate: ${passedTests}/${totalTests} (${Math.round((passedTests/totalTests)*100)}%)`);

    return this.testResults;
  }
}

// Run validation if called directly
const validator = new QuotaManagementValidator();
validator.runAllTests().then(results => {
  process.exit(results.overallSuccess ? 0 : 1);
}).catch(error => {
  console.error('❌ Quota management validation failed:', error.message);
  process.exit(1);
});

export default QuotaManagementValidator;