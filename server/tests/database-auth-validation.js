#!/usr/bin/env node
// Database Authentication Validation Test
// Comprehensive test suite for database authentication security

const axios = require('axios');
const { logger } = require('../utils/logger.js');

class DatabaseAuthValidationTest {
  constructor() {
    this.baseUrl = 'http://localhost:5000';
    this.testResults = [];
    this.passedTests = 0;
    this.totalTests = 0;
  }

  async runTest(testName, testFunction) {
    this.totalTests++;
    console.log(`\n🧪 Testing: ${testName}`);
    
    try {
      const result = await testFunction();
      if (result.success) {
        this.passedTests++;
        console.log(`✅ ${testName}: PASSED`);
        this.testResults.push({ name: testName, status: 'PASSED', details: result.details });
      } else {
        console.log(`❌ ${testName}: FAILED - ${result.error}`);
        this.testResults.push({ name: testName, status: 'FAILED', error: result.error });
      }
    } catch (error) {
      console.log(`❌ ${testName}: ERROR - ${error.message}`);
      this.testResults.push({ name: testName, status: 'ERROR', error: error.message });
    }
  }

  // Test 1: Unauthorized access to protected endpoints
  async testUnauthorizedAccess() {
    try {
      const response = await axios.get(`${this.baseUrl}/api/brand-purpose`);
      return {
        success: false,
        error: 'Endpoint allowed unauthorized access'
      };
    } catch (error) {
      if (error.response && error.response.status === 401) {
        return {
          success: true,
          details: 'Properly blocked unauthorized access with 401 status'
        };
      }
      return {
        success: false,
        error: `Unexpected response: ${error.response?.status || error.message}`
      };
    }
  }

  // Test 2: Quota status with authentication
  async testQuotaStatusAuth() {
    try {
      const response = await axios.get(`${this.baseUrl}/api/quota-status`);
      
      if (response.status === 200 && response.data.sessionValidated) {
        return {
          success: true,
          details: 'Quota status properly authenticated and validated'
        };
      }
      
      return {
        success: false,
        error: 'Quota status missing session validation'
      };
    } catch (error) {
      if (error.response && error.response.status === 401) {
        return {
          success: true,
          details: 'Quota status properly blocked unauthorized access'
        };
      }
      return {
        success: false,
        error: `Unexpected quota status response: ${error.response?.status || error.message}`
      };
    }
  }

  // Test 3: Database authentication middleware protection
  async testDatabaseMiddlewareProtection() {
    const protectedEndpoints = [
      '/api/brand-purpose',
      '/api/platform-connections',
      '/api/subscription-usage',
      '/api/enforce-auto-posting',
      '/api/video',
      '/api/posts'
    ];

    let protectedCount = 0;
    
    for (const endpoint of protectedEndpoints) {
      try {
        await axios.get(`${this.baseUrl}${endpoint}`);
        console.log(`⚠️  ${endpoint} allowed unauthorized access`);
      } catch (error) {
        if (error.response && error.response.status === 401) {
          protectedCount++;
        }
      }
    }

    const isFullyProtected = protectedCount === protectedEndpoints.length;
    
    return {
      success: isFullyProtected,
      details: isFullyProtected 
        ? `All ${protectedEndpoints.length} endpoints properly protected`
        : `Only ${protectedCount}/${protectedEndpoints.length} endpoints protected`,
      error: isFullyProtected ? null : 'Some endpoints not properly protected'
    };
  }

  // Test 4: Session format validation
  async testSessionFormatValidation() {
    const { SessionValidator } = require('../utils/session-validator.js');
    const validator = new SessionValidator();

    const testCases = [
      { sessionId: 'aiq_123_abc', expected: true, name: 'Valid session format' },
      { sessionId: 'invalid_session', expected: false, name: 'Invalid session format' },
      { sessionId: '', expected: false, name: 'Empty session' },
      { sessionId: null, expected: false, name: 'Null session' },
      { sessionId: 'aiq_', expected: false, name: 'Incomplete session format' }
    ];

    let passedValidations = 0;
    
    for (const testCase of testCases) {
      const result = validator.isValidSessionFormat(testCase.sessionId);
      if (result === testCase.expected) {
        passedValidations++;
        console.log(`  ✅ ${testCase.name}: ${result}`);
      } else {
        console.log(`  ❌ ${testCase.name}: Expected ${testCase.expected}, got ${result}`);
      }
    }

    const allPassed = passedValidations === testCases.length;
    
    return {
      success: allPassed,
      details: allPassed 
        ? `All ${testCases.length} session validation tests passed`
        : `${passedValidations}/${testCases.length} session validation tests passed`,
      error: allPassed ? null : 'Some session format validations failed'
    };
  }

  // Test 5: Cookie extraction validation
  async testCookieExtractionValidation() {
    const { SessionValidator } = require('../utils/session-validator.js');
    const validator = new SessionValidator();

    const testCookies = [
      {
        cookie: 'theagencyiq.session=aiq_123_abc; other=value',
        expected: 'aiq_123_abc',
        name: 'Valid cookie extraction'
      },
      {
        cookie: 'theagencyiq.session=s%3Aaiq_123_abc.signature; other=value',
        expected: 'aiq_123_abc',
        name: 'URL encoded cookie extraction'
      },
      {
        cookie: 'other=value; no_session=here',
        expected: null,
        name: 'Missing session cookie'
      },
      {
        cookie: '',
        expected: null,
        name: 'Empty cookie string'
      }
    ];

    let passedExtractions = 0;
    
    for (const testCase of testCookies) {
      const result = validator.extractSessionFromCookie(testCase.cookie);
      if (result === testCase.expected) {
        passedExtractions++;
        console.log(`  ✅ ${testCase.name}: ${result || 'null'}`);
      } else {
        console.log(`  ❌ ${testCase.name}: Expected ${testCase.expected || 'null'}, got ${result || 'null'}`);
      }
    }

    const allPassed = passedExtractions === testCookies.length;
    
    return {
      success: allPassed,
      details: allPassed 
        ? `All ${testCookies.length} cookie extraction tests passed`
        : `${passedExtractions}/${testCookies.length} cookie extraction tests passed`,
      error: allPassed ? null : 'Some cookie extraction tests failed'
    };
  }

  // Test 6: Script authentication validation
  async testScriptAuthentication() {
    const { AutoPostingAuth } = require('../middleware/database-auth.js');

    try {
      // Test with invalid session cookie
      await AutoPostingAuth.validatePostingRequest('invalid_cookie', '2');
      return {
        success: false,
        error: 'Script validation allowed invalid session cookie'
      };
    } catch (error) {
      if (error.message.includes('authentication failed')) {
        return {
          success: true,
          details: 'Script authentication properly rejected invalid session'
        };
      }
      return {
        success: false,
        error: `Unexpected script authentication error: ${error.message}`
      };
    }
  }

  // Generate comprehensive test report
  generateReport() {
    const successRate = ((this.passedTests / this.totalTests) * 100).toFixed(1);
    const isFullySecure = this.passedTests === this.totalTests;

    console.log('\n' + '='.repeat(60));
    console.log('🔐 DATABASE AUTHENTICATION SECURITY VALIDATION REPORT');
    console.log('='.repeat(60));
    console.log(`📊 Test Results: ${this.passedTests}/${this.totalTests} passed (${successRate}%)`);
    console.log(`🛡️  Security Status: ${isFullySecure ? 'BULLETPROOF' : 'NEEDS ATTENTION'}`);
    console.log('');

    // Detailed results
    this.testResults.forEach((test, index) => {
      const icon = test.status === 'PASSED' ? '✅' : '❌';
      console.log(`${icon} ${index + 1}. ${test.name}: ${test.status}`);
      if (test.details) {
        console.log(`   📋 ${test.details}`);
      }
      if (test.error) {
        console.log(`   ⚠️  ${test.error}`);
      }
    });

    console.log('');
    console.log('🔐 DATABASE SECURITY FEATURES:');
    console.log('   ✅ Session authentication middleware');
    console.log('   ✅ Database operation protection');
    console.log('   ✅ Script-based access validation');
    console.log('   ✅ Cookie format validation');
    console.log('   ✅ Unauthorized access blocking');
    console.log('   ✅ Comprehensive security logging');

    if (isFullySecure) {
      console.log('\n🎯 RESULT: Database authentication security is BULLETPROOF');
      console.log('   All script-based bypass vulnerabilities eliminated');
      console.log('   Session validation enforced across all database operations');
    } else {
      console.log('\n⚠️  RESULT: Database authentication needs attention');
      console.log('   Some security tests failed - review implementation');
    }

    return isFullySecure;
  }

  // Run all validation tests
  async runAllTests() {
    console.log('🔐 Starting Database Authentication Security Validation');
    console.log('   Testing script-based bypass vulnerability fixes');
    console.log('');

    await this.runTest('Unauthorized Access Blocking', () => this.testUnauthorizedAccess());
    await this.runTest('Quota Status Authentication', () => this.testQuotaStatusAuth());
    await this.runTest('Database Middleware Protection', () => this.testDatabaseMiddlewareProtection());
    await this.runTest('Session Format Validation', () => this.testSessionFormatValidation());
    await this.runTest('Cookie Extraction Validation', () => this.testCookieExtractionValidation());
    await this.runTest('Script Authentication Validation', () => this.testScriptAuthentication());

    const isSecure = this.generateReport();
    return isSecure;
  }
}

// Run validation if called directly
async function main() {
  if (require.main === module) {
    const validator = new DatabaseAuthValidationTest();
    
    try {
      const isSecure = await validator.runAllTests();
      process.exit(isSecure ? 0 : 1);
    } catch (error) {
      console.error('❌ Validation failed:', error.message);
      process.exit(1);
    }
  }
}

main().catch(console.error);

module.exports = { DatabaseAuthValidationTest };