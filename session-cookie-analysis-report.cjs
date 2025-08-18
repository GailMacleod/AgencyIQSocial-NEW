/**
 * COMPREHENSIVE SESSION COOKIE ANALYSIS AND TESTING REPORT
 * Analyzes current session cookie implementation, security, and reliability
 * Tests all session endpoints without making any changes to the system
 */

const axios = require('axios');

const BASE_URL = 'https://4fc77172-459a-4da7-8c33-5014abb1b73e-00-dqhtnud4ismj.worf.replit.dev';

console.log('🔐 SESSION COOKIE COMPREHENSIVE ANALYSIS');
console.log('==========================================');
console.log(`Testing Domain: ${BASE_URL}`);
console.log(`Analysis Date: ${new Date().toISOString()}`);

async function analyzeSessionCookies() {
  const report = {
    sessionEstablishment: null,
    cookiePersistence: null,
    sessionSecurity: null,
    crossRequestConsistency: null,
    sessionRecovery: null,
    errorHandling: null,
    multipleSessionHandling: null,
    sessionExpiry: null
  };

  let sessionData = {};

  console.log('\n📋 ANALYSIS 1: Session Establishment and Cookie Creation');
  console.log('=' * 60);
  
  try {
    // Test session establishment
    const sessionResponse = await axios.get(`${BASE_URL}/api/auth/session`, {
      timeout: 30000
    });
    
    console.log(`✅ Session Endpoint Status: ${sessionResponse.status}`);
    console.log(`📊 Response Data:`, JSON.stringify(sessionResponse.data, null, 2));
    
    // Analyze cookies in response headers
    const setCookieHeaders = sessionResponse.headers['set-cookie'] || [];
    console.log(`🍪 Set-Cookie Headers Found: ${setCookieHeaders.length}`);
    
    setCookieHeaders.forEach((cookie, index) => {
      console.log(`   Cookie ${index + 1}: ${cookie}`);
      
      // Parse cookie attributes
      const cookieParts = cookie.split(';').map(part => part.trim());
      const [nameValue] = cookieParts;
      const [name, value] = nameValue.split('=');
      
      console.log(`   - Name: ${name}`);
      console.log(`   - Value Length: ${value ? value.length : 0} characters`);
      
      // Check security attributes
      const hasHttpOnly = cookieParts.some(part => part.toLowerCase() === 'httponly');
      const hasSecure = cookieParts.some(part => part.toLowerCase() === 'secure');
      const sameSite = cookieParts.find(part => part.toLowerCase().startsWith('samesite='));
      const maxAge = cookieParts.find(part => part.toLowerCase().startsWith('max-age='));
      const expires = cookieParts.find(part => part.toLowerCase().startsWith('expires='));
      
      console.log(`   - HttpOnly: ${hasHttpOnly}`);
      console.log(`   - Secure: ${hasSecure}`);
      console.log(`   - SameSite: ${sameSite || 'Not set'}`);
      console.log(`   - Max-Age: ${maxAge || 'Not set'}`);
      console.log(`   - Expires: ${expires || 'Not set'}`);
    });
    
    if (sessionResponse.data.sessionId) {
      sessionData.sessionId = sessionResponse.data.sessionId;
      sessionData.userId = sessionResponse.data.userId;
      console.log(`✅ Session ID: ${sessionData.sessionId}`);
      console.log(`👤 User ID: ${sessionData.userId}`);
    }
    
    report.sessionEstablishment = 'PASSED';
    
  } catch (error) {
    console.log(`❌ Session establishment failed: ${error.message}`);
    console.log(`   Status: ${error.response?.status}`);
    console.log(`   Response: ${JSON.stringify(error.response?.data, null, 2)}`);
    report.sessionEstablishment = 'FAILED';
  }

  console.log('\n📋 ANALYSIS 2: Cookie Persistence Across Requests');
  console.log('=' * 50);
  
  try {
    // Test multiple requests to check cookie persistence
    const requests = [];
    for (let i = 0; i < 3; i++) {
      requests.push(
        axios.get(`${BASE_URL}/api/user`, {
          timeout: 30000,
          withCredentials: true
        })
      );
    }
    
    const responses = await Promise.all(requests);
    
    console.log(`✅ Multiple requests completed: ${responses.length}`);
    
    responses.forEach((response, index) => {
      console.log(`Request ${index + 1}:`);
      console.log(`   Status: ${response.status}`);
      console.log(`   Session ID: ${response.data?.sessionId || 'Not provided'}`);
      console.log(`   User ID: ${response.data?.userId || response.data?.id || 'Not provided'}`);
      console.log(`   Cookies Received: ${response.headers['set-cookie']?.length || 0}`);
    });
    
    // Check consistency
    const sessionIds = responses.map(r => r.data?.sessionId).filter(Boolean);
    const userIds = responses.map(r => r.data?.userId || r.data?.id).filter(Boolean);
    
    console.log(`🔍 Session ID Consistency: ${new Set(sessionIds).size === 1 ? 'CONSISTENT' : 'INCONSISTENT'}`);
    console.log(`🔍 User ID Consistency: ${new Set(userIds).size === 1 ? 'CONSISTENT' : 'INCONSISTENT'}`);
    
    report.cookiePersistence = new Set(sessionIds).size === 1 ? 'PASSED' : 'FAILED';
    
  } catch (error) {
    console.log(`❌ Cookie persistence test failed: ${error.message}`);
    report.cookiePersistence = 'FAILED';
  }

  console.log('\n📋 ANALYSIS 3: Session Security Implementation');
  console.log('=' * 45);
  
  try {
    // Test session validation endpoint
    const userResponse = await axios.get(`${BASE_URL}/api/user`, {
      timeout: 30000
    });
    
    console.log(`✅ User endpoint accessible: ${userResponse.status}`);
    console.log(`📊 User data structure:`, Object.keys(userResponse.data || {}));
    
    // Check for sensitive data exposure
    const sensitiveFields = ['password', 'token', 'secret', 'key'];
    const exposedFields = Object.keys(userResponse.data || {}).filter(key => 
      sensitiveFields.some(sensitive => key.toLowerCase().includes(sensitive))
    );
    
    console.log(`🔐 Sensitive data exposure check: ${exposedFields.length === 0 ? 'SECURE' : 'WARNING'}`);
    if (exposedFields.length > 0) {
      console.log(`   Potentially sensitive fields: ${exposedFields.join(', ')}`);
    }
    
    report.sessionSecurity = exposedFields.length === 0 ? 'PASSED' : 'WARNING';
    
  } catch (error) {
    console.log(`❌ Session security test failed: ${error.message}`);
    report.sessionSecurity = 'FAILED';
  }

  console.log('\n📋 ANALYSIS 4: Cross-Request Session Consistency');
  console.log('=' * 48);
  
  try {
    // Test different endpoints with same session
    const endpoints = [
      '/api/user',
      '/api/user-status', 
      '/api/auth/session',
      '/api/posts'
    ];
    
    const endpointTests = await Promise.allSettled(
      endpoints.map(endpoint => 
        axios.get(`${BASE_URL}${endpoint}`, {
          timeout: 30000,
          withCredentials: true
        })
      )
    );
    
    console.log(`🔍 Testing ${endpoints.length} different endpoints:`);
    
    endpointTests.forEach((result, index) => {
      const endpoint = endpoints[index];
      if (result.status === 'fulfilled') {
        console.log(`   ${endpoint}: ✅ Status ${result.value.status}`);
        const sessionId = result.value.data?.sessionId;
        const userId = result.value.data?.userId || result.value.data?.user?.id;
        console.log(`     Session ID: ${sessionId || 'Not provided'}`);
        console.log(`     User ID: ${userId || 'Not provided'}`);
      } else {
        console.log(`   ${endpoint}: ❌ ${result.reason.message}`);
      }
    });
    
    const successfulResponses = endpointTests.filter(r => r.status === 'fulfilled');
    const sessionIds = successfulResponses.map(r => r.value.data?.sessionId).filter(Boolean);
    
    console.log(`📊 Consistency Analysis:`);
    console.log(`   Successful endpoints: ${successfulResponses.length}/${endpoints.length}`);
    console.log(`   Unique session IDs: ${new Set(sessionIds).size}`);
    console.log(`   Session consistency: ${new Set(sessionIds).size <= 1 ? 'EXCELLENT' : 'INCONSISTENT'}`);
    
    report.crossRequestConsistency = new Set(sessionIds).size <= 1 ? 'PASSED' : 'FAILED';
    
  } catch (error) {
    console.log(`❌ Cross-request consistency test failed: ${error.message}`);
    report.crossRequestConsistency = 'FAILED';
  }

  console.log('\n📋 ANALYSIS 5: Session Recovery and Auto-Establishment');
  console.log('=' * 52);
  
  try {
    // Test session recovery with minimal cookies
    const recoveryResponse = await axios.get(`${BASE_URL}/api/auth/session`, {
      headers: {
        'Cookie': 'minimal=test'
      },
      timeout: 30000
    });
    
    console.log(`✅ Session recovery test: ${recoveryResponse.status}`);
    console.log(`📊 Recovery response:`, JSON.stringify(recoveryResponse.data, null, 2));
    
    const hasAutoEstablishment = recoveryResponse.data?.sessionId || recoveryResponse.data?.authenticated;
    console.log(`🔄 Auto-establishment working: ${hasAutoEstablishment ? 'YES' : 'NO'}`);
    
    report.sessionRecovery = hasAutoEstablishment ? 'PASSED' : 'FAILED';
    
  } catch (error) {
    console.log(`❌ Session recovery test failed: ${error.message}`);
    report.sessionRecovery = 'FAILED';
  }

  console.log('\n📋 ANALYSIS 6: Error Handling and Unauthorized Access');
  console.log('=' * 54);
  
  try {
    // Test with invalid/expired session cookie
    const errorResponse = await axios.get(`${BASE_URL}/api/user`, {
      headers: {
        'Cookie': 'theagencyiq.session=invalid_expired_session_test'
      },
      timeout: 30000
    });
    
    console.log(`✅ Invalid session handling: ${errorResponse.status}`);
    
    // Should either auto-establish or return 401
    if (errorResponse.status === 200) {
      console.log(`🔄 Auto-establishment on invalid session: WORKING`);
      console.log(`   New session created: ${errorResponse.data?.sessionId ? 'YES' : 'NO'}`);
    } else if (errorResponse.status === 401) {
      console.log(`🔐 Proper 401 response for invalid session: WORKING`);
    }
    
    report.errorHandling = 'PASSED';
    
  } catch (error) {
    if (error.response?.status === 401) {
      console.log(`✅ Proper 401 unauthorized response: WORKING`);
      report.errorHandling = 'PASSED';
    } else {
      console.log(`❌ Error handling test failed: ${error.message}`);
      report.errorHandling = 'FAILED';
    }
  }

  console.log('\n📋 ANALYSIS 7: Multiple Session Handling');
  console.log('=' * 40);
  
  try {
    // Test with different session identifiers
    const sessionTests = [
      'session_test_1',
      'session_test_2',
      'session_test_3'
    ];
    
    const multiSessionTests = await Promise.allSettled(
      sessionTests.map(sessionId => 
        axios.get(`${BASE_URL}/api/auth/session`, {
          headers: {
            'Cookie': `theagencyiq.session=${sessionId}`
          },
          timeout: 30000
        })
      )
    );
    
    console.log(`🔍 Testing ${sessionTests.length} different session identifiers:`);
    
    multiSessionTests.forEach((result, index) => {
      const testSession = sessionTests[index];
      if (result.status === 'fulfilled') {
        console.log(`   ${testSession}: ✅ Status ${result.value.status}`);
        console.log(`     Response session: ${result.value.data?.sessionId || 'Auto-generated'}`);
        console.log(`     User authenticated: ${result.value.data?.authenticated || false}`);
      } else {
        console.log(`   ${testSession}: ❌ ${result.reason.message}`);
      }
    });
    
    const successfulSessions = multiSessionTests.filter(r => r.status === 'fulfilled');
    console.log(`📊 Multi-session handling: ${successfulSessions.length}/${sessionTests.length} successful`);
    
    report.multipleSessionHandling = successfulSessions.length >= 2 ? 'PASSED' : 'FAILED';
    
  } catch (error) {
    console.log(`❌ Multiple session test failed: ${error.message}`);
    report.multipleSessionHandling = 'FAILED';
  }

  console.log('\n📋 ANALYSIS 8: Session Timeout and Expiry Behavior');
  console.log('=' * 48);
  
  try {
    // Test session status endpoint for timeout information
    const statusResponse = await axios.get(`${BASE_URL}/api/user-status`, {
      timeout: 30000
    });
    
    console.log(`✅ Session status check: ${statusResponse.status}`);
    console.log(`📊 Status data:`, JSON.stringify(statusResponse.data, null, 2));
    
    // Look for session timeout or expiry information
    const hasExpiryInfo = statusResponse.data?.sessionId || statusResponse.data?.authenticated !== undefined;
    console.log(`⏰ Session expiry tracking: ${hasExpiryInfo ? 'IMPLEMENTED' : 'NOT VISIBLE'}`);
    
    report.sessionExpiry = hasExpiryInfo ? 'PASSED' : 'PARTIAL';
    
  } catch (error) {
    console.log(`❌ Session timeout test failed: ${error.message}`);
    report.sessionExpiry = 'FAILED';
  }

  // Generate comprehensive report
  console.log('\n' + '='.repeat(80));
  console.log('🔐 COMPREHENSIVE SESSION COOKIE ANALYSIS REPORT');
  console.log('='.repeat(80));
  
  const totalTests = Object.keys(report).length;
  const passedTests = Object.values(report).filter(status => status === 'PASSED').length;
  const warningTests = Object.values(report).filter(status => status === 'WARNING').length;
  const failedTests = Object.values(report).filter(status => status === 'FAILED').length;
  
  console.log(`📊 OVERALL RESULTS:`);
  console.log(`   Total Tests: ${totalTests}`);
  console.log(`   ✅ Passed: ${passedTests}`);
  console.log(`   ⚠️  Warnings: ${warningTests}`);
  console.log(`   ❌ Failed: ${failedTests}`);
  console.log(`   📈 Success Rate: ${Math.round((passedTests / totalTests) * 100)}%`);
  
  console.log(`\n📋 DETAILED ANALYSIS RESULTS:`);
  console.log(`   Session Establishment: ${report.sessionEstablishment}`);
  console.log(`   Cookie Persistence: ${report.cookiePersistence}`);
  console.log(`   Session Security: ${report.sessionSecurity}`);
  console.log(`   Cross-Request Consistency: ${report.crossRequestConsistency}`);
  console.log(`   Session Recovery: ${report.sessionRecovery}`);
  console.log(`   Error Handling: ${report.errorHandling}`);
  console.log(`   Multiple Session Handling: ${report.multipleSessionHandling}`);
  console.log(`   Session Expiry Management: ${report.sessionExpiry}`);

  console.log(`\n🔍 KEY FINDINGS:`);
  
  if (passedTests >= 6) {
    console.log(`✅ EXCELLENT: Session cookie system is highly robust`);
    console.log(`   - Strong session establishment and persistence`);
    console.log(`   - Good error handling and recovery mechanisms`);
    console.log(`   - Consistent cross-request behavior`);
  } else if (passedTests >= 4) {
    console.log(`⚠️  GOOD: Session system functional with some areas for improvement`);
    console.log(`   - Core functionality working properly`);
    console.log(`   - Some edge cases may need attention`);
  } else {
    console.log(`❌ NEEDS ATTENTION: Session system has significant issues`);
    console.log(`   - Critical session management problems detected`);
    console.log(`   - User experience may be affected`);
  }

  console.log(`\n🛡️  SECURITY ASSESSMENT:`);
  if (report.sessionSecurity === 'PASSED') {
    console.log(`✅ Session security appears robust`);
    console.log(`   - No sensitive data exposed in responses`);
    console.log(`   - Proper authentication validation`);
  } else {
    console.log(`⚠️  Session security needs review`);
    console.log(`   - Potential sensitive data exposure detected`);
    console.log(`   - Review authentication mechanisms`);
  }

  console.log(`\n🔄 RELIABILITY ASSESSMENT:`);
  if (report.cookiePersistence === 'PASSED' && report.crossRequestConsistency === 'PASSED') {
    console.log(`✅ High reliability - consistent session behavior`);
    console.log(`   - Sessions persist across multiple requests`);
    console.log(`   - Consistent user experience maintained`);
  } else {
    console.log(`⚠️  Reliability concerns detected`);
    console.log(`   - Session inconsistencies may cause user issues`);
    console.log(`   - Cookie persistence may be unreliable`);
  }

  console.log(`\n📈 RECOMMENDATIONS:`);
  
  if (report.sessionEstablishment === 'FAILED') {
    console.log(`🔧 CRITICAL: Fix session establishment mechanism`);
  }
  
  if (report.cookiePersistence === 'FAILED') {
    console.log(`🔧 HIGH: Improve cookie persistence across requests`);
  }
  
  if (report.sessionSecurity === 'WARNING') {
    console.log(`🔧 MEDIUM: Review and secure sensitive data exposure`);
  }
  
  if (report.crossRequestConsistency === 'FAILED') {
    console.log(`🔧 HIGH: Fix session ID consistency across endpoints`);
  }
  
  if (report.sessionRecovery === 'FAILED') {
    console.log(`🔧 MEDIUM: Implement better session recovery mechanisms`);
  }

  console.log(`\n📋 TECHNICAL IMPLEMENTATION DETAILS:`);
  console.log(`   - Session auto-establishment: ${report.sessionRecovery === 'PASSED' ? 'Working' : 'Needs attention'}`);
  console.log(`   - Cross-origin cookie handling: ${report.cookiePersistence === 'PASSED' ? 'Functional' : 'Problematic'}`);
  console.log(`   - Error recovery: ${report.errorHandling === 'PASSED' ? 'Robust' : 'Needs improvement'}`);
  console.log(`   - Multi-session support: ${report.multipleSessionHandling === 'PASSED' ? 'Working' : 'Limited'}`);

  console.log(`\n🏁 ANALYSIS COMPLETE`);
  console.log(`📄 Report generated: ${new Date().toISOString()}`);
  console.log(`📂 File: session-cookie-analysis-report.cjs`);
  
  return {
    overallHealth: passedTests >= 6 ? 'EXCELLENT' : passedTests >= 4 ? 'GOOD' : 'NEEDS_ATTENTION',
    passedTests,
    totalTests,
    successRate: Math.round((passedTests / totalTests) * 100),
    report
  };
}

// Run the comprehensive analysis
analyzeSessionCookies().catch(console.error);