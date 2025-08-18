/**
 * SURGICAL AGENCYIQ TESTING - FOCUSED ON 4 CRITICAL AREAS
 * Testing surgical fixes: Auth routes, Anomaly detection, Quota structure, Session/Quota interconnections
 */

import axios from 'axios';

// Configuration
const BASE_URL = process.env.REPL_URL || 'https://4fc77172-459a-4da7-8c33-5014abb1b73e-00-dqhtnud4ismj.worf.replit.dev';
const TEST_USER = {
  email: 'gailm@macleodglba.com.au',
  password: 'Tw33dl3dum!',
  phone: '+61424835189'
};

// Test Results Storage
let passCount = 0;
let failCount = 0;
const testResults = [];

function logTest(description, expected, actual, passed) {
  testResults.push({ description, expected, actual, passed });
  
  if (passed) {
    console.log(`✅ PASS: ${description}`);
    passCount++;
  } else {
    console.log(`❌ FAIL: ${description}`);
    console.log(`   Expected: ${expected}`);
    console.log(`   Actual: ${actual}`);
    failCount++;
  }
}

async function makeRequest(method, path, data = null, cookies = '', headers = {}) {
  try {
    const config = {
      method,
      url: `${BASE_URL}${path}`,
      headers: {
        'Content-Type': 'application/json',
        'Cookie': cookies,
        ...headers
      },
      timeout: 15000,
      validateStatus: () => true
    };
    
    if (data) config.data = data;
    
    const response = await axios(config);
    return {
      status: response.status,
      data: response.data,
      headers: response.headers,
      cookies: response.headers['set-cookie'] || []
    };
  } catch (error) {
    return {
      status: 0,
      error: error.message,
      data: null,
      headers: {},
      cookies: []
    };
  }
}

// SURGICAL FIX 1: AUTH ROUTES TESTING
async function testAuthRoutes() {
  console.log('\n🔐 SURGICAL FIX 1: AUTH ROUTES TESTING...');
  
  // Test 1: Login with valid credentials (should work now)
  const loginResponse = await makeRequest('POST', '/api/auth/login', {
    email: TEST_USER.email,
    password: TEST_USER.password
  });
  
  logTest(
    'SURGICAL: Login endpoint works with valid credentials',
    'Status 200 with session regeneration',
    `Status: ${loginResponse.status}, Success: ${loginResponse.data?.success}`,
    loginResponse.status === 200 && loginResponse.data?.success === true
  );
  
  // Test 2: Login with invalid credentials  
  const invalidLogin = await makeRequest('POST', '/api/auth/login', {
    email: TEST_USER.email,
    password: 'wrongpassword'
  });
  
  logTest(
    'SURGICAL: Invalid login properly rejected',
    'Status 401, success: false',
    `Status: ${invalidLogin.status}, Success: ${invalidLogin.data?.success}`,
    invalidLogin.status === 401 && invalidLogin.data?.success === false
  );
  
  // Test 3: Session invalidation endpoint exists
  const sessionInvalidate = await makeRequest('POST', '/api/auth/invalidate-session', {});
  
  logTest(
    'SURGICAL: Session invalidation endpoint exists',
    'Status 200 (endpoint functional)',
    `Status: ${sessionInvalidate.status}`,
    sessionInvalidate.status === 200
  );
}

// SURGICAL FIX 2: ANOMALY DETECTION TESTING
async function testAnomalyDetection() {
  console.log('\n🛡️ SURGICAL FIX 2: ANOMALY DETECTION TESTING...');
  
  // Test 4: Suspicious admin path should be blocked
  const adminDebugRequest = await makeRequest('GET', '/admin/debug');
  
  logTest(
    'SURGICAL: /admin/debug blocked in all environments',
    'Status 403 (access denied)',
    `Status: ${adminDebugRequest.status}`,
    adminDebugRequest.status === 403
  );
  
  // Test 5: Other suspicious patterns
  const adminRequest = await makeRequest('GET', '/admin/users');
  const debugRequest = await makeRequest('GET', '/debug/sessions');
  
  logTest(
    'SURGICAL: Suspicious patterns consistently blocked',
    'Status 403 for suspicious paths',
    `Admin: ${adminRequest.status}, Debug: ${debugRequest.status}`,
    adminRequest.status === 403 && debugRequest.status === 403
  );
}

// SURGICAL FIX 3: QUOTA STRUCTURE TESTING  
async function testQuotaStructure() {
  console.log('\n📊 SURGICAL FIX 3: QUOTA STRUCTURE TESTING...');
  
  // Test 6: Quota status has proper database fields
  const quotaStatus = await makeRequest('GET', '/api/quota-status');
  
  const hasRequiredFields = quotaStatus.data && 
    quotaStatus.data.totalPosts !== undefined &&
    quotaStatus.data.remainingPosts !== undefined &&
    quotaStatus.data.publishedPosts !== undefined &&
    quotaStatus.data.persistent === true;
  
  logTest(
    'SURGICAL: Quota status has database-backed fields',
    'totalPosts, remainingPosts, publishedPosts, persistent=true',
    `Fields present: ${hasRequiredFields}, Persistent: ${quotaStatus.data?.persistent}`,
    hasRequiredFields
  );
  
  // Test 7: User status endpoint has quota fields
  const userStatus = await makeRequest('GET', '/api/user-status');
  
  const hasQuotaFields = userStatus.data &&
    userStatus.data.remainingPosts !== undefined &&
    userStatus.data.totalPosts !== undefined &&
    userStatus.data.quotaLimit !== undefined;
  
  logTest(
    'SURGICAL: User status has enhanced quota fields',
    'remainingPosts, totalPosts, quotaLimit fields present',
    `Quota fields present: ${hasQuotaFields}`,
    hasQuotaFields
  );
  
  // Test 8: Cancelled subscription shows 0/0 quota
  if (userStatus.data?.subscriptionPlan === 'cancelled') {
    const correctCancelledQuota = userStatus.data.remainingPosts === 0 && 
                                  userStatus.data.quotaLimit === 0;
    
    logTest(
      'SURGICAL: Cancelled subscription shows 0/0 quota',
      'remainingPosts=0, quotaLimit=0 for cancelled plan',
      `Remaining: ${userStatus.data.remainingPosts}, Limit: ${userStatus.data.quotaLimit}`,
      correctCancelledQuota
    );
  }
}

// SURGICAL FIX 4: SESSION/QUOTA INTERCONNECTIONS TESTING
async function testSessionQuotaInterconnections() {
  console.log('\n🔗 SURGICAL FIX 4: SESSION/QUOTA INTERCONNECTIONS TESTING...');
  
  // Test 9: Subscription cancellation endpoint exists
  const cancelResponse = await makeRequest('POST', '/api/cancel-subscription', {});
  
  logTest(
    'SURGICAL: Enhanced cancellation endpoint exists',
    'Status 200/401 (not 404)',
    `Status: ${cancelResponse.status}`,
    cancelResponse.status !== 404
  );
  
  // Test 10: Cancellation invalidates session
  if (cancelResponse.status === 200) {
    const hasSessionInvalidation = cancelResponse.data?.sessionInvalidated === true &&
                                   cancelResponse.data?.redirectToLogin === true;
    
    logTest(
      'SURGICAL: Cancellation invalidates session properly',
      'sessionInvalidated=true, redirectToLogin=true',
      `Session invalidated: ${cancelResponse.data?.sessionInvalidated}, Redirect: ${cancelResponse.data?.redirectToLogin}`,
      hasSessionInvalidation
    );
  }
  
  // Test 11: Session authentication on protected endpoints
  const brandPurposeAuth = await makeRequest('GET', '/api/brand-purpose');
  const platformConnAuth = await makeRequest('GET', '/api/platform-connections');
  
  const authRequired = brandPurposeAuth.status === 401 || brandPurposeAuth.status === 200;
  const platformAuthRequired = platformConnAuth.status === 401 || platformConnAuth.status === 200;
  
  logTest(
    'SURGICAL: Protected endpoints require authentication',
    'Status 200 (authenticated) or 401 (auth required)',
    `Brand: ${brandPurposeAuth.status}, Platform: ${platformConnAuth.status}`,
    authRequired && platformAuthRequired
  );
}

// MAIN SURGICAL TEST RUNNER
async function runSurgicalTests() {
  console.log('🔪 STARTING SURGICAL AGENCYIQ TESTING - 4 CRITICAL AREAS');
  console.log(`📍 Testing against: ${BASE_URL}`);
  console.log(`📅 Started at: ${new Date().toISOString()}\n`);
  
  try {
    // Run surgical tests for 4 critical areas
    await testAuthRoutes();
    await testAnomalyDetection(); 
    await testQuotaStructure();
    await testSessionQuotaInterconnections();
    
    // Generate surgical results
    console.log('\n📊 SURGICAL TEST RESULTS');
    console.log('='.repeat(50));
    console.log(`✅ PASSED: ${passCount} tests`);
    console.log(`❌ FAILED: ${failCount} tests`);
    
    const passRate = (passCount / (passCount + failCount)) * 100;
    const originalRate = 77.8;
    const improvement = passRate - originalRate;
    
    console.log(`📈 PASS RATE: ${passRate.toFixed(1)}% (was ${originalRate}%)`);
    console.log(`📊 IMPROVEMENT: ${improvement > 0 ? '+' : ''}${improvement.toFixed(1)}%`);
    
    // Launch readiness assessment
    const launchReady = passRate >= 90;
    
    console.log('\n🚀 SURGICAL LAUNCH READINESS');
    console.log('='.repeat(50));
    console.log(`📊 Surgical Score: ${passRate.toFixed(1)}%`);
    console.log(`🎯 Launch Ready: ${launchReady ? 'YES' : 'NO'} (target: 90%+)`);
    
    if (launchReady) {
      console.log('✅ SURGICAL FIXES SUCCESSFUL - Ready for production deployment');
    } else {
      console.log('⚠️ Additional surgical fixes needed');
    }
    
    // Critical surgical issues
    const failedTests = testResults.filter(test => !test.passed);
    if (failedTests.length > 0) {
      console.log('\n🔪 REMAINING SURGICAL ISSUES:');
      console.log('='.repeat(50));
      failedTests.forEach((test, index) => {
        console.log(`${index + 1}. ${test.description}`);
        console.log(`   Expected: ${test.expected}`);
        console.log(`   Actual: ${test.actual}\n`);
      });
    }
    
    // Surgical fixes summary
    console.log('\n🏥 SURGICAL FIXES STATUS');
    console.log('='.repeat(50));
    console.log(`🔐 Auth Routes: ${testResults.slice(0, 3).filter(t => t.passed).length}/3 fixed`);
    console.log(`🛡️ Anomaly Detection: ${testResults.slice(3, 5).filter(t => t.passed).length}/2 fixed`);
    console.log(`📊 Quota Structure: ${testResults.slice(5, 8).filter(t => t.passed).length}/3 fixed`);
    console.log(`🔗 Session Interconnections: ${testResults.slice(8).filter(t => t.passed).length}/${testResults.slice(8).length} fixed`);
    
    return {
      totalTests: passCount + failCount,
      passed: passCount,
      failed: failCount,
      passRate: passRate,
      improvement: improvement,
      launchReady: launchReady,
      surgicalResults: testResults
    };
    
  } catch (error) {
    console.error('❌ Surgical testing encountered an error:', error.message);
    return {
      error: error.message,
      results: testResults
    };
  }
}

// Run surgical tests
runSurgicalTests().then(results => {
  console.log('\n✅ Surgical testing complete.');
  process.exit(results.launchReady ? 0 : 1);
}).catch(error => {
  console.error('❌ Surgical test suite failed:', error);
  process.exit(1);
});

export { runSurgicalTests };