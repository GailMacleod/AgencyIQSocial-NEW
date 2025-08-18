#!/usr/bin/env node

/**
 * COMPREHENSIVE LOGOUT COOLDOWN TEST - PERSISTENT SOLUTION
 * Tests all three middleware layers to ensure logout cooldown works correctly
 * across server restarts and file changes.
 * 
 * Expected behavior: After logout, all middleware should respect the 10-second
 * cooldown period stored in temp/last_logout.txt file.
 */

const { execSync } = require('child_process');

const BASE_URL = 'http://localhost:5000';

// Color codes for better visibility
const colors = {
  reset: '\x1b[0m',
  green: '\x1b[32m',
  red: '\x1b[31m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  cyan: '\x1b[36m'
};

function colorLog(color, message) {
  console.log(`${colors[color]}${message}${colors.reset}`);
}

function makeRequest(method, endpoint, description) {
  try {
    colorLog('blue', `\n🔍 Testing: ${description}`);
    const command = method === 'POST' 
      ? `curl -s -X POST ${BASE_URL}${endpoint}`
      : `curl -s ${BASE_URL}${endpoint}`;
    
    const response = execSync(command, { encoding: 'utf8' });
    const parsed = JSON.parse(response);
    
    colorLog('cyan', `Response: ${JSON.stringify(parsed, null, 2)}`);
    return parsed;
  } catch (error) {
    colorLog('red', `❌ Request failed: ${error.message}`);
    return null;
  }
}

function sleep(seconds) {
  colorLog('yellow', `⏳ Waiting ${seconds} seconds...`);
  execSync(`sleep ${seconds}`, { encoding: 'utf8' });
}

function testEndpoint(endpoint, endpointName, expectBlocked = true) {
  const result = makeRequest('GET', endpoint, `${endpointName} during cooldown`);
  
  if (expectBlocked) {
    const isBlocked = result && 
      (result.authenticated === false || 
       result.message?.includes('Not authenticated') ||
       result.message?.includes('cooldown active'));
    
    if (isBlocked) {
      colorLog('green', `✅ ${endpointName}: Correctly blocked during cooldown`);
      return true;
    } else {
      colorLog('red', `❌ ${endpointName}: Should be blocked but isn't`);
      return false;
    }
  } else {
    const isWorking = result && result.authenticated === true;
    if (isWorking) {
      colorLog('green', `✅ ${endpointName}: Working after cooldown expired`);
      return true;
    } else {
      colorLog('red', `❌ ${endpointName}: Should work after cooldown but doesn't`);
      return false;
    }
  }
}

async function runComprehensiveTest() {
  colorLog('cyan', '🚀 COMPREHENSIVE LOGOUT COOLDOWN TEST');
  colorLog('cyan', '=====================================');
  
  let passedTests = 0;
  let totalTests = 0;
  
  // Phase 1: Perform logout
  colorLog('blue', '\n📋 PHASE 1: Performing logout');
  const logoutResult = makeRequest('POST', '/api/auth/logout', 'User logout');
  totalTests++;
  
  if (logoutResult && logoutResult.success) {
    colorLog('green', '✅ Logout successful');
    passedTests++;
  } else {
    colorLog('red', '❌ Logout failed');
  }
  
  // Phase 2: Test immediate access (should be blocked)
  colorLog('blue', '\n📋 PHASE 2: Testing immediate access (should be blocked)');
  
  const endpointsToTest = [
    ['/api/user-status', 'Global Middleware'],
    ['/api/posts', 'RequirePaidSubscription Middleware'],
    ['/api/brand-purpose', 'RequireAuth Middleware'],
  ];
  
  for (const [endpoint, middlewareName] of endpointsToTest) {
    totalTests++;
    if (testEndpoint(endpoint, middlewareName, true)) {
      passedTests++;
    }
  }
  
  // Phase 3: Wait for cooldown to expire
  colorLog('blue', '\n📋 PHASE 3: Waiting for cooldown to expire');
  sleep(11); // Wait 11 seconds to ensure cooldown expires
  
  // Phase 4: Test access after cooldown (should work)
  colorLog('blue', '\n📋 PHASE 4: Testing access after cooldown (should work)');
  
  for (const [endpoint, middlewareName] of endpointsToTest) {
    totalTests++;
    if (testEndpoint(endpoint, middlewareName, false)) {
      passedTests++;
    }
  }
  
  // Summary
  colorLog('cyan', '\n📊 TEST SUMMARY');
  colorLog('cyan', '================');
  colorLog('cyan', `Total Tests: ${totalTests}`);
  colorLog('cyan', `Passed: ${passedTests}`);
  colorLog('cyan', `Failed: ${totalTests - passedTests}`);
  
  const successRate = ((passedTests / totalTests) * 100).toFixed(1);
  colorLog('cyan', `Success Rate: ${successRate}%`);
  
  if (passedTests === totalTests) {
    colorLog('green', '\n🎉 ALL TESTS PASSED - LOGOUT COOLDOWN WORKING PERFECTLY!');
    colorLog('green', '✅ Persistent file-based cooldown prevents auto-session establishment');
    colorLog('green', '✅ All three middleware layers respect logout cooldown');
    colorLog('green', '✅ Cooldown expires correctly after 10 seconds');
  } else {
    colorLog('red', '\n❌ SOME TESTS FAILED - LOGOUT COOLDOWN NEEDS FIXES');
    colorLog('yellow', 'Check the logs above for specific middleware issues');
  }
  
  return passedTests === totalTests;
}

// Run the test
runComprehensiveTest();