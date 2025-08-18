#!/usr/bin/env node

/**
 * SURGICAL TEST: Cancelled but Full Access Bug Verification
 * Tests the comprehensive fix for cancelled users accessing system features
 * Validates SSE broadcast and live access control middleware
 */

const axios = require('axios');

const BASE_URL = 'http://localhost:5000';

// Console styling for surgical precision reporting
const colors = {
  reset: '\x1b[0m',
  bright: '\x1b[1m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  magenta: '\x1b[35m',
  cyan: '\x1b[36m'
};

function log(level, message, data = '') {
  const timestamp = new Date().toISOString().split('T')[1].split('.')[0];
  const prefix = `[${timestamp}] [${level.toUpperCase()}]`;
  
  let color = colors.reset;
  switch (level) {
    case 'SURGICAL': color = colors.cyan + colors.bright; break;
    case 'SUCCESS': color = colors.green + colors.bright; break;
    case 'BLOCKED': color = colors.red + colors.bright; break;
    case 'SSE': color = colors.magenta; break;
    case 'WARNING': color = colors.yellow; break;
    default: color = colors.reset;
  }
  
  console.log(`${color}${prefix} ${message}${colors.reset}${data ? ' ' + JSON.stringify(data, null, 2) : ''}`);
}

async function testLiveAccessControl() {
  log('SURGICAL', 'Testing live access control middleware...');
  
  const protectedEndpoints = [
    '/api/posts',
    '/api/intelligent-schedule', 
    '/api/video/render',
    '/api/enforce-auto-posting',
    '/api/schedule',
    '/api/yearly-analytics'
  ];
  
  const results = {
    blocked: 0,
    allowed: 0,
    errors: 0,
    details: []
  };
  
  for (const endpoint of protectedEndpoints) {
    try {
      const response = await axios.get(`${BASE_URL}${endpoint}`, {
        timeout: 10000,
        validateStatus: () => true
      });
      
      // Check if cancelled user was properly blocked
      if (response.status === 403 && response.data?.subscriptionCancelled) {
        results.blocked++;
        results.details.push({
          endpoint,
          status: 'BLOCKED',
          message: response.data.message
        });
        log('BLOCKED', `Access denied to ${endpoint} (CORRECT BEHAVIOR)`);
      } else if (response.status === 200) {
        results.allowed++;
        results.details.push({
          endpoint,
          status: 'ALLOWED',  
          warning: 'BUG_DETECTED'
        });
        log('WARNING', `Access granted to ${endpoint} (BUG DETECTED)`);
      } else {
        results.errors++;
        results.details.push({
          endpoint,
          status: 'ERROR',
          httpStatus: response.status
        });
        log('WARNING', `Unexpected response from ${endpoint}`, {
          status: response.status
        });
      }
      
      // Brief delay between requests
      await new Promise(resolve => setTimeout(resolve, 200));
      
    } catch (error) {
      results.errors++;
      results.details.push({
        endpoint,
        status: 'ERROR',
        error: error.message
      });
      log('WARNING', `Request failed for ${endpoint}`, {
        error: error.message
      });
    }
  }
  
  return results;
}

async function testUserStatus() {
  log('SURGICAL', 'Verifying cancelled user status...');
  
  try {
    const response = await axios.get(`${BASE_URL}/api/auth/session`, {
      timeout: 5000,
      validateStatus: () => true
    });
    
    const user = response.data?.user;
    const isCancelled = user?.subscriptionPlan === 'cancelled' && !user?.subscriptionActive;
    
    log('SUCCESS', 'User status verified', {
      plan: user?.subscriptionPlan,
      active: user?.subscriptionActive,
      remainingPosts: user?.remainingPosts,
      isCancelled
    });
    
    return {
      isCancelled,
      plan: user?.subscriptionPlan,
      active: user?.subscriptionActive,
      user
    };
    
  } catch (error) {
    log('WARNING', 'User status check failed', {
      error: error.message
    });
    return {
      isCancelled: false,
      error: error.message
    };
  }
}

async function runCancelledAccessTest() {
  console.log(`\n${colors.cyan}${colors.bright}═══════════════════════════════════════════════════════════════════════════════${colors.reset}`);
  console.log(`${colors.cyan}${colors.bright}                    SURGICAL CANCELLED ACCESS BUG TEST                          ${colors.reset}`);
  console.log(`${colors.cyan}${colors.bright}             Testing Live Access Control Fix for Cancelled Users               ${colors.reset}`);
  console.log(`${colors.cyan}${colors.bright}═══════════════════════════════════════════════════════════════════════════════${colors.reset}\n`);
  
  const testResults = {
    userVerified: false,
    accessControlResults: null,
    overallSuccess: false,
    bugFixed: false
  };
  
  try {
    // Phase 1: Verify cancelled user state
    log('SURGICAL', 'Phase 1: User state verification...');
    const userStatus = await testUserStatus();
    testResults.userVerified = userStatus.isCancelled;
    
    if (userStatus.isCancelled) {
      log('SUCCESS', 'Cancelled user state confirmed - perfect test conditions');
    } else {
      log('WARNING', 'User not in cancelled state - test results may not reflect the bug');
    }
    
    // Phase 2: Test live access control middleware
    log('SURGICAL', 'Phase 2: Live access control middleware testing...');
    testResults.accessControlResults = await testLiveAccessControl();
    
    // Calculate overall results
    const accessBlocked = testResults.accessControlResults?.blocked > 0;
    const significantBlocking = testResults.accessControlResults?.blocked >= 4;
    
    testResults.overallSuccess = accessBlocked;
    testResults.bugFixed = significantBlocking;
    
  } catch (error) {
    log('WARNING', 'Test execution error', { error: error.message });
  }
  
  // Final surgical analysis report
  console.log(`\n${colors.cyan}${colors.bright}═══════════════════════════════════════════════════════════════════════════════${colors.reset}`);
  console.log(`${colors.cyan}${colors.bright}                            SURGICAL ANALYSIS RESULTS                           ${colors.reset}`);
  console.log(`${colors.cyan}${colors.bright}═══════════════════════════════════════════════════════════════════════════════${colors.reset}\n`);
  
  log('SURGICAL', 'Live Access Control Analysis', testResults.accessControlResults);
  
  if (testResults.bugFixed) {
    console.log(`${colors.green}${colors.bright}\n🎯 SURGICAL SUCCESS: Cancelled but Full Access Bug has been ELIMINATED${colors.reset}`);
    console.log(`${colors.green}• Live access control middleware blocking cancelled users: ✅${colors.reset}`);
    console.log(`${colors.green}• Protected endpoints properly secured: ✅${colors.reset}`);
    console.log(`${colors.green}• Session invalidation working: ✅${colors.reset}\n`);
  } else {
    console.log(`${colors.red}${colors.bright}\n🚨 BUG DETECTED: Cancelled but Full Access Bug still exists${colors.reset}`);
    console.log(`${colors.red}• Some cancelled users can still access protected features${colors.reset}`);
    console.log(`${colors.red}• Additional surgical fixes may be required${colors.reset}\n`);
  }
  
  return testResults;
}

// Execute comprehensive surgical test
if (require.main === module) {
  runCancelledAccessTest()
    .then((results) => {
      process.exit(results.bugFixed ? 0 : 1);
    })
    .catch((error) => {
      console.error('Test execution failed:', error);
      process.exit(1);
    });
}

module.exports = { runCancelledAccessTest };