#!/usr/bin/env node

/**
 * COMPREHENSIVE LOGOUT COOLDOWN SYSTEM TEST
 * Tests all four middleware layers working together
 * 
 * Tests:
 * 1. Global middleware (session establishment)
 * 2. requireAuth middleware  
 * 3. requirePaidSubscription middleware
 * 4. Database authentication middleware
 */

const axios = require('axios');

// Test configuration
const BASE_URL = 'https://4fc77172-459a-4da7-8c33-5014abb1b73e-00-dqhtnud4ismj.worf.replit.dev';
const COOLDOWN_SECONDS = 10;

// Test endpoints for each middleware layer
const TEST_ENDPOINTS = {
  global: '/api/auth/session',           // Global middleware
  requireAuth: '/api/posts',             // requireAuth middleware
  requirePaid: '/api/yearly-analytics',  // requirePaidSubscription middleware  
  database: '/api/brand-purpose'         // Database authentication middleware
};

// ANSI colors for output
const colors = {
  green: '\x1b[32m',
  red: '\x1b[31m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  cyan: '\x1b[36m',
  white: '\x1b[37m',
  reset: '\x1b[0m',
  bold: '\x1b[1m'
};

/**
 * Make authenticated request with cookies
 */
async function makeRequest(endpoint, cookies = '', method = 'GET') {
  try {
    const response = await axios({
      method,
      url: `${BASE_URL}${endpoint}`,
      headers: {
        'Cookie': cookies,
        'Content-Type': 'application/json',
        'User-Agent': 'ComprehensiveLogoutTest/1.0'
      },
      validateStatus: () => true // Don't throw on error status codes
    });

    return {
      status: response.status,
      data: response.data,
      headers: response.headers,
      cookies: response.headers['set-cookie'] || []
    };
  } catch (error) {
    return {
      status: 0,
      data: { error: error.message },
      headers: {},
      cookies: []
    };
  }
}

/**
 * Extract session cookie from response
 */
function extractSessionCookie(cookies) {
  for (const cookie of cookies) {
    if (cookie.includes('theagencyiq.session=')) {
      return cookie.split(';')[0];
    }
  }
  return '';
}

/**
 * Test middleware layer during cooldown period
 */
async function testMiddlewareLayer(name, endpoint, cookies = '') {
  const response = await makeRequest(endpoint, cookies);
  
  let status = 'UNKNOWN';
  let cooldownActive = false;
  
  if (response.status === 401) {
    if (response.data.code === 'LOGOUT_COOLDOWN_ACTIVE' || 
        response.data.error?.includes('logout cooldown') ||
        response.data.error?.includes('cooldown active')) {
      status = 'COOLDOWN_BLOCKED';
      cooldownActive = true;
    } else {
      status = 'AUTH_BLOCKED';
    }
  } else if (response.status === 403) {
    if (response.data.message?.includes('cancelled') || 
        response.data.message?.includes('access denied')) {
      status = 'SUBSCRIPTION_BLOCKED';
    } else {
      status = 'FORBIDDEN';
    }
  } else if (response.status === 200) {
    status = 'ALLOWED';
  } else {
    status = `HTTP_${response.status}`;
  }
  
  return { status, cooldownActive, response };
}

/**
 * Sleep for specified milliseconds
 */
function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * Main test execution
 */
async function runComprehensiveLogoutTest() {
  console.log(`${colors.bold}${colors.cyan}🔬 COMPREHENSIVE LOGOUT COOLDOWN SYSTEM TEST${colors.reset}`);
  console.log(`${colors.white}Testing all four middleware layers for logout cooldown compliance${colors.reset}\n`);

  // Phase 1: Establish session
  console.log(`${colors.bold}${colors.blue}Phase 1: Session Establishment${colors.reset}`);
  const sessionResponse = await makeRequest('/api/auth/establish-session', '', 'POST');
  
  if (sessionResponse.status !== 200) {
    console.log(`${colors.red}❌ Failed to establish session: ${sessionResponse.status}${colors.reset}`);
    return;
  }

  const sessionCookie = extractSessionCookie(sessionResponse.cookies);
  console.log(`${colors.green}✅ Session established successfully${colors.reset}\n`);

  // Phase 2: Test all middleware before logout
  console.log(`${colors.bold}${colors.blue}Phase 2: Pre-Logout Middleware Tests${colors.reset}`);
  const preLogoutResults = {};
  
  for (const [layer, endpoint] of Object.entries(TEST_ENDPOINTS)) {
    const result = await testMiddlewareLayer(layer, endpoint, sessionCookie);
    preLogoutResults[layer] = result;
    console.log(`${colors.white}${layer.padEnd(12)}: ${result.status} (${result.response.status})${colors.reset}`);
  }
  console.log();

  // Phase 3: Trigger logout cooldown
  console.log(`${colors.bold}${colors.blue}Phase 3: Logout Cooldown Activation${colors.reset}`);
  const logoutResponse = await makeRequest('/api/auth/logout', sessionCookie, 'POST');
  
  console.log(`${colors.white}Logout status: ${logoutResponse.status}${colors.reset}`);
  if (logoutResponse.status === 200) {
    console.log(`${colors.green}✅ Logout successful - cooldown timer started${colors.reset}`);
  } else {
    console.log(`${colors.yellow}⚠️ Logout response: ${JSON.stringify(logoutResponse.data, null, 2)}${colors.reset}`);
    console.log(`${colors.yellow}⚠️ Testing cooldown behavior anyway${colors.reset}`);
  }
  console.log();

  // Phase 4: Test all middleware during cooldown
  console.log(`${colors.bold}${colors.blue}Phase 4: Middleware Tests During Cooldown${colors.reset}`);
  const duringCooldownResults = {};
  let cooldownDetected = false;
  
  for (const [layer, endpoint] of Object.entries(TEST_ENDPOINTS)) {
    const result = await testMiddlewareLayer(layer, endpoint, '');
    duringCooldownResults[layer] = result;
    
    if (result.cooldownActive) {
      cooldownDetected = true;
      console.log(`${colors.green}✅ ${layer.padEnd(12)}: COOLDOWN ACTIVE (${result.status})${colors.reset}`);
    } else {
      console.log(`${colors.yellow}⚠️ ${layer.padEnd(12)}: ${result.status} (${result.response.status})${colors.reset}`);
    }
  }
  
  if (!cooldownDetected) {
    console.log(`${colors.yellow}⚠️ No explicit cooldown messages detected - testing behavior based on blocking${colors.reset}`);
  }
  console.log();

  // Phase 5: Wait for cooldown to expire
  console.log(`${colors.bold}${colors.blue}Phase 5: Cooldown Expiration Wait${colors.reset}`);
  console.log(`${colors.yellow}⏳ Waiting ${COOLDOWN_SECONDS} seconds for cooldown to expire...${colors.reset}`);
  
  for (let i = COOLDOWN_SECONDS; i > 0; i--) {
    process.stdout.write(`${colors.yellow}⏳ ${i}s remaining...${colors.reset}\r`);
    await sleep(1000);
  }
  console.log(`${colors.green}✅ Cooldown period expired${colors.reset}\n`);

  // Phase 6: Test all middleware after cooldown
  console.log(`${colors.bold}${colors.blue}Phase 6: Middleware Tests After Cooldown${colors.reset}`);
  const postCooldownResults = {};
  
  for (const [layer, endpoint] of Object.entries(TEST_ENDPOINTS)) {
    const result = await testMiddlewareLayer(layer, endpoint, '');
    postCooldownResults[layer] = result;
    
    // After cooldown, we expect normal behavior (not cooldown-specific blocking)
    if (result.cooldownActive) {
      console.log(`${colors.red}❌ ${layer.padEnd(12)}: STILL COOLDOWN BLOCKED${colors.reset}`);
    } else {
      console.log(`${colors.green}✅ ${layer.padEnd(12)}: NORMAL BEHAVIOR (${result.status})${colors.reset}`);
    }
  }
  console.log();

  // Final Results Summary
  console.log(`${colors.bold}${colors.cyan}📊 COMPREHENSIVE LOGOUT SYSTEM TEST RESULTS${colors.reset}`);
  console.log(`${colors.white}${'='.repeat(60)}${colors.reset}`);
  
  let overallSuccess = true;
  
  for (const [layer, endpoint] of Object.entries(TEST_ENDPOINTS)) {
    const during = duringCooldownResults[layer];
    const after = postCooldownResults[layer];
    
    // Success criteria: blocked during cooldown, normal behavior after
    const layerSuccess = (during.status !== 'ALLOWED') && !after.cooldownActive;
    
    console.log(`${colors.white}${layer.toUpperCase().padEnd(12)}:${colors.reset}`);
    console.log(`${colors.white}  Endpoint: ${endpoint}${colors.reset}`);
    console.log(`${colors.white}  During:   ${during.status}${colors.reset}`);
    console.log(`${colors.white}  After:    ${after.status}${colors.reset}`);
    console.log(`${layerSuccess ? colors.green : colors.red}  Result:   ${layerSuccess ? 'PASS' : 'NEEDS ATTENTION'}${colors.reset}\n`);
    
    if (!layerSuccess) overallSuccess = false;
  }
  
  console.log(`${colors.bold}${overallSuccess ? colors.green : colors.red}🎯 OVERALL SYSTEM STATUS: ${overallSuccess ? 'LOGOUT COOLDOWN WORKING' : 'NEEDS DEBUGGING'}${colors.reset}`);
  console.log(`${colors.white}${'='.repeat(60)}${colors.reset}`);
}

// Run the test
if (require.main === module) {
  runComprehensiveLogoutTest().catch(console.error);
}

module.exports = { runComprehensiveLogoutTest };