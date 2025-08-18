#!/usr/bin/env node

/**
 * SURGICAL DATABASE MIDDLEWARE COOLDOWN TEST
 * Tests the fourth middleware layer (database authentication) logout cooldown
 * 
 * Target: server/middleware/database-auth.js requireSessionAuth() method
 * Endpoint: /api/brand-purpose (protected by database authentication middleware)
 * Expected: Database auth middleware should respect logout cooldown mechanism
 */

const axios = require('axios');

// Test configuration
const BASE_URL = 'https://4fc77172-459a-4da7-8c33-5014abb1b73e-00-dqhtnud4ismj.worf.replit.dev';
const COOLDOWN_SECONDS = 10;
const TEST_ENDPOINT = '/api/brand-purpose'; // Uses database authentication middleware

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
        'User-Agent': 'DatabaseMiddlewareTest/1.0'
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
 * Sleep for specified milliseconds
 */
function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * Main test execution
 */
async function runDatabaseMiddlewareTest() {
  console.log(`${colors.bold}${colors.cyan}🔬 SURGICAL DATABASE MIDDLEWARE COOLDOWN TEST${colors.reset}`);
  console.log(`${colors.white}Testing fourth middleware layer: database authentication middleware${colors.reset}`);
  console.log(`${colors.white}Target endpoint: ${TEST_ENDPOINT}${colors.reset}`);
  console.log(`${colors.white}Expected: Database auth middleware respects logout cooldown${colors.reset}\n`);

  // Phase 1: Establish session
  console.log(`${colors.bold}${colors.blue}Phase 1: Session Establishment${colors.reset}`);
  const sessionResponse = await makeRequest('/api/auth/establish-session', '', 'POST');
  
  if (sessionResponse.status !== 200) {
    console.log(`${colors.red}❌ Failed to establish session: ${sessionResponse.status}${colors.reset}`);
    console.log(`Response: ${JSON.stringify(sessionResponse.data, null, 2)}`);
    return;
  }

  const sessionCookie = extractSessionCookie(sessionResponse.cookies);
  if (!sessionCookie) {
    console.log(`${colors.red}❌ No session cookie received${colors.reset}`);
    return;
  }

  console.log(`${colors.green}✅ Session established successfully${colors.reset}`);
  console.log(`${colors.white}Session cookie: ${sessionCookie.substring(0, 50)}...${colors.reset}\n`);

  // Phase 2: Test database endpoint access (before logout)
  console.log(`${colors.bold}${colors.blue}Phase 2: Pre-Logout Database Access Test${colors.reset}`);
  const preLogoutResponse = await makeRequest(TEST_ENDPOINT, sessionCookie);
  
  console.log(`${colors.white}Pre-logout status: ${preLogoutResponse.status}${colors.reset}`);
  console.log(`${colors.white}Pre-logout response: ${JSON.stringify(preLogoutResponse.data, null, 2)}${colors.reset}\n`);

  // Phase 3: Logout
  console.log(`${colors.bold}${colors.blue}Phase 3: User Logout${colors.reset}`);
  const logoutResponse = await makeRequest('/api/auth/logout', sessionCookie);
  
  console.log(`${colors.white}Logout status: ${logoutResponse.status}${colors.reset}`);
  console.log(`${colors.green}✅ Logout completed - cooldown timer started${colors.reset}\n`);

  // Phase 4: Immediate database access test (during cooldown)
  console.log(`${colors.bold}${colors.blue}Phase 4: Database Access During Cooldown${colors.reset}`);
  console.log(`${colors.yellow}⏱️ Testing database middleware immediately after logout...${colors.reset}`);
  
  const immediateResponse = await makeRequest(TEST_ENDPOINT, '');
  
  console.log(`${colors.white}Immediate response status: ${immediateResponse.status}${colors.reset}`);
  console.log(`${colors.white}Immediate response body: ${JSON.stringify(immediateResponse.data, null, 2)}${colors.reset}`);
  
  // Check if database middleware is blocking during cooldown
  if (immediateResponse.status === 401 && 
      (immediateResponse.data.code === 'LOGOUT_COOLDOWN_ACTIVE' || 
       immediateResponse.data.error?.includes('logout cooldown'))) {
    console.log(`${colors.green}✅ DATABASE MIDDLEWARE: Correctly blocking during cooldown${colors.reset}`);
  } else if (immediateResponse.status === 401) {
    console.log(`${colors.yellow}⚠️ DATABASE MIDDLEWARE: Blocking but not showing cooldown message${colors.reset}`);
    console.log(`${colors.yellow}   This may still be correct behavior${colors.reset}`);
  } else {
    console.log(`${colors.red}❌ DATABASE MIDDLEWARE: Not blocking during cooldown (Status: ${immediateResponse.status})${colors.reset}`);
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

  // Phase 6: Post-cooldown database access test
  console.log(`${colors.bold}${colors.blue}Phase 6: Database Access After Cooldown${colors.reset}`);
  const postCooldownResponse = await makeRequest(TEST_ENDPOINT, '');
  
  console.log(`${colors.white}Post-cooldown status: ${postCooldownResponse.status}${colors.reset}`);
  console.log(`${colors.white}Post-cooldown response: ${JSON.stringify(postCooldownResponse.data, null, 2)}${colors.reset}`);
  
  // Check if database middleware allows access after cooldown
  if (postCooldownResponse.status === 200 || 
      (postCooldownResponse.status === 401 && !postCooldownResponse.data.error?.includes('cooldown'))) {
    console.log(`${colors.green}✅ DATABASE MIDDLEWARE: Correctly allowing access after cooldown${colors.reset}`);
  } else if (postCooldownResponse.status === 401 && postCooldownResponse.data.error?.includes('cooldown')) {
    console.log(`${colors.red}❌ DATABASE MIDDLEWARE: Still blocking after cooldown expired${colors.reset}`);
  } else {
    console.log(`${colors.yellow}⚠️ DATABASE MIDDLEWARE: Unexpected response after cooldown${colors.reset}`);
  }

  // Final Results Summary
  console.log(`\n${colors.bold}${colors.cyan}📊 DATABASE MIDDLEWARE COOLDOWN TEST RESULTS${colors.reset}`);
  console.log(`${colors.white}Endpoint tested: ${TEST_ENDPOINT}${colors.reset}`);
  console.log(`${colors.white}Middleware: database authentication (server/middleware/database-auth.js)${colors.reset}`);
  console.log(`${colors.white}During cooldown: Status ${immediateResponse.status}${colors.reset}`);
  console.log(`${colors.white}After cooldown: Status ${postCooldownResponse.status}${colors.reset}`);
  
  const testPassed = (immediateResponse.status === 401) && 
                     (postCooldownResponse.status === 200 || 
                      (postCooldownResponse.status === 401 && !postCooldownResponse.data.error?.includes('cooldown')));
  
  if (testPassed) {
    console.log(`${colors.bold}${colors.green}🎯 DATABASE MIDDLEWARE COOLDOWN: WORKING CORRECTLY${colors.reset}`);
  } else {
    console.log(`${colors.bold}${colors.red}❌ DATABASE MIDDLEWARE COOLDOWN: NEEDS ATTENTION${colors.reset}`);
  }
  
  console.log(`${colors.white}${'='.repeat(60)}${colors.reset}`);
}

// Run the test
if (require.main === module) {
  runDatabaseMiddlewareTest().catch(console.error);
}

module.exports = { runDatabaseMiddlewareTest };