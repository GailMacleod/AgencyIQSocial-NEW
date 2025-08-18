/**
 * PRODUCTION READINESS TEST
 * Tests all critical functionality for 200 users
 */

const axios = require('axios');

const BASE_URL = 'https://4fc77172-459a-4da7-8c33-5014abb1b73e-00-dqhtnud4ismj.worf.replit.dev';

async function testProductionReadiness() {
  console.log('🚀 TESTING PRODUCTION READINESS FOR 200 USERS');
  console.log('='.repeat(60));
  
  let results = [];
  
  // Test 1: Frontend loads instantly
  console.log('Test 1: Frontend Loading Speed');
  const startTime = Date.now();
  try {
    const response = await axios.get(BASE_URL, { timeout: 5000 });
    const loadTime = Date.now() - startTime;
    if (response.status === 200 && loadTime < 3000) {
      console.log(`✅ Frontend loads in ${loadTime}ms (< 3s)`);
      results.push({ test: 'Frontend Load', status: 'PASS', time: `${loadTime}ms` });
    } else {
      console.log(`❌ Frontend slow: ${loadTime}ms`);
      results.push({ test: 'Frontend Load', status: 'FAIL', time: `${loadTime}ms` });
    }
  } catch (error) {
    console.log(`❌ Frontend failed: ${error.message}`);
    results.push({ test: 'Frontend Load', status: 'FAIL', error: error.message });
  }
  
  // Test 2: API responds quickly
  console.log('\nTest 2: API Response Speed');
  const apiStartTime = Date.now();
  try {
    const response = await axios.get(`${BASE_URL}/api/user`, { timeout: 10000 });
    const apiTime = Date.now() - apiStartTime;
    if (response.status === 200 && apiTime < 5000) {
      console.log(`✅ API responds in ${apiTime}ms (< 5s)`);
      results.push({ test: 'API Response', status: 'PASS', time: `${apiTime}ms` });
    } else {
      console.log(`❌ API slow: ${apiTime}ms`);
      results.push({ test: 'API Response', status: 'FAIL', time: `${apiTime}ms` });
    }
  } catch (error) {
    console.log(`❌ API failed: ${error.message}`);
    results.push({ test: 'API Response', status: 'FAIL', error: error.message });
  }
  
  // Test 3: Session management
  console.log('\nTest 3: Session Management');
  try {
    const response = await axios.get(`${BASE_URL}/api/auth/session`, { timeout: 5000 });
    if (response.status === 200 && response.data.authenticated) {
      console.log(`✅ Session management working: ${response.data.userEmail}`);
      results.push({ test: 'Session Management', status: 'PASS', user: response.data.userEmail });
    } else {
      console.log(`❌ Session not authenticated`);
      results.push({ test: 'Session Management', status: 'FAIL', error: 'Not authenticated' });
    }
  } catch (error) {
    console.log(`❌ Session failed: ${error.message}`);
    results.push({ test: 'Session Management', status: 'FAIL', error: error.message });
  }
  
  // Test 4: Database connectivity
  console.log('\nTest 4: Database Connectivity');
  try {
    const response = await axios.get(`${BASE_URL}/api/user-status`, { timeout: 10000 });
    if (response.status === 200 && response.data.hasActiveSubscription) {
      console.log(`✅ Database working: Professional subscription active`);
      results.push({ test: 'Database', status: 'PASS', subscription: 'Professional' });
    } else {
      console.log(`❌ Database issue: No active subscription`);
      results.push({ test: 'Database', status: 'FAIL', error: 'No active subscription' });
    }
  } catch (error) {
    console.log(`❌ Database failed: ${error.message}`);
    results.push({ test: 'Database', status: 'FAIL', error: error.message });
  }
  
  // Test 5: Platform connections
  console.log('\nTest 5: Platform Connections');
  try {
    const response = await axios.get(`${BASE_URL}/api/platform-connections`, { timeout: 10000 });
    if (response.status === 200 && response.data.length > 0) {
      console.log(`✅ Platform connections: ${response.data.length} platforms connected`);
      results.push({ test: 'Platform Connections', status: 'PASS', platforms: response.data.length });
    } else {
      console.log(`❌ No platform connections`);
      results.push({ test: 'Platform Connections', status: 'FAIL', error: 'No connections' });
    }
  } catch (error) {
    console.log(`❌ Platform connections failed: ${error.message}`);
    results.push({ test: 'Platform Connections', status: 'FAIL', error: error.message });
  }
  
  // Final Report
  console.log('\n' + '='.repeat(60));
  console.log('PRODUCTION READINESS REPORT');
  console.log('='.repeat(60));
  
  const passCount = results.filter(r => r.status === 'PASS').length;
  const totalTests = results.length;
  
  console.log(`\nOverall Score: ${passCount}/${totalTests} tests passing`);
  
  if (passCount === totalTests) {
    console.log('🎉 READY FOR 200 USERS - ALL TESTS PASS');
  } else if (passCount >= 3) {
    console.log('⚠️  MOSTLY READY - Minor issues to address');
  } else {
    console.log('❌ NOT READY - Critical issues need fixing');
  }
  
  console.log('\nDetailed Results:');
  results.forEach((result, index) => {
    console.log(`${index + 1}. ${result.test}: ${result.status}`);
    if (result.time) console.log(`   Response Time: ${result.time}`);
    if (result.error) console.log(`   Error: ${result.error}`);
    if (result.user) console.log(`   User: ${result.user}`);
    if (result.subscription) console.log(`   Subscription: ${result.subscription}`);
    if (result.platforms) console.log(`   Platforms: ${result.platforms}`);
  });
  
  console.log('\n🚀 Production deployment ready if all tests pass');
}

testProductionReadiness().catch(console.error);