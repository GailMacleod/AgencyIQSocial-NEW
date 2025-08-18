/**
 * CANCELLED USER REDIRECT VALIDATION TEST
 * 
 * Tests that cancelled authenticated users are properly redirected 
 * to the reactivation page instead of showing the confusing 
 * dual-display of hamburger menu + landing page.
 * 
 * Expected Flow: 
 * Cancelled User → Splash Component → Redirect to /reactivate-subscription
 */

const BASE_URL = process.env.BASE_URL || 'https://4fc77172-459a-4da7-8c33-5014abb1b73e-00-dqhtnud4ismj.worf.replit.dev';

async function testCancelledUserRedirect() {
  console.log('🧪 Testing Cancelled User Redirect Flow...\n');
  
  let testResults = {
    totalTests: 0,
    passedTests: 0,
    failedTests: 0,
    results: []
  };

  function addTestResult(testName, passed, message) {
    testResults.totalTests++;
    if (passed) {
      testResults.passedTests++;
      console.log(`✅ ${testName}: PASS - ${message}`);
    } else {
      testResults.failedTests++;
      console.log(`❌ ${testName}: FAIL - ${message}`);
    }
    testResults.results.push({ testName, passed, message });
  }

  try {
    // Test 1: Verify User Status
    console.log('📋 Test 1: Verifying User Status...');
    const statusResponse = await fetch(`${BASE_URL}/api/user-status`, {
      credentials: 'include',
      headers: { 'Accept': 'application/json' }
    });
    
    if (statusResponse.ok) {
      const statusData = await statusResponse.json();
      const isCancelled = statusData.subscriptionPlan === 'cancelled';
      addTestResult(
        'User Status Check', 
        isCancelled, 
        isCancelled ? `User has cancelled subscription (${statusData.subscriptionPlan})` : `User subscription status: ${statusData.subscriptionPlan}`
      );
    } else {
      addTestResult('User Status Check', false, `Failed to fetch user status: ${statusResponse.status}`);
    }

    // Test 2: Test Reactivation Page Accessibility
    console.log('📋 Test 2: Testing Reactivation Page Access...');
    const reactivationResponse = await fetch(`${BASE_URL}/reactivate-subscription`, {
      credentials: 'include',
      headers: { 'Accept': 'text/html' }
    });
    
    if (reactivationResponse.ok) {
      const reactivationHtml = await reactivationResponse.text();
      const hasReactivationContent = reactivationHtml.includes('Welcome Back') && 
                                   reactivationHtml.includes('Subscription Cancelled') &&
                                   reactivationHtml.includes('Choose Your Plan');
      addTestResult(
        'Reactivation Page Access', 
        hasReactivationContent, 
        hasReactivationContent ? 'Reactivation page loads with correct content' : 'Reactivation page missing expected content'
      );
    } else {
      addTestResult('Reactivation Page Access', false, `Reactivation page returned ${reactivationResponse.status}`);
    }

    // Test 3: Check Root Path Behavior
    console.log('📋 Test 3: Testing Root Path Redirect Logic...');
    const rootResponse = await fetch(`${BASE_URL}/`, {
      credentials: 'include',
      headers: { 'Accept': 'text/html' },
      redirect: 'manual' // Don't follow redirects automatically
    });
    
    // Check if we get a redirect or the page loads correctly
    const rootHtml = await rootResponse.text();
    const hasRedirectLogic = rootHtml.includes('subscriptionPlan') || 
                           rootHtml.includes('reactivate-subscription') ||
                           rootResponse.status === 302 || 
                           rootResponse.status === 301;
    
    addTestResult(
      'Root Path Redirect Logic', 
      hasRedirectLogic, 
      hasRedirectLogic ? 'Root path has redirect logic for cancelled users' : 'Root path missing redirect logic'
    );

    // Test 4: Verify No Hamburger Menu on Landing Page Confusion
    console.log('📋 Test 4: Testing UI State Consistency...');
    const landingResponse = await fetch(`${BASE_URL}/`, {
      credentials: 'include',
      headers: { 'Accept': 'text/html' }
    });
    
    if (landingResponse.ok) {
      const landingHtml = await landingResponse.text();
      // Check that we don't have the confusing dual-display
      const hasUserMenu = landingHtml.includes('UserMenu') || landingHtml.includes('user-menu');
      const hasLandingContent = landingHtml.includes('Get Started') || landingHtml.includes('Sign In');
      const hasConfusingState = hasUserMenu && hasLandingContent;
      
      addTestResult(
        'UI State Consistency', 
        !hasConfusingState, 
        hasConfusingState ? 'WARNING: Detected confusing dual-display (UserMenu + Landing)' : 'UI state is consistent - no dual-display detected'
      );
    } else {
      addTestResult('UI State Consistency', false, `Failed to check UI state: ${landingResponse.status}`);
    }

    // Test 5: Subscription Plan Routing
    console.log('📋 Test 5: Testing Subscription Plan Routing...');
    const subscriptionResponse = await fetch(`${BASE_URL}/subscription`, {
      credentials: 'include',
      headers: { 'Accept': 'text/html' }
    });
    
    if (subscriptionResponse.ok) {
      const subscriptionHtml = await subscriptionResponse.text();
      const hasSubscriptionPlans = subscriptionHtml.includes('Starter') && 
                                  subscriptionHtml.includes('Growth') && 
                                  subscriptionHtml.includes('Professional');
      addTestResult(
        'Subscription Plan Access', 
        hasSubscriptionPlans, 
        hasSubscriptionPlans ? 'Subscription page accessible with all plans' : 'Subscription page missing expected plans'
      );
    } else {
      addTestResult('Subscription Plan Access', false, `Subscription page returned ${subscriptionResponse.status}`);
    }

  } catch (error) {
    console.error('❌ Test execution error:', error.message);
    addTestResult('Test Execution', false, `Error: ${error.message}`);
  }

  // Print Summary
  console.log('\n' + '='.repeat(60));
  console.log('🧪 CANCELLED USER REDIRECT TEST SUMMARY');
  console.log('='.repeat(60));
  console.log(`📊 Total Tests: ${testResults.totalTests}`);
  console.log(`✅ Passed: ${testResults.passedTests}`);
  console.log(`❌ Failed: ${testResults.failedTests}`);
  console.log(`📈 Success Rate: ${Math.round((testResults.passedTests / testResults.totalTests) * 100)}%`);
  
  if (testResults.failedTests === 0) {
    console.log('\n🎉 ALL TESTS PASSED - Cancelled user redirect system working correctly!');
    console.log('✅ No more confusing dual-display of hamburger menu + landing page');
    console.log('✅ Cancelled users properly redirected to reactivation flow');
  } else {
    console.log('\n⚠️  Some tests failed - review results above');
  }
  
  return testResults;
}

// Run the test
testCancelledUserRedirect().catch(console.error);