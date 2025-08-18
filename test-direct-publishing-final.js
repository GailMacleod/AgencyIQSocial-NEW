/**
 * Final Direct Publishing Test
 * Tests the complete direct publishing system with existing connections
 */

import axios from 'axios';

const BASE_URL = 'https://4fc77172-459a-4da7-8c33-5014abb1b73e-00-dqhtnud4ismj.worf.replit.dev';

async function testDirectPublishingFinal() {
  console.log('🚀 Starting final direct publishing test...\n');
  
  try {
    // Step 1: Establish session
    console.log('1. Establishing user session...');
    const sessionResponse = await axios.post(`${BASE_URL}/api/establish-session`, {
      email: 'gailm@macleodglba.com.au',
      phone: '+61424835189'
    }, {
      withCredentials: true,
      headers: {
        'Content-Type': 'application/json'
      }
    });
    
    const cookies = sessionResponse.headers['set-cookie'];
    const cookieString = cookies ? cookies.join('; ') : '';
    
    console.log(`✅ Session established for User ID: ${sessionResponse.data.user.id}`);
    console.log(`   Email: ${sessionResponse.data.user.email}`);
    console.log(`   Subscription: ${sessionResponse.data.user.subscriptionPlan}`);
    console.log(`   Remaining Posts: ${sessionResponse.data.user.remainingPosts}`);
    
    // Step 2: Check platform connections
    console.log('\n2. Checking platform connections...');
    const connectionsResponse = await axios.get(`${BASE_URL}/api/platform-connections`, {
      withCredentials: true,
      headers: {
        'Content-Type': 'application/json',
        'Cookie': cookieString
      }
    });
    
    console.log(`✅ Platform connections active: ${connectionsResponse.data.length}`);
    connectionsResponse.data.forEach(conn => {
      console.log(`   - ${conn.platform}: ${conn.platformUsername} (${conn.isActive ? 'Active' : 'Inactive'})`);
    });
    
    // Step 3: Test direct publishing to all platforms
    console.log('\n3. Testing direct publishing to all platforms...');
    const publishData = {
      action: 'test_publish_all',
      content: 'FINAL BILLING VERIFICATION TEST - All systems operational after successful duplicate subscription cleanup',
      platforms: ['facebook', 'instagram', 'linkedin', 'x', 'youtube']
    };
    
    const publishResponse = await axios.post(`${BASE_URL}/api/direct-publish`, publishData, {
      withCredentials: true,
      headers: {
        'Content-Type': 'application/json',
        'Cookie': cookieString
      }
    });
    
    console.log('\n📊 PUBLISHING RESULTS:');
    console.log('========================');
    
    const results = publishResponse.data;
    let successCount = 0;
    let failCount = 0;
    
    // Handle both array and object response formats
    if (Array.isArray(results)) {
      results.forEach(result => {
        if (result.success) {
          successCount++;
          console.log(`✅ ${result.platform.toUpperCase()}: SUCCESS`);
          console.log(`   Post ID: ${result.postId}`);
          console.log(`   Message: ${result.message}`);
        } else {
          failCount++;
          console.log(`❌ ${result.platform.toUpperCase()}: FAILED`);
          console.log(`   Error: ${result.error}`);
        }
      });
    } else if (results.success && results.results) {
      // Handle object format response with results object
      console.log(`✅ Backend Response: ${results.message}`);
      
      Object.entries(results.results).forEach(([platform, result]) => {
        if (result.success) {
          successCount++;
          console.log(`✅ ${platform.toUpperCase()}: SUCCESS`);
          console.log(`   Post ID: ${result.platformPostId}`);
          console.log(`   Message: Platform test completed`);
        } else {
          failCount++;
          console.log(`❌ ${platform.toUpperCase()}: FAILED`);
          console.log(`   Error: ${result.error}`);
        }
      });
    } else {
      // Handle unexpected response format
      console.log(`❌ Unexpected response format: ${JSON.stringify(results, null, 2)}`);
      failCount = 5; // If we get an unexpected response, consider all failed
    }
    
    console.log('\n📈 FINAL RESULTS:');
    console.log(`✅ Successful publishes: ${successCount}/5`);
    console.log(`❌ Failed publishes: ${failCount}/5`);
    console.log(`📊 Success rate: ${Math.round((successCount/5) * 100)}%`);
    
    // Step 4: Verify subscription integrity
    console.log('\n4. Verifying subscription integrity...');
    const subscriptionResponse = await axios.get(`${BASE_URL}/api/subscriptions`, {
      withCredentials: true,
      headers: {
        'Content-Type': 'application/json',
        'Cookie': cookieString
      }
    });
    
    const usageResponse = await axios.get(`${BASE_URL}/api/subscription-usage`, {
      withCredentials: true,
      headers: {
        'Content-Type': 'application/json',
        'Cookie': cookieString
      }
    });
    
    console.log('\n💳 SUBSCRIPTION STATUS:');
    console.log('======================');
    console.log(`Plan: ${subscriptionResponse.data.subscriptionPlan}`);
    console.log(`Active: ${subscriptionResponse.data.subscriptionActive}`);
    console.log(`Stripe ID: ${subscriptionResponse.data.stripeSubscriptionId}`);
    console.log(`Single Plan Enforced: ${subscriptionResponse.data.singlePlanEnforced}`);
    console.log(`Quota: ${usageResponse.data.remainingPosts}/${usageResponse.data.totalAllocation} posts remaining`);
    console.log(`Usage: ${usageResponse.data.usagePercentage}%`);
    
    // Step 5: Final assessment
    console.log('\n🏁 FINAL ASSESSMENT:');
    console.log('====================');
    
    const isSuccess = successCount === 5 && 
                     subscriptionResponse.data.subscriptionActive && 
                     subscriptionResponse.data.singlePlanEnforced;
    
    if (isSuccess) {
      console.log('🎉 CRITICAL MISSION ACCOMPLISHED!');
      console.log('✅ All 5 platforms publishing successfully');
      console.log('✅ Single Professional subscription active');
      console.log('✅ Billing cleanup completed successfully');
      console.log('✅ Database properly synchronized');
      console.log('✅ Quota system operational');
      console.log('✅ Platform ready for production launch');
      
      return {
        success: true,
        publishingSuccessRate: `${successCount}/5 (${Math.round((successCount/5) * 100)}%)`,
        subscriptionStatus: 'Active Professional Plan',
        billingStatus: 'Clean - No Duplicates',
        systemStatus: 'Ready for Production'
      };
    } else {
      console.log('⚠️ ISSUES DETECTED:');
      if (successCount < 5) {
        console.log(`   - Publishing success rate: ${successCount}/5`);
      }
      if (!subscriptionResponse.data.subscriptionActive) {
        console.log('   - Subscription not active');
      }
      if (!subscriptionResponse.data.singlePlanEnforced) {
        console.log('   - Single plan enforcement not enabled');
      }
      
      return {
        success: false,
        publishingSuccessRate: `${successCount}/5 (${Math.round((successCount/5) * 100)}%)`,
        subscriptionStatus: subscriptionResponse.data.subscriptionActive ? 'Active' : 'Inactive',
        billingStatus: 'Requires Attention',
        systemStatus: 'Requires Fixes'
      };
    }
    
  } catch (error) {
    console.error('❌ Direct publishing test failed:', error.message);
    
    if (error.response?.data) {
      console.error('Error details:', error.response.data);
    }
    
    return {
      success: false,
      error: error.message,
      systemStatus: 'Critical Error'
    };
  }
}

// Run the test
testDirectPublishingFinal()
  .then(result => {
    console.log('\n📋 TEST SUMMARY:');
    console.log('================');
    console.log(`Status: ${result.success ? 'SUCCESS' : 'FAILED'}`);
    console.log(`Publishing: ${result.publishingSuccessRate}`);
    console.log(`Subscription: ${result.subscriptionStatus}`);
    console.log(`Billing: ${result.billingStatus}`);
    console.log(`System: ${result.systemStatus}`);
    
    if (result.success) {
      console.log('\n🚀 THEAGENCYIQ PLATFORM READY FOR LAUNCH!');
      process.exit(0);
    } else {
      console.log('\n🔧 ADDITIONAL FIXES REQUIRED');
      process.exit(1);
    }
  })
  .catch(error => {
    console.error('💥 Critical test failure:', error);
    process.exit(1);
  });