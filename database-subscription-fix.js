/**
 * CRITICAL DATABASE SUBSCRIPTION FIX
 * Update User ID 2 (gailm@macleodglba.com.au) to have the Professional subscription
 */

import axios from 'axios';

const BASE_URL = 'https://4fc77172-459a-4da7-8c33-5014abb1b73e-00-dqhtnud4ismj.worf.replit.dev';

async function fixDatabaseSubscription() {
  console.log('🚨 CRITICAL DATABASE SUBSCRIPTION FIX - Updating User ID 2 with Professional subscription\n');
  
  try {
    // Step 1: Establish session for User ID 2
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
    console.log(`   Current subscription: ${sessionResponse.data.user.subscriptionPlan}`);
    
    // Step 2: Update user subscription in database
    console.log('\n💾 UPDATING DATABASE WITH CORRECT SUBSCRIPTION...');
    
    // Use the internal API to update the user's subscription
    const updateResponse = await axios.put(`${BASE_URL}/api/user`, {
      subscriptionPlan: 'professional',
      stripeCustomerId: 'cus_SStznDRDVG32xg', // Correct customer ID for gailm@macleodglba.com.au
      stripeSubscriptionId: 'sub_1RjgwBS90ymeq6trhbQarOOK', // New subscription ID
      remainingPosts: 31,
      totalPosts: 52
    }, {
      headers: {
        'Content-Type': 'application/json',
        'Cookie': cookieString
      }
    });
    
    console.log(`✅ Database updated successfully`);
    
    // Step 3: Verify the update
    console.log('\n🔍 VERIFYING DATABASE UPDATE...');
    
    const verifyResponse = await axios.get(`${BASE_URL}/api/user`, {
      headers: {
        'Cookie': cookieString
      }
    });
    
    console.log(`✅ Verification complete:`);
    console.log(`   User ID: ${verifyResponse.data.id}`);
    console.log(`   Email: ${verifyResponse.data.email}`);
    console.log(`   Subscription: ${verifyResponse.data.subscriptionPlan}`);
    console.log(`   Stripe Customer: ${verifyResponse.data.stripeCustomerId}`);
    console.log(`   Stripe Subscription: ${verifyResponse.data.stripeSubscriptionId}`);
    console.log(`   Remaining Posts: ${verifyResponse.data.remainingPosts}`);
    console.log(`   Total Posts: ${verifyResponse.data.totalPosts}`);
    
    // Step 4: Test subscription status
    console.log('\n📊 TESTING SUBSCRIPTION STATUS...');
    
    const subscriptionResponse = await axios.get(`${BASE_URL}/api/subscriptions`, {
      headers: {
        'Cookie': cookieString
      }
    });
    
    console.log(`✅ Subscription status verified:`);
    console.log(`   Plan: ${subscriptionResponse.data.subscriptionPlan}`);
    console.log(`   Active: ${subscriptionResponse.data.isActive}`);
    console.log(`   Remaining Posts: ${subscriptionResponse.data.remainingPosts}`);
    console.log(`   Total Posts: ${subscriptionResponse.data.totalPosts}`);
    
    if (verifyResponse.data.subscriptionPlan === 'professional' && 
        verifyResponse.data.email === 'gailm@macleodglba.com.au' &&
        subscriptionResponse.data.isActive) {
      
      console.log('\n🎉 DATABASE FIX SUCCESSFUL!');
      console.log(`✅ User ID 2 (gailm@macleodglba.com.au) now has Professional subscription`);
      console.log(`✅ Subscription Plan: professional`);
      console.log(`✅ Stripe Customer ID: ${verifyResponse.data.stripeCustomerId}`);
      console.log(`✅ Stripe Subscription ID: ${verifyResponse.data.stripeSubscriptionId}`);
      console.log(`✅ Quota: ${verifyResponse.data.remainingPosts}/${verifyResponse.data.totalPosts} posts`);
      console.log(`✅ Status: Active`);
      
      return {
        success: true,
        userId: verifyResponse.data.id,
        email: verifyResponse.data.email,
        subscriptionPlan: verifyResponse.data.subscriptionPlan,
        stripeCustomerId: verifyResponse.data.stripeCustomerId,
        stripeSubscriptionId: verifyResponse.data.stripeSubscriptionId,
        remainingPosts: verifyResponse.data.remainingPosts,
        totalPosts: verifyResponse.data.totalPosts
      };
    } else {
      console.log('\n❌ DATABASE FIX VERIFICATION FAILED');
      return false;
    }
    
  } catch (error) {
    console.error('💥 DATABASE FIX ERROR:', error.message);
    if (error.response) {
      console.error('Response data:', error.response.data);
      console.error('Response status:', error.response.status);
    }
    return false;
  }
}

// Run the database fix
fixDatabaseSubscription()
  .then(result => {
    if (result) {
      console.log('\n🚀 DATABASE SUBSCRIPTION FIX COMPLETED SUCCESSFULLY');
      console.log('gailm@macleodglba.com.au now has the correct Professional subscription in the database');
      process.exit(0);
    } else {
      console.log('\n🔧 DATABASE SUBSCRIPTION FIX FAILED');
      process.exit(1);
    }
  })
  .catch(error => {
    console.error('💥 CRITICAL FAILURE:', error);
    process.exit(1);
  });