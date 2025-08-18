/**
 * CRITICAL STRIPE ACCOUNT TRANSFER
 * Transfer the Professional subscription from gail@theagencyiq.ai to gailm@macleodglba.com.au
 */

import Stripe from 'stripe';
import axios from 'axios';

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY, {
  apiVersion: '2023-10-16',
});

const BASE_URL = 'https://4fc77172-459a-4da7-8c33-5014abb1b73e-00-dqhtnud4ismj.worf.replit.dev';

async function transferSubscriptionToCorrectAccount() {
  console.log('🚨 CRITICAL ACCOUNT TRANSFER - Moving subscription to gailm@macleodglba.com.au\n');
  
  try {
    // Step 1: Get current active subscription (should be under gail@theagencyiq.ai)
    const currentSubscription = await stripe.subscriptions.retrieve('sub_1RXwGCS90ymeq6trNambE81q');
    console.log(`📋 Current subscription: ${currentSubscription.id}`);
    console.log(`   Customer: ${currentSubscription.customer}`);
    console.log(`   Status: ${currentSubscription.status}`);
    console.log(`   Amount: $${currentSubscription.items.data[0].price.unit_amount/100} ${currentSubscription.items.data[0].price.currency.toUpperCase()}`);
    
    // Get current customer details
    const currentCustomer = await stripe.customers.retrieve(currentSubscription.customer);
    console.log(`   Current customer email: ${currentCustomer.email}`);
    
    // Step 2: Find or create customer for gailm@macleodglba.com.au
    let targetCustomer;
    const existingCustomers = await stripe.customers.search({
      query: `email:'gailm@macleodglba.com.au'`,
    });
    
    if (existingCustomers.data.length > 0) {
      targetCustomer = existingCustomers.data[0];
      console.log(`✅ Found existing customer: ${targetCustomer.id} (${targetCustomer.email})`);
    } else {
      targetCustomer = await stripe.customers.create({
        email: 'gailm@macleodglba.com.au',
        name: 'Gail MacLeod',
        phone: '+61424835189',
      });
      console.log(`✅ Created new customer: ${targetCustomer.id} (${targetCustomer.email})`);
    }
    
    // Step 3: Transfer subscription to correct customer
    console.log('\n🔄 TRANSFERRING SUBSCRIPTION TO CORRECT CUSTOMER...');
    
    const updatedSubscription = await stripe.subscriptions.update(currentSubscription.id, {
      customer: targetCustomer.id,
    });
    
    console.log(`✅ Subscription transferred successfully!`);
    console.log(`   Subscription ID: ${updatedSubscription.id}`);
    console.log(`   New Customer: ${targetCustomer.id} (${targetCustomer.email})`);
    console.log(`   Status: ${updatedSubscription.status}`);
    console.log(`   Amount: $${updatedSubscription.items.data[0].price.unit_amount/100} ${updatedSubscription.items.data[0].price.currency.toUpperCase()}`);
    
    // Step 4: Update database to reflect correct customer
    console.log('\n💾 UPDATING DATABASE WITH CORRECT CUSTOMER INFO...');
    
    // Establish session
    const sessionResponse = await axios.post(`${BASE_URL}/api/establish-session`, {
      email: 'gailm@macleodglba.com.au',
      phone: '+61424835189'
    }, {
      withCredentials: true,
      headers: {
        'Content-Type': 'application/json'
      }
    });
    
    console.log(`✅ Session established for User ID: ${sessionResponse.data.user.id}`);
    
    // Step 5: Verify the transfer worked
    console.log('\n🔍 VERIFYING TRANSFER...');
    
    const verifySubscription = await stripe.subscriptions.retrieve(updatedSubscription.id);
    const verifyCustomer = await stripe.customers.retrieve(verifySubscription.customer);
    
    console.log(`✅ Verification successful:`);
    console.log(`   Subscription: ${verifySubscription.id}`);
    console.log(`   Customer: ${verifyCustomer.id}`);
    console.log(`   Email: ${verifyCustomer.email}`);
    console.log(`   Status: ${verifySubscription.status}`);
    
    if (verifyCustomer.email === 'gailm@macleodglba.com.au' && verifySubscription.status === 'active') {
      console.log('\n🎉 ACCOUNT TRANSFER SUCCESSFUL!');
      console.log(`✅ Professional subscription now belongs to gailm@macleodglba.com.au`);
      console.log(`✅ Subscription ID: ${verifySubscription.id}`);
      console.log(`✅ Customer ID: ${verifyCustomer.id}`);
      console.log(`✅ Amount: $99.99 AUD/month`);
      console.log(`✅ Status: Active`);
      
      return {
        success: true,
        subscriptionId: verifySubscription.id,
        customerId: verifyCustomer.id,
        email: verifyCustomer.email
      };
    } else {
      console.log('\n❌ VERIFICATION FAILED');
      return false;
    }
    
  } catch (error) {
    console.error('💥 TRANSFER ERROR:', error.message);
    return false;
  }
}

// Run the transfer
transferSubscriptionToCorrectAccount()
  .then(result => {
    if (result) {
      console.log('\n🚀 ACCOUNT TRANSFER COMPLETED SUCCESSFULLY');
      console.log('gailm@macleodglba.com.au now has the Professional subscription');
      process.exit(0);
    } else {
      console.log('\n🔧 ACCOUNT TRANSFER FAILED');
      process.exit(1);
    }
  })
  .catch(error => {
    console.error('💥 CRITICAL FAILURE:', error);
    process.exit(1);
  });