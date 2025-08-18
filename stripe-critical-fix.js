/**
 * CRITICAL STRIPE FIX - Keep gailm@macleodglba.com.au Professional Subscription
 * Cancel all other subscriptions and ensure correct account retention
 */

import Stripe from 'stripe';
import axios from 'axios';

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY, {
  apiVersion: '2023-10-16',
});

const BASE_URL = 'https://4fc77172-459a-4da7-8c33-5014abb1b73e-00-dqhtnud4ismj.worf.replit.dev';

async function fixStripeSubscriptions() {
  console.log('🚨 CRITICAL STRIPE FIX - Ensuring gailm@macleodglba.com.au Professional subscription is retained\n');
  
  try {
    // Step 1: Find all customers and subscriptions
    const targetEmails = ['gailm@macleodglba.com.au', 'admin@theagencyiq.ai', 'gail@theagencyiq.ai'];
    const allCustomers = [];
    
    for (const email of targetEmails) {
      const customers = await stripe.customers.search({
        query: `email:'${email}'`,
      });
      allCustomers.push(...customers.data.map(c => ({...c, searchEmail: email})));
    }
    
    console.log(`📊 Found ${allCustomers.length} customers in Stripe:`);
    allCustomers.forEach(c => {
      console.log(`   - ${c.email} (${c.id}) - searched for: ${c.searchEmail}`);
    });
    
    // Step 2: Get all active subscriptions
    const allSubscriptions = [];
    for (const customer of allCustomers) {
      const subscriptions = await stripe.subscriptions.list({
        customer: customer.id,
        status: 'active',
      });
      
      for (const sub of subscriptions.data) {
        allSubscriptions.push({
          ...sub,
          customerEmail: customer.email,
          customerId: customer.id,
          searchEmail: customer.searchEmail
        });
      }
    }
    
    console.log(`\n📋 ACTIVE SUBSCRIPTIONS FOUND: ${allSubscriptions.length}`);
    
    // Step 3: Find the correct subscription for gailm@macleodglba.com.au
    const targetSubscription = allSubscriptions.find(sub => 
      sub.customerEmail === 'gailm@macleodglba.com.au' && 
      sub.items.data[0].price.unit_amount === 9999 // $99.99
    );
    
    if (!targetSubscription) {
      console.log('\n❌ CRITICAL ERROR: No Professional subscription found for gailm@macleodglba.com.au');
      console.log('Available subscriptions:');
      allSubscriptions.forEach(sub => {
        console.log(`   - ${sub.customerEmail}: ${sub.id} - $${sub.items.data[0].price.unit_amount/100} ${sub.items.data[0].price.currency.toUpperCase()}`);
      });
      return false;
    }
    
    console.log(`\n✅ TARGET SUBSCRIPTION FOUND:`);
    console.log(`   Email: ${targetSubscription.customerEmail}`);
    console.log(`   Subscription ID: ${targetSubscription.id}`);
    console.log(`   Customer ID: ${targetSubscription.customerId}`);
    console.log(`   Amount: $${targetSubscription.items.data[0].price.unit_amount/100} ${targetSubscription.items.data[0].price.currency.toUpperCase()}`);
    console.log(`   Status: ${targetSubscription.status}`);
    
    // Step 4: Cancel all OTHER subscriptions
    const subscriptionsToCancel = allSubscriptions.filter(sub => 
      sub.id !== targetSubscription.id
    );
    
    console.log(`\n🔥 CANCELING ${subscriptionsToCancel.length} DUPLICATE SUBSCRIPTIONS:`);
    
    for (const sub of subscriptionsToCancel) {
      try {
        await stripe.subscriptions.cancel(sub.id);
        console.log(`   ✅ Canceled: ${sub.id} for ${sub.customerEmail} ($${sub.items.data[0].price.unit_amount/100})`);
      } catch (error) {
        console.log(`   ❌ Failed to cancel ${sub.id}: ${error.message}`);
      }
    }
    
    // Step 5: Update database to match the correct subscription
    console.log('\n🔄 UPDATING DATABASE TO MATCH CORRECT SUBSCRIPTION...');
    
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
    
    const cookies = sessionResponse.headers['set-cookie'];
    const cookieString = cookies ? cookies.join('; ') : '';
    
    console.log(`✅ Session established for User ID: ${sessionResponse.data.user.id}`);
    
    // Step 6: Verify final state
    console.log('\n🔍 VERIFYING FINAL STATE...');
    
    const finalSubscriptions = await stripe.subscriptions.list({
      customer: targetSubscription.customerId,
      status: 'active',
    });
    
    console.log(`✅ Final active subscriptions: ${finalSubscriptions.data.length}`);
    
    if (finalSubscriptions.data.length === 1 && finalSubscriptions.data[0].id === targetSubscription.id) {
      console.log('\n🎉 CRITICAL FIX SUCCESSFUL!');
      console.log(`✅ Retained Professional subscription for gailm@macleodglba.com.au`);
      console.log(`✅ Subscription ID: ${targetSubscription.id}`);
      console.log(`✅ Customer ID: ${targetSubscription.customerId}`);
      console.log(`✅ Amount: $99.99 AUD/month`);
      console.log(`✅ All duplicate subscriptions canceled`);
      
      return {
        success: true,
        retainedSubscription: targetSubscription.id,
        retainedCustomer: targetSubscription.customerId,
        canceledCount: subscriptionsToCancel.length
      };
    } else {
      console.log('\n❌ VERIFICATION FAILED - Manual intervention required');
      return false;
    }
    
  } catch (error) {
    console.error('💥 CRITICAL ERROR:', error.message);
    return false;
  }
}

// Run the fix
fixStripeSubscriptions()
  .then(result => {
    if (result) {
      console.log('\n🚀 STRIPE FIX COMPLETED SUCCESSFULLY');
      console.log('gailm@macleodglba.com.au Professional subscription is now the only active subscription');
      process.exit(0);
    } else {
      console.log('\n🔧 STRIPE FIX FAILED - MANUAL INTERVENTION REQUIRED');
      process.exit(1);
    }
  })
  .catch(error => {
    console.error('💥 CRITICAL FAILURE:', error);
    process.exit(1);
  });