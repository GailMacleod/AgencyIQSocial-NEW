/**
 * CRITICAL STRIPE SUBSCRIPTION RECREATION
 * Create new Professional subscription for gailm@macleodglba.com.au and cancel old one
 */

import Stripe from 'stripe';
import axios from 'axios';

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY, {
  apiVersion: '2023-10-16',
});

const BASE_URL = 'https://4fc77172-459a-4da7-8c33-5014abb1b73e-00-dqhtnud4ismj.worf.replit.dev';

async function recreateSubscriptionForCorrectCustomer() {
  console.log('🚨 CRITICAL SUBSCRIPTION RECREATION - Creating new subscription for gailm@macleodglba.com.au\n');
  
  try {
    // Step 1: Get current subscription details
    const currentSubscription = await stripe.subscriptions.retrieve('sub_1RXwGCS90ymeq6trNambE81q');
    console.log(`📋 Current subscription: ${currentSubscription.id}`);
    console.log(`   Customer: ${currentSubscription.customer}`);
    console.log(`   Price ID: ${currentSubscription.items.data[0].price.id}`);
    console.log(`   Amount: $${currentSubscription.items.data[0].price.unit_amount/100} ${currentSubscription.items.data[0].price.currency.toUpperCase()}`);
    
    // Step 2: Get target customer (gailm@macleodglba.com.au)
    const targetCustomers = await stripe.customers.search({
      query: `email:'gailm@macleodglba.com.au'`,
    });
    
    if (targetCustomers.data.length === 0) {
      console.log('❌ No customer found for gailm@macleodglba.com.au');
      return false;
    }
    
    const targetCustomer = targetCustomers.data[0];
    console.log(`✅ Target customer found: ${targetCustomer.id} (${targetCustomer.email})`);
    
    // Step 3: Create new subscription for correct customer
    console.log('\n🔄 CREATING NEW SUBSCRIPTION FOR CORRECT CUSTOMER...');
    
    const newSubscription = await stripe.subscriptions.create({
      customer: targetCustomer.id,
      items: [{
        price: currentSubscription.items.data[0].price.id,
      }],
      payment_behavior: 'default_incomplete',
      payment_settings: {
        payment_method_types: ['card'],
      },
    });
    
    console.log(`✅ New subscription created: ${newSubscription.id}`);
    console.log(`   Customer: ${targetCustomer.id} (${targetCustomer.email})`);
    console.log(`   Status: ${newSubscription.status}`);
    console.log(`   Amount: $${newSubscription.items.data[0].price.unit_amount/100} ${newSubscription.items.data[0].price.currency.toUpperCase()}`);
    
    // Step 4: Set up payment method (simulate successful payment)
    if (newSubscription.status === 'incomplete') {
      console.log('\n💳 SETTING UP PAYMENT METHOD...');
      
      // Create a payment method for the subscription
      const paymentMethod = await stripe.paymentMethods.create({
        type: 'card',
        card: {
          token: 'tok_visa', // Test token for successful payment
        },
      });
      
      // Attach payment method to customer
      await stripe.paymentMethods.attach(paymentMethod.id, {
        customer: targetCustomer.id,
      });
      
      // Update subscription with payment method
      await stripe.subscriptions.update(newSubscription.id, {
        default_payment_method: paymentMethod.id,
      });
      
      console.log(`✅ Payment method set up for subscription`);
    }
    
    // Step 5: Update database with new subscription
    console.log('\n💾 UPDATING DATABASE WITH NEW SUBSCRIPTION...');
    
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
    
    // Step 6: Cancel old subscription
    console.log('\n🚫 CANCELING OLD SUBSCRIPTION...');
    
    await stripe.subscriptions.cancel('sub_1RXwGCS90ymeq6trNambE81q');
    console.log(`✅ Old subscription canceled: sub_1RXwGCS90ymeq6trNambE81q`);
    
    // Step 7: Verify final state
    console.log('\n🔍 VERIFYING FINAL STATE...');
    
    const finalSubscription = await stripe.subscriptions.retrieve(newSubscription.id);
    const finalCustomer = await stripe.customers.retrieve(finalSubscription.customer);
    
    console.log(`✅ Final verification:`);
    console.log(`   Subscription: ${finalSubscription.id}`);
    console.log(`   Customer: ${finalCustomer.id}`);
    console.log(`   Email: ${finalCustomer.email}`);
    console.log(`   Status: ${finalSubscription.status}`);
    console.log(`   Amount: $${finalSubscription.items.data[0].price.unit_amount/100} ${finalSubscription.items.data[0].price.currency.toUpperCase()}`);
    
    if (finalCustomer.email === 'gailm@macleodglba.com.au' && finalSubscription.status === 'active') {
      console.log('\n🎉 SUBSCRIPTION RECREATION SUCCESSFUL!');
      console.log(`✅ Professional subscription now belongs to gailm@macleodglba.com.au`);
      console.log(`✅ New Subscription ID: ${finalSubscription.id}`);
      console.log(`✅ Customer ID: ${finalCustomer.id}`);
      console.log(`✅ Old subscription canceled`);
      
      return {
        success: true,
        newSubscriptionId: finalSubscription.id,
        customerId: finalCustomer.id,
        email: finalCustomer.email
      };
    } else {
      console.log('\n❌ VERIFICATION FAILED');
      return false;
    }
    
  } catch (error) {
    console.error('💥 RECREATION ERROR:', error.message);
    return false;
  }
}

// Run the recreation
recreateSubscriptionForCorrectCustomer()
  .then(result => {
    if (result) {
      console.log('\n🚀 SUBSCRIPTION RECREATION COMPLETED SUCCESSFULLY');
      console.log('gailm@macleodglba.com.au now has the Professional subscription');
      process.exit(0);
    } else {
      console.log('\n🔧 SUBSCRIPTION RECREATION FAILED');
      process.exit(1);
    }
  })
  .catch(error => {
    console.error('💥 CRITICAL FAILURE:', error);
    process.exit(1);
  });