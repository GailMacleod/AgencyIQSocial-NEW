/**
 * Stripe Subscription Audit and Cleanup
 * Identifies and cancels duplicate subscriptions for specified user accounts
 */

import Stripe from 'stripe';

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY, {
  apiVersion: '2023-10-16',
});

async function auditAndCleanupSubscriptions() {
  console.log('🔍 Starting Stripe subscription audit and cleanup...\n');
  
  const targetEmails = ['gailm@macleodglba.com.au', 'admin@theagencyiq.ai', 'gail@theagencyiq.ai'];
  const targetPhone = '+61424835189';
  
  try {
    // Step 1: Find all customers for target emails
    console.log('1. Finding Stripe customers for target accounts...');
    const customers = [];
    
    for (const email of targetEmails) {
      try {
        const customerSearch = await stripe.customers.search({
          query: `email:'${email}'`,
        });
        
        if (customerSearch.data.length > 0) {
          customers.push(...customerSearch.data);
          console.log(`✅ Found ${customerSearch.data.length} customer(s) for ${email}`);
        } else {
          console.log(`⚠️ No customers found for ${email}`);
        }
      } catch (error) {
        console.error(`❌ Error searching for ${email}:`, error.message);
      }
    }
    
    // Step 2: Get all subscriptions for found customers
    console.log('\n2. Retrieving all subscriptions...');
    const allSubscriptions = [];
    
    for (const customer of customers) {
      try {
        const subscriptions = await stripe.subscriptions.list({
          customer: customer.id,
          limit: 100,
        });
        
        for (const subscription of subscriptions.data) {
          allSubscriptions.push({
            id: subscription.id,
            customer_id: customer.id,
            customer_email: customer.email,
            status: subscription.status,
            current_period_start: new Date(subscription.current_period_start * 1000),
            current_period_end: new Date(subscription.current_period_end * 1000),
            amount: subscription.items.data[0]?.price?.unit_amount || 0,
            currency: subscription.items.data[0]?.price?.currency || 'usd',
            price_id: subscription.items.data[0]?.price?.id,
            created: new Date(subscription.created * 1000)
          });
        }
        
        console.log(`✅ Found ${subscriptions.data.length} subscription(s) for ${customer.email}`);
      } catch (error) {
        console.error(`❌ Error retrieving subscriptions for ${customer.email}:`, error.message);
      }
    }
    
    // Step 3: Analyze subscriptions
    console.log('\n3. Subscription analysis:');
    console.log(`📊 Total subscriptions found: ${allSubscriptions.length}`);
    
    const activeSubscriptions = allSubscriptions.filter(sub => 
      sub.status === 'active' || sub.status === 'trialing'
    );
    
    console.log(`📊 Active subscriptions: ${activeSubscriptions.length}`);
    
    // Group by email to identify duplicates
    const subscriptionsByEmail = {};
    activeSubscriptions.forEach(sub => {
      if (!subscriptionsByEmail[sub.customer_email]) {
        subscriptionsByEmail[sub.customer_email] = [];
      }
      subscriptionsByEmail[sub.customer_email].push(sub);
    });
    
    // Step 4: Display current subscriptions
    console.log('\n4. Current active subscriptions:');
    Object.entries(subscriptionsByEmail).forEach(([email, subs]) => {
      console.log(`\n📧 ${email}:`);
      subs.forEach((sub, index) => {
        console.log(`  ${index + 1}. ID: ${sub.id}`);
        console.log(`     Status: ${sub.status}`);
        console.log(`     Amount: ${sub.currency.toUpperCase()} ${sub.amount / 100}`);
        console.log(`     Created: ${sub.created.toISOString()}`);
        console.log(`     Current period: ${sub.current_period_start.toISOString()} - ${sub.current_period_end.toISOString()}`);
      });
    });
    
    // Step 5: Identify target subscription to keep (Professional tier $99.99)
    console.log('\n5. Identifying target subscription to keep...');
    const professionalTierAmount = 9999; // $99.99 in cents
    
    let targetSubscription = null;
    let subscriptionsToCancel = [];
    
    // Look for Professional tier subscription
    for (const subscription of activeSubscriptions) {
      if (subscription.amount === professionalTierAmount) {
        if (!targetSubscription) {
          targetSubscription = subscription;
          console.log(`✅ Target subscription found: ${subscription.id} (${subscription.customer_email})`);
        } else {
          subscriptionsToCancel.push(subscription);
        }
      } else {
        subscriptionsToCancel.push(subscription);
      }
    }
    
    // If no Professional tier found, keep the most recent active subscription
    if (!targetSubscription && activeSubscriptions.length > 0) {
      const sortedByDate = activeSubscriptions.sort((a, b) => b.created - a.created);
      targetSubscription = sortedByDate[0];
      subscriptionsToCancel = sortedByDate.slice(1);
      console.log(`⚠️ No Professional tier found, keeping most recent: ${targetSubscription.id}`);
    }
    
    // Step 6: Cancel duplicate subscriptions
    console.log('\n6. Canceling duplicate subscriptions...');
    const cancellationResults = [];
    
    for (const subscription of subscriptionsToCancel) {
      try {
        console.log(`🔄 Canceling subscription ${subscription.id} for ${subscription.customer_email}...`);
        
        const canceledSubscription = await stripe.subscriptions.cancel(subscription.id, {
          prorate: false
        });
        
        cancellationResults.push({
          id: subscription.id,
          customer_email: subscription.customer_email,
          amount: subscription.amount,
          status: 'canceled',
          canceled_at: new Date()
        });
        
        console.log(`✅ Successfully canceled subscription ${subscription.id}`);
      } catch (error) {
        console.error(`❌ Failed to cancel subscription ${subscription.id}:`, error.message);
        cancellationResults.push({
          id: subscription.id,
          customer_email: subscription.customer_email,
          amount: subscription.amount,
          status: 'error',
          error: error.message
        });
      }
    }
    
    // Step 7: Final report
    console.log('\n7. CLEANUP REPORT:');
    console.log(`📊 Total subscriptions processed: ${allSubscriptions.length}`);
    console.log(`📊 Active subscriptions found: ${activeSubscriptions.length}`);
    console.log(`📊 Subscriptions canceled: ${cancellationResults.filter(r => r.status === 'canceled').length}`);
    console.log(`📊 Cancellation errors: ${cancellationResults.filter(r => r.status === 'error').length}`);
    
    if (targetSubscription) {
      console.log(`\n✅ RETAINED SUBSCRIPTION:`);
      console.log(`   ID: ${targetSubscription.id}`);
      console.log(`   Customer: ${targetSubscription.customer_email}`);
      console.log(`   Amount: ${targetSubscription.currency.toUpperCase()} ${targetSubscription.amount / 100}/month`);
      console.log(`   Status: ${targetSubscription.status}`);
    }
    
    if (cancellationResults.length > 0) {
      console.log(`\n❌ CANCELED SUBSCRIPTIONS:`);
      cancellationResults.forEach(result => {
        console.log(`   ${result.id} (${result.customer_email}) - ${result.status}`);
        if (result.error) {
          console.log(`     Error: ${result.error}`);
        }
      });
    }
    
    return {
      totalSubscriptions: allSubscriptions.length,
      activeSubscriptions: activeSubscriptions.length,
      targetSubscription,
      cancellationResults,
      success: cancellationResults.filter(r => r.status === 'canceled').length
    };
    
  } catch (error) {
    console.error('❌ Subscription audit failed:', error);
    throw error;
  }
}

// Run the audit
auditAndCleanupSubscriptions()
  .then(result => {
    console.log('\n🏁 Subscription cleanup completed successfully!');
    process.exit(0);
  })
  .catch(error => {
    console.error('💥 Subscription cleanup failed:', error);
    process.exit(1);
  });