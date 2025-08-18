/**
 * Update customer phone number for gailm@macleodglba.com.au
 */

import Stripe from 'stripe';

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY, {
  apiVersion: '2023-10-16',
});

async function updateCustomerPhone() {
  console.log('📞 UPDATING CUSTOMER PHONE NUMBER');
  console.log('Setting phone +61424835189 for gailm@macleodglba.com.au\n');
  
  try {
    // Get the customer with active subscription
    const customerId = 'cus_SStznDRDVG32xg';
    const targetPhone = '+61424835189';
    
    console.log(`🔍 Updating customer ${customerId}...`);
    
    // Update the customer phone number
    const updatedCustomer = await stripe.customers.update(customerId, {
      phone: targetPhone
    });
    
    console.log('✅ Customer updated successfully:');
    console.log(`   Customer ID: ${updatedCustomer.id}`);
    console.log(`   Email: ${updatedCustomer.email}`);
    console.log(`   Phone: ${updatedCustomer.phone}`);
    console.log(`   Created: ${new Date(updatedCustomer.created * 1000).toISOString()}`);
    
    // Verify the update
    const verifyCustomer = await stripe.customers.retrieve(customerId);
    console.log(`\n🎯 VERIFICATION:`);
    console.log(`   Phone set correctly: ${verifyCustomer.phone === targetPhone}`);
    console.log(`   Current phone: ${verifyCustomer.phone}`);
    
    return true;
    
  } catch (error) {
    console.error('💥 UPDATE ERROR:', error.message);
    return false;
  }
}

// Run update
updateCustomerPhone()
  .then(success => {
    if (success) {
      console.log('\n🎉 CUSTOMER PHONE UPDATE COMPLETED');
      console.log('✅ Phone number +61424835189 set for gailm@macleodglba.com.au');
      process.exit(0);
    } else {
      console.log('\n❌ CUSTOMER PHONE UPDATE FAILED');
      process.exit(1);
    }
  })
  .catch(error => {
    console.error('💥 CRITICAL ERROR:', error);
    process.exit(1);
  });