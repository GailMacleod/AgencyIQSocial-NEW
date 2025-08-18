const axios = require('axios');

// Configuration
const BASE_URL = 'http://localhost:5000';
const TEST_EMAIL = 'gailm@macleodglba.com.au';

async function testBrandPurposeAfterFix() {
  console.log('🔍 Testing Brand Purpose Retrieval After Duplicate Endpoint Fix...');
  
  // Create a session first
  console.log('1. Establishing session...');
  const sessionRes = await axios.post(`${BASE_URL}/api/establish-session`, {
    email: TEST_EMAIL,
    phone: '+61424835189'
  });
  
  console.log(`✅ Session established: ${sessionRes.status}`);
  
  // Extract session cookie from response
  const cookies = sessionRes.headers['set-cookie'];
  const sessionCookie = cookies ? cookies[0].split(';')[0] : null;
  
  if (!sessionCookie) {
    console.log('❌ No session cookie received');
    return;
  }
  
  console.log(`🍪 Session cookie: ${sessionCookie}`);
  
  // Test brand purpose retrieval with session cookie
  console.log('2. Testing brand purpose retrieval with session...');
  try {
    const brandPurposeRes = await axios.get(`${BASE_URL}/api/brand-purpose`, {
      headers: {
        'Cookie': sessionCookie
      }
    });
    
    console.log('✅ Brand purpose retrieved successfully!');
    console.log(`   Status: ${brandPurposeRes.status}`);
    console.log(`   Brand Name: ${brandPurposeRes.data.brandName}`);
    console.log(`   Core Purpose: ${brandPurposeRes.data.corePurpose}`);
    console.log(`   Audience: ${brandPurposeRes.data.audience}`);
    console.log(`   Products/Services: ${brandPurposeRes.data.productsServices}`);
    
    console.log('\n🎉 DUPLICATE ENDPOINT FIX SUCCESSFUL!');
    console.log('The brand purpose data is now properly accessible.');
    
  } catch (error) {
    console.log('❌ Brand purpose retrieval failed');
    console.log(`   Status: ${error.response?.status}`);
    console.log(`   Error: ${error.response?.data?.message || error.message}`);
    
    if (error.response?.status === 401) {
      console.log('   This indicates a session/authentication issue, not the duplicate endpoint issue');
    }
  }
  
  // Test other endpoints to compare
  console.log('\n3. Testing other authenticated endpoints for comparison...');
  
  try {
    const userRes = await axios.get(`${BASE_URL}/api/user`, {
      headers: {
        'Cookie': sessionCookie
      }
    });
    console.log(`✅ User endpoint: ${userRes.status} - Authentication working`);
  } catch (error) {
    console.log(`❌ User endpoint: ${error.response?.status} - ${error.response?.data?.message}`);
  }
  
  try {
    const subscriptionRes = await axios.get(`${BASE_URL}/api/subscription-usage`, {
      headers: {
        'Cookie': sessionCookie
      }
    });
    console.log(`✅ Subscription endpoint: ${subscriptionRes.status} - Authentication working`);
  } catch (error) {
    console.log(`❌ Subscription endpoint: ${error.response?.status} - ${error.response?.data?.message}`);
  }
}

testBrandPurposeAfterFix().catch(console.error);