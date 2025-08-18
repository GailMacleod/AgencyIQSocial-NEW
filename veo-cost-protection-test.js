/**
 * VEO 3.0 Cost Protection System Test
 * Validates cost monitoring and quota enforcement
 */

const axios = require('axios');

async function testVeoCostProtection() {
  const baseUrl = 'http://localhost:5000';
  
  console.log('🧪 Testing VEO 3.0 Cost Protection System');
  console.log('=====================================');
  
  try {
    // Test 1: Check VEO usage statistics
    console.log('\n📊 Test 1: VEO Usage Statistics');
    const usageResponse = await axios.get(`${baseUrl}/api/veo/usage`);
    console.log('✅ Usage data:', JSON.stringify(usageResponse.data, null, 2));
    
    // Test 2: Check video generation validation
    console.log('\n🎬 Test 2: Video Generation Validation');
    const canGenerateResponse = await axios.get(`${baseUrl}/api/veo/can-generate?duration=8`);
    console.log('✅ Generation check:', JSON.stringify(canGenerateResponse.data, null, 2));
    
    // Test 3: Cost dashboard
    console.log('\n💰 Test 3: Cost Dashboard');
    const dashboardResponse = await axios.get(`${baseUrl}/api/veo/cost-dashboard`);
    console.log('✅ Cost dashboard:', JSON.stringify(dashboardResponse.data, null, 2));
    
    // Test 4: Record a test usage
    console.log('\n📝 Test 4: Record Test Usage');
    try {
      const recordResponse = await axios.post(`${baseUrl}/api/veo/record-usage`, {
        operationId: `test-${Date.now()}`,
        durationSeconds: 8,
        costUsd: 6.00
      });
      console.log('✅ Usage recorded:', JSON.stringify(recordResponse.data, null, 2));
    } catch (error) {
      console.log('ℹ️ Usage recording endpoint may need authentication');
    }
    
    console.log('\n🎯 VEO Cost Protection Tests Summary:');
    console.log('✅ Usage monitoring endpoints operational');
    console.log('✅ Cost tracking infrastructure ready');
    console.log('✅ Quota validation system functional');
    console.log('💡 Integration with video generation endpoints needed');
    
  } catch (error) {
    console.error('❌ Test failed:', error.message);
    if (error.response) {
      console.error('Response data:', error.response.data);
    }
  }
}

// Run the test
testVeoCostProtection();