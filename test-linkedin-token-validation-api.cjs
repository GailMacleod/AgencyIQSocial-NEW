/**
 * Test LinkedIn Token Validation API
 */
const axios = require('axios');

async function testLinkedInTokenValidationAPI() {
  try {
    console.log('🔍 Testing LinkedIn token validation API...');
    
    // Test the new LinkedIn token validation endpoint
    const response = await axios.get('https://4fc77172-459a-4da7-8c33-5014abb1b73e-00-dqhtnud4ismj.worf.replit.dev/api/linkedin/validate-token', {
      headers: {
        'Cookie': 'theagencyiq.session=s%3Aaiq_md10oner_zzltawpuqz.gYlCRNuFBOsoUjYhiJNYGPf6kNOnk8SvzUElLWNXR0w'
      }
    });
    
    console.log('✅ LinkedIn token validation API response:');
    console.log(JSON.stringify(response.data, null, 2));
    
    if (response.data.connected) {
      console.log('✅ LinkedIn connection exists in database');
      console.log('📋 Username:', response.data.username);
      console.log('🔍 Token Valid:', response.data.tokenValid);
      if (response.data.error) {
        console.log('⚠️  Error:', response.data.error);
      }
    } else {
      console.log('❌ No LinkedIn connection found in database');
      console.log('🔍 Error:', response.data.error);
    }
    
  } catch (error) {
    console.error('❌ Error testing LinkedIn token validation API:', error.message);
    if (error.response) {
      console.error('Status:', error.response.status);
      console.error('Data:', error.response.data);
    }
  }
}

testLinkedInTokenValidationAPI();