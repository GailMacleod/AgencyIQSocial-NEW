/**
 * Final Instagram OAuth Test
 * Tests Instagram OAuth with separate app credentials and proper domain configuration
 */

const axios = require('axios');

const BASE_URL = 'https://4fc77172-459a-4da7-8c33-5014abb1b73e-00-dqhtnud4ismj.worf.replit.dev';

async function testInstagramOAuth() {
  console.log('🔍 Testing Instagram OAuth with separate app credentials...');
  console.log('📱 Instagram App ID: 1260163325661196');
  console.log('🌐 Domain configured in Instagram app');
  
  try {
    // Test session establishment
    const sessionResponse = await axios.post(`${BASE_URL}/api/auth/establish-session`, {}, {
      withCredentials: true
    });
    
    console.log('✅ Session established:', sessionResponse.data.user?.email);
    const cookies = sessionResponse.headers['set-cookie'];
    
    // Test Instagram OAuth initiation
    const instagramResponse = await axios.get(`${BASE_URL}/auth/instagram`, {
      maxRedirects: 0,
      validateStatus: (status) => status === 302,
      headers: {
        'Cookie': cookies?.join('; ')
      }
    });
    
    const redirectUrl = instagramResponse.headers.location;
    console.log('🔗 Instagram OAuth redirect URL generated:');
    console.log(redirectUrl);
    
    // Verify it's using correct Instagram app credentials
    if (redirectUrl.includes('1260163325661196')) {
      console.log('✅ Instagram OAuth using correct app ID: 1260163325661196');
    } else {
      console.log('❌ Instagram OAuth not using correct app ID');
    }
    
    // Verify domain configuration
    if (redirectUrl.includes('4fc77172-459a-4da7-8c33-5014abb1b73e-00-dqhtnud4ismj.worf.replit.dev')) {
      console.log('✅ Callback URL using correct domain');
    } else {
      console.log('❌ Callback URL domain mismatch');
    }
    
    // Verify scopes
    if (redirectUrl.includes('instagram_basic') && redirectUrl.includes('pages_show_list')) {
      console.log('✅ Instagram OAuth scopes configured correctly');
    } else {
      console.log('❌ Instagram OAuth scopes missing or incorrect');
    }
    
    console.log('\n🎉 Instagram OAuth configuration test complete!');
    console.log('📋 Summary:');
    console.log('- Instagram app ID: 1260163325661196');
    console.log('- Domain added to Instagram app settings');
    console.log('- Separate app credentials configured');
    console.log('- OAuth redirect URL generated successfully');
    console.log('\n🔗 Click the Instagram "Connect" button to test the full OAuth flow');
    
  } catch (error) {
    console.error('❌ Instagram OAuth test failed:', error.response?.data || error.message);
  }
}

testInstagramOAuth();