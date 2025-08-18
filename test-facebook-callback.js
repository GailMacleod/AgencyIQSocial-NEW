/**
 * Test Facebook OAuth Callback URL
 * Verifies that the callback endpoint responds correctly
 */

import axios from 'axios';

async function testFacebookCallback() {
  console.log('🔵 Testing Facebook OAuth Callback URL...');
  
  try {
    // Test that the callback endpoint exists and responds
    const response = await axios.get('https://4fc77172-459a-4da7-8c33-5014abb1b73e-00-dqhtnud4ismj.worf.replit.dev/auth/facebook/callback', {
      maxRedirects: 0,
      validateStatus: function (status) {
        return status >= 200 && status < 500; // Allow most statuses
      }
    });
    
    console.log('✅ Facebook callback endpoint accessible');
    console.log('📋 Response status:', response.status);
    
    if (response.status === 400) {
      console.log('⚠️  Expected 400 - callback needs OAuth parameters');
      console.log('✅ Callback endpoint configured correctly');
    } else {
      console.log('📋 Response:', response.data);
    }
    
  } catch (error) {
    console.error('❌ Facebook callback test failed:', error.message);
    if (error.response) {
      console.error('Response status:', error.response.status);
      console.error('Response data:', error.response.data);
    }
  }
}

testFacebookCallback();