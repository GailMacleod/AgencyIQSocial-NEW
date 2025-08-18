/**
 * Test Facebook OAuth Connection
 * Direct test of the Facebook OAuth flow with your configured callback URLs
 */

import axios from 'axios';

async function testFacebookOAuth() {
  console.log('🔵 Testing Facebook OAuth Connection...');
  
  try {
    // First establish session
    const sessionResponse = await axios.post('https://4fc77172-459a-4da7-8c33-5014abb1b73e-00-dqhtnud4ismj.worf.replit.dev/api/auth/establish-session', {}, {
      withCredentials: true,
      headers: {
        'Content-Type': 'application/json',
      }
    });
    
    console.log('✅ Session established:', sessionResponse.data);
    
    // Extract session cookie
    const setCookie = sessionResponse.headers['set-cookie'];
    const sessionCookie = setCookie ? setCookie[0] : '';
    
    // Test Facebook OAuth initiation
    const oauthResponse = await axios.get('https://4fc77172-459a-4da7-8c33-5014abb1b73e-00-dqhtnud4ismj.worf.replit.dev/auth/facebook', {
      headers: {
        'Cookie': sessionCookie,
      },
      maxRedirects: 0,
      validateStatus: function (status) {
        return status >= 200 && status < 400; // Allow redirects
      }
    });
    
    console.log('🔵 Facebook OAuth Response Status:', oauthResponse.status);
    console.log('🔵 Facebook OAuth Response Headers:', oauthResponse.headers);
    
    if (oauthResponse.status === 302) {
      console.log('✅ Facebook OAuth redirect successful');
      console.log('🔗 Redirect URL:', oauthResponse.headers.location);
      
      // Check if redirect URL contains Facebook OAuth endpoint
      if (oauthResponse.headers.location && oauthResponse.headers.location.includes('facebook.com')) {
        console.log('✅ Facebook OAuth URL generated successfully');
        console.log('📋 OAuth URL structure verified');
      } else {
        console.log('❌ Unexpected redirect URL');
      }
    } else {
      console.log('❌ Unexpected OAuth response status');
    }
    
  } catch (error) {
    console.error('❌ Facebook OAuth test failed:', error.message);
    if (error.response) {
      console.error('Response status:', error.response.status);
      console.error('Response data:', error.response.data);
    }
  }
}

testFacebookOAuth();