/**
 * Debug OAuth Flow with Session Authentication
 * Tests the complete OAuth flow with proper session establishment
 */

const axios = require('axios');
const tough = require('tough-cookie');

const BASE_URL = 'https://4fc77172-459a-4da7-8c33-5014abb1b73e-00-dqhtnud4ismj.worf.replit.dev';

async function testOAuthFlow() {
  console.log('🔄 Testing OAuth flow with authenticated session...');
  
  const cookieJar = new tough.CookieJar();
  const axiosInstance = axios.create({
    jar: cookieJar,
    withCredentials: true
  });
  
  try {
    // Step 1: Login first
    const loginResponse = await axiosInstance.post(`${BASE_URL}/api/auth/login`, {
      email: 'gailm@macleodglba.com.au',
      password: 'testpass'
    });
    
    console.log('✅ Login successful');
    
    // Step 2: Test X OAuth initiation
    const xOAuthResponse = await axiosInstance.get(`${BASE_URL}/auth/twitter`, {
      maxRedirects: 0,
      validateStatus: function (status) {
        return status >= 200 && status < 400;
      }
    });
    
    console.log('✅ X OAuth initiation successful');
    console.log('Status:', xOAuthResponse.status);
    console.log('Redirect URL:', xOAuthResponse.headers.location);
    
    // Step 3: Check platform connections
    const connectionsResponse = await axiosInstance.get(`${BASE_URL}/api/platform-connections`);
    console.log('📊 Platform connections:', connectionsResponse.data);
    
  } catch (error) {
    if (error.response) {
      console.log('❌ Status:', error.response.status);
      console.log('Response:', error.response.data);
    } else {
      console.error('❌ Error:', error.message);
    }
  }
}

testOAuthFlow();