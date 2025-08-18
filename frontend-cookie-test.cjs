/**
 * Frontend Cookie Test - Test if frontend is properly sending cookies
 */

const axios = require('axios');

const BASE_URL = 'https://4fc77172-459a-4da7-8c33-5014abb1b73e-00-dqhtnud4ismj.worf.replit.dev';

async function testFrontendCookies() {
  console.log('🔍 FRONTEND COOKIE TRANSMISSION TEST');
  console.log('='.repeat(50));
  
  try {
    // Test establish-session endpoint
    const response = await axios.post(BASE_URL + '/api/establish-session', {
      email: 'gailm@macleodglba.com.au',
      phone: '+61424835189'
    }, {
      withCredentials: true,
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
      }
    });
    
    console.log('✅ Session established:', response.data);
    
    // Extract cookies
    const cookies = response.headers['set-cookie'];
    if (cookies) {
      const sessionCookie = cookies.find(cookie => cookie.includes('theagencyiq.session'));
      console.log('🍪 Session cookie found:', sessionCookie ? 'YES' : 'NO');
      if (sessionCookie) {
        console.log('🍪 Cookie value:', sessionCookie.substring(0, 100) + '...');
      }
    }
    
  } catch (error) {
    console.error('❌ Session test failed:', error.message);
  }
}

testFrontendCookies();