/**
 * Manual Cookie Fix Test - Force session cookie transmission
 */

const axios = require('axios');
const tough = require('tough-cookie');

const BASE_URL = 'https://4fc77172-459a-4da7-8c33-5014abb1b73e-00-dqhtnud4ismj.worf.replit.dev';

async function testManualCookieFix() {
  console.log('🔍 TESTING MANUAL COOKIE FIX');
  console.log('='.repeat(50));
  
  // Create proper cookie jar
  const cookieJar = new tough.CookieJar();
  
  try {
    // Step 1: Establish session and capture cookies
    console.log('1️⃣ Establishing session and capturing cookies...');
    
    const sessionResponse = await axios.post(BASE_URL + '/api/establish-session', {
      email: 'gailm@macleodglba.com.au',
      phone: '+61424835189'
    }, {
      withCredentials: true,
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
      }
    });
    
    console.log('✅ Session established:', sessionResponse.data.message);
    
    // Extract and store cookies
    const setCookieHeaders = sessionResponse.headers['set-cookie'];
    if (setCookieHeaders) {
      setCookieHeaders.forEach(cookie => {
        console.log('🍪 Setting cookie:', cookie.substring(0, 100) + '...');
        cookieJar.setCookieSync(cookie, BASE_URL);
      });
    }
    
    // Verify cookies are stored
    const cookies = cookieJar.getCookiesSync(BASE_URL);
    console.log('🍪 Cookies stored:', cookies.length);
    
    // Step 2: Make API calls with manual cookie transmission
    console.log('\n2️⃣ Making API calls with manual cookie transmission...');
    
    const endpoints = ['/api/user', '/api/user-status', '/api/platform-connections'];
    
    for (const endpoint of endpoints) {
      try {
        const cookieString = cookies.map(c => `${c.key}=${c.value}`).join('; ');
        
        const response = await axios.get(BASE_URL + endpoint, {
          headers: {
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'Cookie': cookieString
          }
        });
        
        console.log(`✅ ${endpoint}: SUCCESS (${response.status})`);
      } catch (error) {
        console.log(`❌ ${endpoint}: FAILED (${error.response?.status})`);
        if (error.response?.data) {
          console.log(`   Error: ${JSON.stringify(error.response.data)}`);
        }
      }
    }
    
  } catch (error) {
    console.error('❌ Test failed:', error.message);
  }
}

testManualCookieFix();