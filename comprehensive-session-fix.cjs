/**
 * COMPREHENSIVE SESSION FIX - Final solution for cookie transmission
 * Tests different cookie configurations to find the working solution
 */

const axios = require('axios');
const tough = require('tough-cookie');

const BASE_URL = 'https://4fc77172-459a-4da7-8c33-5014abb1b73e-00-dqhtnud4ismj.worf.replit.dev';

async function testComprehensiveSessionFix() {
  console.log('🔍 COMPREHENSIVE SESSION FIX TEST');
  console.log('='.repeat(60));
  
  const cookieJar = new tough.CookieJar();
  
  try {
    // Test 1: Manual cookie jar with proper session persistence
    console.log('\n1️⃣ Testing manual cookie jar approach...');
    
    // Establish session
    const sessionResponse = await axios.post(BASE_URL + '/api/establish-session', {
      email: 'gailm@macleodglba.com.au',
      phone: '+61424835189'
    });
    
    console.log('✅ Session established:', sessionResponse.data.message);
    
    // Extract session cookie
    const setCookieHeaders = sessionResponse.headers['set-cookie'];
    let sessionCookie = null;
    
    if (setCookieHeaders) {
      setCookieHeaders.forEach(cookie => {
        if (cookie.includes('theagencyiq.session=')) {
          sessionCookie = cookie.split(';')[0]; // Get just the cookie value
          console.log('🍪 Extracted session cookie:', sessionCookie);
        }
      });
    }
    
    if (!sessionCookie) {
      console.log('❌ No session cookie found');
      return;
    }
    
    // Test API calls with manual cookie inclusion
    console.log('\n2️⃣ Testing API calls with manual cookie inclusion...');
    
    const endpoints = ['/api/user', '/api/user-status', '/api/platform-connections'];
    
    for (const endpoint of endpoints) {
      try {
        const response = await axios.get(BASE_URL + endpoint, {
          headers: {
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'Cookie': sessionCookie
          }
        });
        
        console.log(`✅ ${endpoint}: SUCCESS (${response.status})`);
        if (endpoint === '/api/user') {
          console.log(`   User: ${response.data.email} (ID: ${response.data.id})`);
        }
      } catch (error) {
        console.log(`❌ ${endpoint}: FAILED (${error.response?.status || 'Network Error'})`);
      }
    }
    
    // Test 3: Test with different cookie configurations
    console.log('\n3️⃣ Testing different cookie configurations...');
    
    // Test with domain removal
    const domainFreeResponse = await axios.post(BASE_URL + '/api/test-cookie-config', {
      config: 'domain-free',
      sameSite: 'lax',
      secure: true
    }).catch(err => ({ data: { error: err.message } }));
    
    console.log('Domain-free test:', domainFreeResponse.data);
    
    // Test with SameSite=Lax
    const sameSiteLaxResponse = await axios.post(BASE_URL + '/api/test-cookie-config', {
      config: 'samesite-lax',
      sameSite: 'lax',
      secure: true
    }).catch(err => ({ data: { error: err.message } }));
    
    console.log('SameSite=Lax test:', sameSiteLaxResponse.data);
    
    console.log('\n✅ Cookie transmission test completed');
    
  } catch (error) {
    console.error('❌ Test failed:', error.message);
  }
}

testComprehensiveSessionFix();