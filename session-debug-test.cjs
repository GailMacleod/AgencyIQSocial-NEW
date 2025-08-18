/**
 * Session Debug Test
 * Test with actual session ID from database
 */

const axios = require('axios');
const tough = require('tough-cookie');

const BASE_URL = 'https://4fc77172-459a-4da7-8c33-5014abb1b73e-00-dqhtnud4ismj.worf.replit.dev';

async function testSessionDebug() {
  console.log('🔍 SESSION DEBUG TEST');
  console.log('='.repeat(60));
  
  // Create a cookie jar and set the session cookie manually
  const cookieJar = new tough.CookieJar();
  const sessionCookie = new tough.Cookie({
    key: 'theagencyiq.session',
    value: 'aiq_md155zuc_lxdub0ta7e', // Use actual session ID from database
    domain: '4fc77172-459a-4da7-8c33-5014abb1b73e-00-dqhtnud4ismj.worf.replit.dev',
    path: '/',
    httpOnly: false,
    secure: false,
    sameSite: 'lax'
  });
  
  cookieJar.setCookieSync(sessionCookie, BASE_URL);
  
  const axiosInstance = axios.create({
    jar: cookieJar,
    withCredentials: true,
    headers: {
      'Cookie': 'theagencyiq.session=aiq_md155zuc_lxdub0ta7e'
    }
  });
  
  try {
    console.log('\n1️⃣ TESTING WITH EXISTING SESSION');
    console.log('-'.repeat(40));
    console.log('📋 Using Session ID: aiq_md155zuc_lxdub0ta7e');
    
    // Test user endpoint
    try {
      const userResponse = await axiosInstance.get(`${BASE_URL}/api/user`);
      console.log('📋 User API Status:', userResponse.status);
      console.log('📋 User Data:', userResponse.data);
      console.log('📋 Session Works: SUCCESS');
      
    } catch (error) {
      console.log('📋 User API Status:', error.response?.status || 'ERROR');
      console.log('📋 User API Error:', error.response?.data?.message || error.message);
      console.log('📋 Session Works: FAILED');
      
      // Log request headers to debug
      console.log('📋 Request Headers:', error.config?.headers || 'No headers');
    }
    
    console.log('\n2️⃣ TESTING DIFFERENT SESSION FORMAT');
    console.log('-'.repeat(40));
    
    // Test with different cookie format
    const axiosInstance2 = axios.create({
      withCredentials: true,
      headers: {
        'Cookie': 'theagencyiq.session=s%3Aaiq_md155zuc_lxdub0ta7e' // Try URL encoded
      }
    });
    
    try {
      const userResponse2 = await axiosInstance2.get(`${BASE_URL}/api/user`);
      console.log('📋 User API Status (encoded):', userResponse2.status);
      console.log('📋 Session Works (encoded): SUCCESS');
      
    } catch (error) {
      console.log('📋 User API Status (encoded):', error.response?.status || 'ERROR');
      console.log('📋 Session Works (encoded): FAILED');
    }
    
  } catch (error) {
    console.error('❌ Session debug test failed:', error);
  }
}

testSessionDebug();