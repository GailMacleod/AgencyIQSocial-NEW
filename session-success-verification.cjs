/**
 * SESSION SUCCESS VERIFICATION
 * Final test to confirm complete session management success
 */

const axios = require('axios');
const BASE_URL = 'https://4fc77172-459a-4da7-8c33-5014abb1b73e-00-dqhtnud4ismj.worf.replit.dev';

async function verifySessionSuccess() {
  console.log('🎉 SESSION SUCCESS VERIFICATION');
  console.log('='.repeat(50));
  
  try {
    // 1. Test session establishment
    console.log('\n1️⃣ Testing session establishment...');
    const sessionResponse = await axios.post(BASE_URL + '/api/establish-session', {
      email: 'gailm@macleodglba.com.au',
      phone: '+61424835189'
    });
    
    console.log('✅ Session established:', sessionResponse.data.message);
    
    // 2. Extract cookie and test manual transmission
    const setCookieHeaders = sessionResponse.headers['set-cookie'];
    let sessionCookie = null;
    
    if (setCookieHeaders) {
      setCookieHeaders.forEach(cookie => {
        if (cookie.includes('theagencyiq.session=')) {
          sessionCookie = cookie.split(';')[0];
        }
      });
    }
    
    if (sessionCookie) {
      console.log('🍪 Session cookie found:', sessionCookie.substring(0, 50) + '...');
      
      // Test authenticated endpoints
      console.log('\n2️⃣ Testing authenticated API calls...');
      
      const endpoints = [
        '/api/user',
        '/api/user-status',
        '/api/platform-connections',
        '/api/subscription-usage'
      ];
      
      let successCount = 0;
      
      for (const endpoint of endpoints) {
        try {
          const response = await axios.get(BASE_URL + endpoint, {
            headers: {
              'Cookie': sessionCookie,
              'Content-Type': 'application/json'
            }
          });
          
          console.log(`✅ ${endpoint}: SUCCESS (${response.status})`);
          successCount++;
          
        } catch (error) {
          console.log(`❌ ${endpoint}: FAILED (${error.response?.status})`);
        }
      }
      
      console.log(`\n🎯 SUCCESS RATE: ${successCount}/${endpoints.length} (${Math.round(successCount/endpoints.length*100)}%)`);
      
      if (successCount === endpoints.length) {
        console.log('\n🎉 SESSION MANAGEMENT COMPLETELY SUCCESSFUL!');
        console.log('✅ Cookie transmission working perfectly');
        console.log('✅ Authentication system operational');
        console.log('✅ All API endpoints responding correctly');
      } else {
        console.log('\n⚠️  Some endpoints still failing - needs investigation');
      }
      
    } else {
      console.log('❌ No session cookie found in response');
    }
    
  } catch (error) {
    console.error('❌ Test failed:', error.message);
  }
}

verifySessionSuccess();