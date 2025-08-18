/**
 * OAUTH SESSION LOGIN AND PLATFORM STATUS INVESTIGATION
 * Step 1: Establish session with proper authentication
 * Step 2: Investigate database and API status for User ID 2
 */

const axios = require('axios');

const BASE_URL = 'https://4fc77172-459a-4da7-8c33-5014abb1b73e-00-dqhtnud4ismj.worf.replit.dev';

async function establishSessionAndInvestigate() {
  console.log('🔍 OAUTH SESSION LOGIN AND PLATFORM STATUS INVESTIGATION');
  console.log('========================================================');
  
  let sessionCookies = '';
  
  try {
    // Step 1: Establish session with proper authentication
    console.log('\n📝 STEP 1: Establishing authenticated session...');
    
    const sessionResponse = await axios.post(`${BASE_URL}/api/establish-session`, {
      email: 'gailm@macleodglba.com.au',
      phone: '+61424835189'
    }, {
      headers: { 'Content-Type': 'application/json' },
      withCredentials: true
    });

    console.log('✅ Session Response:', JSON.stringify(sessionResponse.data, null, 2));
    
    // Extract session cookies
    const setCookieHeader = sessionResponse.headers['set-cookie'];
    if (setCookieHeader) {
      sessionCookies = setCookieHeader.join('; ');
      console.log('✅ Session cookies extracted:', sessionCookies.substring(0, 100) + '...');
    } else {
      throw new Error('No session cookies received');
    }

    // Step 2: Test platform status API calls
    console.log('\n🔗 STEP 2: Testing platform status API calls...');
    
    const platforms = ['facebook', 'instagram', 'linkedin', 'x', 'youtube'];
    
    for (const platform of platforms) {
      try {
        console.log(`\n📊 Testing ${platform.toUpperCase()} platform status...`);
        
        const statusResponse = await axios.get(`${BASE_URL}/api/platform-connections`, {
          headers: {
            'Content-Type': 'application/json',
            'Cookie': sessionCookies
          },
          withCredentials: true
        });
        
        const connection = statusResponse.data.find(c => c.platform === platform);
        
        if (connection) {
          console.log(`✅ ${platform} connection found:`, {
            platform: connection.platform,
            accessToken: connection.accessToken?.substring(0, 30) + '...',
            refreshToken: connection.refreshToken?.substring(0, 30) + '...',
            expiresAt: connection.expiresAt,
            isActive: connection.isActive,
            oauthValid: connection.oauthStatus?.isValid,
            oauthError: connection.oauthStatus?.error
          });
        } else {
          console.log(`❌ ${platform} connection not found`);
        }
        
      } catch (error) {
        console.error(`❌ ${platform} status check failed:`, error.message);
      }
    }
    
    // Step 3: Direct database investigation via SQL endpoint
    console.log('\n🗄️ STEP 3: Database investigation complete via API responses above');
    
  } catch (error) {
    console.error('❌ Investigation failed:', error.message);
    if (error.response) {
      console.error('Response data:', error.response.data);
      console.error('Response status:', error.response.status);
    }
  }
}

// Run investigation
if (require.main === module) {
  establishSessionAndInvestigate().catch(console.error);
}