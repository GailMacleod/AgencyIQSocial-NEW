/**
 * Test LinkedIn Token Validity
 * Uses the LinkedIn API to check if stored tokens are still valid
 */
const axios = require('axios');

async function testLinkedInTokenValidity() {
  try {
    console.log('🔍 Testing LinkedIn token validity...');
    
    // First, get the current platform connections to find LinkedIn token
    const connectionsResponse = await axios.get('https://4fc77172-459a-4da7-8c33-5014abb1b73e-00-dqhtnud4ismj.worf.replit.dev/api/platform-connections', {
      headers: {
        'Cookie': 'theagencyiq.session=s%3Aaiq_md10oner_zzltawpuqz.gYlCRNuFBOsoUjYhiJNYGPf6kNOnk8SvzUElLWNXR0w'
      }
    });
    
    console.log('📋 Current platform connections:');
    connectionsResponse.data.forEach(conn => {
      console.log(`- ${conn.platform}: ${conn.platformUsername} (${conn.isActive ? 'Active' : 'Inactive'})`);
    });
    
    // Look for LinkedIn connection
    const linkedinConnection = connectionsResponse.data.find(conn => conn.platform === 'linkedin');
    
    if (!linkedinConnection) {
      console.log('❌ No LinkedIn connection found in database');
      console.log('🔍 Available connections:', connectionsResponse.data.map(c => c.platform));
      return;
    }
    
    console.log('\n✅ LinkedIn connection found in database');
    console.log('📋 LinkedIn connection details:');
    console.log(`- Platform User ID: ${linkedinConnection.platformUserId}`);
    console.log(`- Platform Username: ${linkedinConnection.platformUsername}`);
    console.log(`- Is Active: ${linkedinConnection.isActive}`);
    console.log(`- Has Access Token: ${linkedinConnection.accessToken ? 'Yes' : 'No'}`);
    
    if (!linkedinConnection.accessToken) {
      console.log('❌ No access token found for LinkedIn connection');
      return;
    }
    
    // Test token validity using LinkedIn API
    console.log('\n🔍 Testing token validity with LinkedIn API...');
    
    try {
      const linkedinApiResponse = await axios.get('https://api.linkedin.com/v1/people/~?oauth2_access_token=' + linkedinConnection.accessToken, {
        headers: {
          'Accept': 'application/json'
        },
        timeout: 10000
      });
      
      console.log('✅ LinkedIn token is VALID');
      console.log('📋 LinkedIn API response:');
      console.log(JSON.stringify(linkedinApiResponse.data, null, 2));
      
    } catch (linkedinError) {
      console.log('❌ LinkedIn token is EXPIRED or INVALID');
      console.log('📋 LinkedIn API error:');
      console.log('- Status:', linkedinError.response?.status);
      console.log('- Message:', linkedinError.response?.data?.message || linkedinError.message);
      
      if (linkedinError.response?.status === 401) {
        console.log('🔄 Token expired - OAuth reconnection needed');
      }
    }
    
  } catch (error) {
    console.error('❌ Error testing LinkedIn token validity:', error.message);
    if (error.response) {
      console.error('Status:', error.response.status);
      console.error('Data:', error.response.data);
    }
  }
}

testLinkedInTokenValidity();