/**
 * Test LinkedIn Connection Creation
 */
const axios = require('axios');

async function testLinkedInConnection() {
  try {
    console.log('🔍 Creating test LinkedIn connection...');
    
    // First, get the current platform connections to see what's stored
    const connectionsResponse = await axios.get('https://4fc77172-459a-4da7-8c33-5014abb1b73e-00-dqhtnud4ismj.worf.replit.dev/api/platform-connections', {
      headers: {
        'Cookie': 'theagencyiq.session=s%3Aaiq_md10oner_zzltawpuqz.gYlCRNuFBOsoUjYhiJNYGPf6kNOnk8SvzUElLWNXR0w'
      }
    });
    
    console.log('📋 Current connections:');
    connectionsResponse.data.forEach(conn => {
      console.log(`- ${conn.platform}: ${conn.platformUsername} (${conn.isActive ? 'Active' : 'Inactive'})`);
    });
    
    // Test the LinkedIn connection by manually trying to connect
    console.log('\n🔍 Testing LinkedIn OAuth initiation...');
    
    const oauthResponse = await axios.get('https://4fc77172-459a-4da7-8c33-5014abb1b73e-00-dqhtnud4ismj.worf.replit.dev/auth/linkedin', {
      headers: {
        'Cookie': 'theagencyiq.session=s%3Aaiq_md10oner_zzltawpuqz.gYlCRNuFBOsoUjYhiJNYGPf6kNOnk8SvzUElLWNXR0w'
      },
      maxRedirects: 0,
      validateStatus: function (status) {
        return status >= 200 && status < 400;
      }
    });
    
    console.log('✅ LinkedIn OAuth initiation successful');
    console.log('📍 Redirect URL:', oauthResponse.headers.location);
    
    // Extract the LinkedIn authorization URL details
    if (oauthResponse.headers.location) {
      const url = new URL(oauthResponse.headers.location);
      console.log('\n🔍 LinkedIn OAuth Details:');
      console.log('- Authorization URL:', url.href);
      console.log('- Client ID:', url.searchParams.get('client_id'));
      console.log('- Redirect URI:', url.searchParams.get('redirect_uri'));
      console.log('- Scope:', url.searchParams.get('scope'));
      console.log('- State:', url.searchParams.get('state') || 'none');
      
      console.log('\n📝 Next steps:');
      console.log('1. Visit the LinkedIn authorization URL above');
      console.log('2. Grant permission to the app');
      console.log('3. LinkedIn will redirect back to the callback URL');
      console.log('4. The callback should save the connection to the database');
    }
    
  } catch (error) {
    console.error('❌ Error testing LinkedIn connection:', error.message);
    if (error.response) {
      console.error('Status:', error.response.status);
      console.error('Data:', error.response.data);
    }
  }
}

testLinkedInConnection();