/**
 * Test Platform Connections Data
 */
const axios = require('axios');

async function testPlatformConnections() {
  try {
    console.log('🔍 Testing platform connections data...');
    
    const response = await axios.get('https://4fc77172-459a-4da7-8c33-5014abb1b73e-00-dqhtnud4ismj.worf.replit.dev/api/platform-connections', {
      headers: {
        'Cookie': 'theagencyiq.session=s%3Aaiq_md10oner_zzltawpuqz.gYlCRNuFBOsoUjYhiJNYGPf6kNOnk8SvzUElLWNXR0w'
      }
    });
    
    console.log('✅ Platform connections data:');
    console.log(JSON.stringify(response.data, null, 2));
    
    // Check LinkedIn specifically
    const linkedinConnection = response.data.find(conn => conn.platform === 'linkedin');
    if (linkedinConnection) {
      console.log('\n🔍 LinkedIn connection details:');
      console.log('- Platform:', linkedinConnection.platform);
      console.log('- Status:', linkedinConnection.status);
      console.log('- Connected:', linkedinConnection.connected);
      console.log('- Valid:', linkedinConnection.valid);
      console.log('- Account:', linkedinConnection.account);
      console.log('- Connected Date:', linkedinConnection.connectedAt);
    } else {
      console.log('\n❌ LinkedIn connection not found in data');
    }
    
  } catch (error) {
    console.error('❌ Error testing platform connections:', error.message);
  }
}

testPlatformConnections();