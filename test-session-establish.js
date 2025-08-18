/**
 * Test Session Establishment - Debug OAuth Issue
 */

import axios from 'axios';

async function testSessionEstablishment() {
  try {
    console.log('=== SESSION ESTABLISHMENT TEST ===');
    
    // Step 1: Establish session
    const sessionResponse = await axios.post('https://4fc77172-459a-4da7-8c33-5014abb1b73e-00-dqhtnud4ismj.worf.replit.dev/api/establish-session', {
      email: 'gailm@macleodglba.com.au',
      phone: '+61424835189'
    });
    
    console.log('✅ Session established:', sessionResponse.data);
    
    // Extract cookies
    const cookies = sessionResponse.headers['set-cookie'];
    const cookieHeader = cookies ? cookies.join('; ') : '';
    
    console.log('🍪 Session cookies:', cookieHeader);
    
    // Step 2: Test platform connections endpoint
    const connectionsResponse = await axios.get('https://4fc77172-459a-4da7-8c33-5014abb1b73e-00-dqhtnud4ismj.worf.replit.dev/api/platform-connections', {
      headers: {
        'Cookie': cookieHeader
      }
    });
    
    console.log('📱 Platform connections:', connectionsResponse.data);
    
    return { cookieHeader, connections: connectionsResponse.data };
    
  } catch (error) {
    console.error('❌ Session establishment failed:', error.response?.data || error.message);
    throw error;
  }
}

testSessionEstablishment();