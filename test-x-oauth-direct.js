/**
 * Test X OAuth directly with existing credentials
 */
import axios from 'axios';

async function testXOAuth() {
  try {
    console.log('🔍 Testing X OAuth with existing credentials...');
    
    // Test the OAuth initiation endpoint
    const response = await axios.get('https://4fc77172-459a-4da7-8c33-5014abb1b73e-00-dqhtnud4ismj.worf.replit.dev/auth/twitter', {
      maxRedirects: 0,
      validateStatus: (status) => status < 400
    });
    
    console.log('✅ X OAuth test successful');
    console.log('Response status:', response.status);
    console.log('Response headers:', response.headers);
    
  } catch (error) {
    console.log('❌ X OAuth test failed:', error.message);
    if (error.response) {
      console.log('Error response:', error.response.data);
      console.log('Error status:', error.response.status);
    }
  }
}

testXOAuth();