/**
 * Test the /api/login endpoint directly
 */

const { apiRequest } = require('./client/src/lib/queryClient');

async function testLoginEndpoint() {
  try {
    console.log('Testing /api/login endpoint...');
    
    const response = await fetch('https://4fc77172-459a-4da7-8c33-5014abb1b73e-00-dqhtnud4ismj.worf.replit.dev/api/login', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
      },
      body: JSON.stringify({
        email: 'gailm@macleodglba.com.au',
        phone: '+61424835189'
      }),
      credentials: 'include'
    });

    console.log('Response status:', response.status);
    console.log('Response headers:', Object.fromEntries(response.headers.entries()));
    
    if (response.ok) {
      const data = await response.json();
      console.log('Success response:', data);
    } else {
      const error = await response.text();
      console.log('Error response:', error);
    }
  } catch (error) {
    console.error('Request failed:', error);
  }
}

testLoginEndpoint();