/**
 * Test if session is working properly
 */

async function testSessionWorking() {
  try {
    console.log('Testing session with current cookies...');
    
    // Test /api/user endpoint
    const response = await fetch('https://4fc77172-459a-4da7-8c33-5014abb1b73e-00-dqhtnud4ismj.worf.replit.dev/api/user', {
      method: 'GET',
      credentials: 'include'
    });
    
    console.log('Response status:', response.status);
    console.log('Response headers:', Object.fromEntries(response.headers.entries()));
    
    if (response.ok) {
      const data = await response.json();
      console.log('✅ Session working - User data:', data);
    } else {
      const error = await response.text();
      console.log('❌ Session not working - Error:', error);
    }
    
  } catch (error) {
    console.error('Test failed:', error);
  }
}

testSessionWorking();