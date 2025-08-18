/**
 * Test Session Fix - Direct Database Session Validation
 * Tests if session is being stored in database correctly
 */

const axios = require('axios');
const { Pool } = require('pg');

const baseURL = 'https://4fc77172-459a-4da7-8c33-5014abb1b73e-00-dqhtnud4ismj.worf.replit.dev';
const pool = new Pool({
  connectionString: process.env.DATABASE_URL
});

async function testSessionFix() {
  console.log('🔧 Testing session fix - database validation...\n');
  
  try {
    // Step 1: Establish session and get sessionId
    console.log('📋 Step 1: Establishing session...');
    const sessionResponse = await axios.post(`${baseURL}/api/establish-session`, {}, {
      withCredentials: true
    });
    
    const sessionId = sessionResponse.data.sessionId;
    console.log(`✅ Session established: ${sessionId}`);
    
    // Step 2: Check database directly
    console.log('\n📋 Step 2: Checking database for session...');
    const dbResult = await pool.query('SELECT * FROM sessions WHERE sid = $1', [sessionId]);
    
    if (dbResult.rows.length > 0) {
      console.log('✅ Session found in database');
      const sessionData = JSON.parse(dbResult.rows[0].sess);
      console.log('📋 Session data:', sessionData);
      
      if (sessionData.userId === 2) {
        console.log('✅ User ID correctly stored in session');
        
        // Step 3: Test manual cookie with correct sessionId
        console.log('\n📋 Step 3: Testing with correct session ID...');
        const userResponse = await axios.get(`${baseURL}/api/user`, {
          headers: {
            'Cookie': `theagencyiq.session=${sessionId}`,
            'Content-Type': 'application/json'
          },
          withCredentials: true
        });
        
        console.log('✅ User data retrieved successfully:', userResponse.data);
        console.log('\n🎯 Session persistence FIXED! ✅');
        
      } else {
        console.log('❌ User ID not stored correctly in session');
      }
    } else {
      console.log('❌ Session not found in database');
    }
    
  } catch (error) {
    console.error('❌ Test failed:', error.response?.status || error.message);
    if (error.response?.data) {
      console.error('Response data:', error.response.data);
    }
  }
}

testSessionFix().finally(() => pool.end());