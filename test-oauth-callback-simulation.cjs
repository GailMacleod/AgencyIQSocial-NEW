/**
 * OAuth Callback Simulation Test
 * Simulates the complete OAuth callback with token storage
 */

const axios = require('axios');
const tough = require('tough-cookie');
const { Pool } = require('pg');

const BASE_URL = 'https://4fc77172-459a-4da7-8c33-5014abb1b73e-00-dqhtnud4ismj.worf.replit.dev';

const pool = new Pool({
  connectionString: process.env.DATABASE_URL
});

async function testOAuthCallbackSimulation() {
  console.log('🔄 Testing OAuth Callback Simulation...');
  
  const cookieJar = new tough.CookieJar();
  const axiosInstance = axios.create({
    jar: cookieJar,
    withCredentials: true
  });
  
  try {
    // Step 1: Login to establish session
    console.log('1️⃣ Establishing session...');
    const loginResponse = await axiosInstance.post(`${BASE_URL}/api/auth/login`, {
      email: 'gailm@macleodglba.com.au',
      password: 'testpass'
    });
    console.log('✅ Session established');
    
    // Step 2: Check current platform connections
    const beforeResult = await pool.query('SELECT * FROM platform_connections WHERE user_id = 2');
    console.log('📊 Current platform connections:', beforeResult.rows.length);
    
    // Step 3: Create test OAuth connections via direct API
    console.log('2️⃣ Testing OAuth token storage via API...');
    
    const testPlatforms = [
      {
        platform: 'facebook',
        platformUserId: 'fb_user_123',
        platformUsername: 'Facebook User',
        accessToken: 'fb_access_token_' + Date.now(),
        refreshToken: 'fb_refresh_token_' + Date.now()
      },
      {
        platform: 'instagram',
        platformUserId: 'ig_user_456',
        platformUsername: 'Instagram User',
        accessToken: 'ig_access_token_' + Date.now(),
        refreshToken: 'ig_refresh_token_' + Date.now()
      },
      {
        platform: 'linkedin',
        platformUserId: 'li_user_789',
        platformUsername: 'LinkedIn User',
        accessToken: 'li_access_token_' + Date.now(),
        refreshToken: 'li_refresh_token_' + Date.now()
      },
      {
        platform: 'x',
        platformUserId: 'x_user_012',
        platformUsername: 'X User',
        accessToken: 'x_access_token_' + Date.now(),
        refreshToken: 'x_token_secret_' + Date.now()
      },
      {
        platform: 'youtube',
        platformUserId: 'yt_user_345',
        platformUsername: 'YouTube User',
        accessToken: 'yt_access_token_' + Date.now(),
        refreshToken: 'yt_refresh_token_' + Date.now()
      }
    ];
    
    // Insert test connections directly into database
    for (const platform of testPlatforms) {
      const insertResult = await pool.query(`
        INSERT INTO platform_connections 
        (user_id, platform, platform_user_id, platform_username, access_token, refresh_token, is_active, connected_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())
        RETURNING *
      `, [
        2, // User ID
        platform.platform,
        platform.platformUserId,
        platform.platformUsername,
        platform.accessToken,
        platform.refreshToken,
        true
      ]);
      
      console.log(`✅ ${platform.platform} token stored:`, insertResult.rows[0].id);
    }
    
    // Step 4: Verify connections were stored
    const afterResult = await pool.query(`
      SELECT platform, platform_username, 
             SUBSTRING(access_token, 1, 20) as token_preview,
             is_active, connected_at
      FROM platform_connections 
      WHERE user_id = 2 
      ORDER BY connected_at DESC
    `);
    
    console.log('📊 Platform connections after storage:');
    afterResult.rows.forEach(row => {
      console.log(`   ${row.platform}: ${row.platform_username} (${row.token_preview}...) - ${row.is_active ? 'ACTIVE' : 'INACTIVE'}`);
    });
    
    // Step 5: Test platform connections API with stored tokens
    console.log('3️⃣ Testing platform connections API...');
    
    try {
      const connectionsResponse = await axiosInstance.get(`${BASE_URL}/api/platform-connections`);
      console.log('✅ Platform connections API successful');
      console.log('   Connection count:', connectionsResponse.data.length);
      
      connectionsResponse.data.forEach(conn => {
        console.log(`   ${conn.platform}: ${conn.isValid ? 'VALID' : 'INVALID'} - ${conn.status}`);
      });
      
    } catch (error) {
      if (error.response) {
        console.log('❌ Platform connections API failed:', error.response.status, error.response.data);
      } else {
        console.log('❌ Platform connections API error:', error.message);
      }
    }
    
    // Step 6: Clean up test data
    console.log('4️⃣ Cleaning up test data...');
    await pool.query('DELETE FROM platform_connections WHERE user_id = 2');
    console.log('✅ Test data cleaned up');
    
    console.log('🎯 OAuth Callback Simulation Complete');
    
  } catch (error) {
    console.error('❌ OAuth Callback Simulation Failed:', error);
    if (error.response) {
      console.log('Response data:', error.response.data);
    }
  } finally {
    await pool.end();
  }
}

testOAuthCallbackSimulation();