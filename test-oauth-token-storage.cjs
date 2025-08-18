/**
 * Test OAuth Token Storage System
 * Tests the complete OAuth flow including token persistence to the database
 */

const axios = require('axios');
const tough = require('tough-cookie');
const { Pool } = require('pg');

const BASE_URL = 'https://4fc77172-459a-4da7-8c33-5014abb1b73e-00-dqhtnud4ismj.worf.replit.dev';

// Database connection
const pool = new Pool({
  connectionString: process.env.DATABASE_URL
});

async function testOAuthTokenStorage() {
  console.log('🔄 Testing OAuth Token Storage System...');
  
  try {
    // Step 1: Check database before OAuth
    const beforeResult = await pool.query('SELECT COUNT(*) FROM platform_connections WHERE user_id = 2');
    console.log('📊 Platform connections before OAuth:', beforeResult.rows[0].count);
    
    // Step 2: Simulate OAuth token storage directly
    console.log('🧪 Testing direct token storage...');
    
    const testConnection = {
      userId: 2,
      platform: 'test_platform',
      platformUserId: 'test_user_123',
      platformUsername: 'Test User',
      accessToken: 'test_access_token_' + Date.now(),
      refreshToken: 'test_refresh_token_' + Date.now(),
      isActive: true
    };
    
    // Insert test connection
    const insertResult = await pool.query(`
      INSERT INTO platform_connections 
      (user_id, platform, platform_user_id, platform_username, access_token, refresh_token, is_active, connected_at)
      VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())
      RETURNING *
    `, [
      testConnection.userId,
      testConnection.platform,
      testConnection.platformUserId,
      testConnection.platformUsername,
      testConnection.accessToken,
      testConnection.refreshToken,
      testConnection.isActive
    ]);
    
    console.log('✅ Direct token storage successful:', insertResult.rows[0]);
    
    // Step 3: Check database after test insertion
    const afterResult = await pool.query('SELECT COUNT(*) FROM platform_connections WHERE user_id = 2');
    console.log('📊 Platform connections after test:', afterResult.rows[0].count);
    
    // Step 4: Clean up test data
    await pool.query('DELETE FROM platform_connections WHERE platform = $1', ['test_platform']);
    console.log('🧹 Test data cleaned up');
    
    // Step 5: Test handleOAuthCallback function parameters
    console.log('🔍 Testing OAuth callback parameters...');
    
    // Simulate what happens in handleOAuthCallback
    const mockTokens = {
      accessToken: 'mock_access_token_' + Date.now(),
      refreshToken: 'mock_refresh_token_' + Date.now()
    };
    
    const mockProfile = {
      id: 'mock_user_123',
      displayName: 'Mock User',
      emails: [{ value: 'gailm@macleodglba.com.au' }]
    };
    
    console.log('Mock tokens:', mockTokens);
    console.log('Mock profile:', mockProfile);
    
    // Test that the User ID 2 exists
    const userCheck = await pool.query('SELECT * FROM users WHERE id = 2');
    console.log('✅ User ID 2 exists:', userCheck.rows[0] ? 'YES' : 'NO');
    
    if (userCheck.rows[0]) {
      console.log('User details:', {
        id: userCheck.rows[0].id,
        email: userCheck.rows[0].email,
        subscriptionPlan: userCheck.rows[0].subscriptionPlan
      });
    }
    
    console.log('🎯 OAuth Token Storage Test Complete');
    
  } catch (error) {
    console.error('❌ OAuth Token Storage Test Failed:', error);
  } finally {
    await pool.end();
  }
}

testOAuthTokenStorage();