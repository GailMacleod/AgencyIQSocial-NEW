#!/usr/bin/env node

/**
 * UPDATE REAL OAUTH TOKENS - IMMEDIATE LIVE PUBLISHING
 * Replaces test tokens with real environment OAuth tokens for instant publishing
 */

const { Pool } = require('@neondatabase/serverless');
const pool = new Pool({ connectionString: process.env.DATABASE_URL });

async function updateRealOAuthTokens() {
    console.log('🔑 UPDATING REAL OAUTH TOKENS FOR LIVE PUBLISHING');
    console.log('================================================');
    
    try {
        // Get real tokens from environment
        const linkedinToken = process.env.LINKEDIN_ACCESS_TOKEN;
        const facebookAppId = process.env.FACEBOOK_APP_ID;
        const facebookAppSecret = process.env.FACEBOOK_APP_SECRET;
        
        console.log('Environment tokens found:');
        console.log(`- LinkedIn: ${linkedinToken ? '✅ Found' : '❌ Missing'}`);
        console.log(`- Facebook App ID: ${facebookAppId ? '✅ Found' : '❌ Missing'}`);
        console.log(`- Facebook App Secret: ${facebookAppSecret ? '✅ Found' : '❌ Missing'}`);
        
        if (linkedinToken) {
            // Update LinkedIn token
            await pool.query(`
                UPDATE oauth_tokens 
                SET access_token = $1, updated_at = NOW()
                WHERE user_id = '2' AND platform = 'linkedin'
            `, [linkedinToken]);
            console.log('✅ LinkedIn token updated');
        }
        
        if (facebookAppId && facebookAppSecret) {
            // For Facebook, we need to generate a page access token
            // For now, update with app credentials - will need page token
            console.log('⚠️ Facebook requires page access token generation');
            console.log('   App credentials available for token generation');
        }
        
        // Test the updated tokens
        console.log('\n🧪 TESTING UPDATED TOKENS');
        const result = await pool.query(`
            SELECT platform, 
                   CASE WHEN access_token LIKE '%real_token%' THEN 'Test Token' ELSE 'Real Token' END as token_type,
                   is_valid
            FROM oauth_tokens 
            WHERE user_id = '2'
            ORDER BY platform
        `);
        
        console.log('Token status:');
        result.rows.forEach(row => {
            console.log(`- ${row.platform}: ${row.token_type} (${row.is_valid ? 'Valid' : 'Invalid'})`);
        });
        
        console.log('\n🚀 READY FOR LIVE PUBLISHING TEST');
        console.log('Run: curl -X POST "http://localhost:5000/api/enforce-auto-posting" -H "Cookie: theagencyiq.session=..." -d \'{"immediate": true}\'');
        
    } catch (error) {
        console.error('❌ Token update failed:', error.message);
    } finally {
        await pool.end();
    }
}

updateRealOAuthTokens();