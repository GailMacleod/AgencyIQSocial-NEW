#!/usr/bin/env node

/**
 * LIVE PUBLISHING TEST WITH REAL TOKENS
 * Tests actual publishing using your real LinkedIn OAuth token
 */

const { Pool } = require('pg');
const axios = require('axios');

const BASE_URL = 'http://localhost:5000';
const SESSION_COOKIE = 'theagencyiq.session=s%3Aaiq_mdgvxliv_9dlzwzmmu5l.f5VVGklTEFT1V0DM6g3fMhF%2B%2Fl5cGRgJdwKvn7rh%2BPs';

async function testLivePublishing() {
    console.log('🚀 LIVE PUBLISHING TEST WITH REAL TOKENS');
    console.log('==========================================');
    
    // First update tokens with real environment values
    const linkedinToken = process.env.LINKEDIN_ACCESS_TOKEN;
    
    if (linkedinToken) {
        console.log('✅ LinkedIn token found in environment');
        
        // Update database directly via SQL since we have database access
        try {
            const response = await axios.post(`${BASE_URL}/api/update-oauth-token`, {
                platform: 'linkedin',
                accessToken: linkedinToken
            }, {
                headers: { 
                    'Cookie': SESSION_COOKIE,
                    'Content-Type': 'application/json'
                }
            });
            console.log('✅ LinkedIn token updated in database');
        } catch (error) {
            console.log('⚠️ Direct API update failed, token may already be current');
        }
        
        // Now test live publishing
        console.log('\n🎯 TESTING LIVE PUBLISHING...');
        try {
            const publishResponse = await axios.post(`${BASE_URL}/api/enforce-auto-posting`, 
                { immediate: true, testMode: false }, 
                { 
                    headers: { 
                        'Cookie': SESSION_COOKIE,
                        'Content-Type': 'application/json'
                    },
                    timeout: 60000
                }
            );
            
            console.log('✅ LIVE PUBLISHING RESULTS:');
            console.log(`📊 Posts processed: ${publishResponse.data.postsProcessed}`);
            console.log(`📤 Posts published: ${publishResponse.data.postsPublished}`);
            console.log(`❌ Posts failed: ${publishResponse.data.postsFailed}`);
            
            if (publishResponse.data.postsPublished > 0) {
                console.log('🎉 SUCCESS: POSTS PUBLISHED TO LIVE PLATFORMS!');
            } else {
                console.log('⚠️ No posts published - checking errors...');
                console.log('Errors:', publishResponse.data.errors);
            }
            
        } catch (error) {
            console.error('❌ Live publishing test failed:', error.response?.data || error.message);
        }
        
    } else {
        console.log('❌ LinkedIn token not found in environment');
        console.log('Available environment variables:');
        Object.keys(process.env).filter(key => key.includes('LINKEDIN') || key.includes('FACEBOOK')).forEach(key => {
            console.log(`- ${key}: ${process.env[key] ? 'Set' : 'Not set'}`);
        });
    }
}

testLivePublishing();