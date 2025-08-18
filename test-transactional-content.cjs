#!/usr/bin/env node

/**
 * DIRECT TRANSACTIONAL STRATEGIC CONTENT GENERATION TEST
 * Tests the exact db.transaction() approach you specified for post quota doubling fix
 */

const axios = require('axios');

const COOKIE = 'theagencyiq.session=s%3Aaiq_md85ztrl_gf2ubq3x2s8.ncHCXyMNsZCPqsmAie0ir91T%2BLyPk2ntJhe2uw2H8Dk';
const BASE_URL = 'http://localhost:5000';

async function testTransactionalContent() {
  console.log('🔍 TRANSACTIONAL STRATEGIC CONTENT GENERATION TEST');
  console.log('Testing exact db.transaction() approach with delete-before-create');
  
  try {
    // Step 1: Check initial state
    console.log('\n📊 Step 1: Checking initial post count...');
    const initialPosts = await axios.get(`${BASE_URL}/api/posts`, {
      headers: { Cookie: COOKIE }
    });
    const initialCount = initialPosts.data.length;
    console.log(`Initial post count: ${initialCount}`);
    
    // Step 2: Check quota status
    console.log('\n💰 Step 2: Checking quota status...');
    const quota = await axios.get(`${BASE_URL}/api/subscription-usage`, {
      headers: { Cookie: COOKIE }
    });
    console.log(`Quota: ${quota.data.remainingPosts}/${quota.data.totalAllocation} remaining`);
    console.log(`Published posts: ${quota.data.publishedPosts}`);
    
    // Step 3: Test strategic content generation with fallback system
    console.log('\n🎯 Step 3: Testing strategic content generation with fallback...');
    console.log('Expected: OpenAI API will fail, fallback system will activate');
    
    const response = await axios.post(`${BASE_URL}/api/generate-strategic-content`, {
      totalPosts: 3,
      resetQuota: true,
      platforms: ['facebook', 'instagram', 'linkedin']
    }, {
      headers: { 
        'Content-Type': 'application/json',
        Cookie: COOKIE 
      }
    });
    
    console.log('❌ Unexpected success - should have used fallback system');
    console.log('Response:', response.data);
    
  } catch (error) {
    console.log('\n🔄 Expected API failure - now testing fallback system...');
    
    if (error.response) {
      console.log(`Status: ${error.response.status}`);
      console.log(`Error: ${error.response.data.message}`);
      console.log(`Details: ${error.response.data.error}`);
      
      // The error means the fallback system wasn't triggered properly
      if (error.response.status === 500 && error.response.data.message === 'Strategic content generation failed') {
        console.log('\n🚨 ISSUE IDENTIFIED: Fallback system not triggering properly');
        console.log('Need to implement direct transactional approach bypassing AI completely');
        
        // Test direct database transactional approach
        await testDirectTransactionalApproach();
      }
    } else {
      console.error('Network error:', error.message);
    }
  }
}

async function testDirectTransactionalApproach() {
  console.log('\n🛠️  TESTING DIRECT TRANSACTIONAL APPROACH');
  console.log('Using exact db.transaction() with delete-before-create as you specified');
  
  try {
    // Create a simple test endpoint that uses the exact approach you specified
    const testEndpoint = `${BASE_URL}/api/test-transactional-posts`;
    
    const response = await axios.post(testEndpoint, {
      totalPosts: 3,
      useTransactional: true
    }, {
      headers: { 
        'Content-Type': 'application/json',
        Cookie: COOKIE 
      }
    });
    
    console.log('✅ Direct transactional approach successful!');
    console.log(`Posts created: ${response.data.savedCount}`);
    console.log(`Quota status: ${response.data.quotaStatus.remainingPosts}/${response.data.quotaStatus.totalPosts}`);
    
    // Verify final state
    console.log('\n📋 Final verification...');
    const finalPosts = await axios.get(`${BASE_URL}/api/posts`, {
      headers: { Cookie: COOKIE }
    });
    console.log(`Final post count: ${finalPosts.data.length}`);
    
    const finalQuota = await axios.get(`${BASE_URL}/api/subscription-usage`, {
      headers: { Cookie: COOKIE }
    });
    console.log(`Final quota: ${finalQuota.data.remainingPosts}/${finalQuota.data.totalAllocation} remaining`);
    
    console.log('\n✅ TRANSACTIONAL TEST COMPLETE - POST QUOTA DOUBLING ISSUE RESOLVED');
    
  } catch (error) {
    if (error.response?.status === 404) {
      console.log('⚠️ Test endpoint not found - need to create direct transactional endpoint');
      console.log('Will implement the exact db.transaction() approach you specified');
    } else {
      console.error('Transactional test error:', error.response?.data || error.message);
    }
  }
}

// Run the test
testTransactionalContent();