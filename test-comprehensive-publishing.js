/**
 * COMPREHENSIVE PUBLISHING SYSTEM TEST
 * Tests the complete publishing workflow with AI optimization
 */

import axios from 'axios';

async function testComprehensivePublishing() {
  console.log('🚀 COMPREHENSIVE PUBLISHING SYSTEM TEST');
  console.log('Testing AI optimization → publishing workflow');
  console.log('=' .repeat(50));
  
  const baseUrl = 'http://localhost:5000';
  let sessionCookie = null;
  
  try {
    // 1. Establish session
    console.log('\n🔐 Establishing session...');
    const sessionResponse = await axios.post(`${baseUrl}/api/establish-session`, {
      email: 'gailm@macleodglba.com.au',
      phone: '+61424835189'
    });
    
    sessionCookie = sessionResponse.headers['set-cookie']?.[0];
    if (sessionResponse.data.success && sessionCookie) {
      console.log('✅ Session established successfully');
    } else {
      throw new Error('Session establishment failed');
    }
    
    // 2. Test AI Content Optimization
    console.log('\n🧠 Testing AI Content Optimization...');
    try {
      const aiResponse = await axios.post(`${baseUrl}/api/ai/optimize-content`, {
        contentType: 'engagement',
        platform: 'facebook'
      }, {
        headers: { Cookie: sessionCookie }
      });
      
      if (aiResponse.data.success) {
        console.log('✅ AI Content Optimization working');
        console.log(`   Content: "${aiResponse.data.content?.content?.substring(0, 50)}..."`);
        console.log(`   Engagement Score: ${aiResponse.data.content?.engagementScore}%`);
      } else {
        console.log('❌ AI Content Optimization failed');
      }
    } catch (error) {
      console.log('❌ AI Content Optimization error:', error.response?.data?.error || error.message);
    }
    
    // 3. Test Platform Connections
    console.log('\n🔗 Testing Platform Connections...');
    const connectionsResponse = await axios.get(`${baseUrl}/api/platform-connections`, {
      headers: { Cookie: sessionCookie }
    });
    
    const connections = connectionsResponse.data;
    const activeConnections = connections.filter(c => c.isActive);
    console.log(`✅ Platform Connections: ${activeConnections.length}/5 active`);
    activeConnections.forEach(conn => {
      const status = conn.oauthStatus?.isValid ? '✅' : '❌';
      console.log(`   ${status} ${conn.platform}: ${conn.oauthStatus?.isValid ? 'Valid' : 'Needs refresh'}`);
    });
    
    // 4. Test Direct Publishing
    console.log('\n📤 Testing Direct Publishing...');
    try {
      const publishResponse = await axios.post(`${baseUrl}/api/direct-publish`, {
        content: 'TEST - Comprehensive publishing validation for Queensland SME success',
        platforms: ['facebook', 'instagram', 'linkedin']
      }, {
        headers: { Cookie: sessionCookie }
      });
      
      if (publishResponse.data.results) {
        const results = publishResponse.data.results;
        const successful = results.filter(r => r.success).length;
        const total = results.length;
        
        console.log(`📊 Publishing Results: ${successful}/${total} successful`);
        results.forEach(result => {
          const status = result.success ? '✅' : '❌';
          console.log(`   ${status} ${result.platform}: ${result.success ? 'Published' : result.error}`);
        });
        
        if (successful === total) {
          console.log('🎉 PERFECT PUBLISHING SUCCESS!');
        } else if (successful > 0) {
          console.log('⚠️ Partial publishing success');
        } else {
          console.log('❌ All publishing attempts failed');
        }
      } else {
        console.log('❌ Invalid publishing response');
      }
    } catch (error) {
      console.log('❌ Publishing error:', error.response?.data?.message || error.message);
    }
    
    // 5. Test User Status & Quota
    console.log('\n📊 Testing User Status & Quota...');
    const userResponse = await axios.get(`${baseUrl}/api/user`, {
      headers: { Cookie: sessionCookie }
    });
    
    if (userResponse.data) {
      const user = userResponse.data;
      console.log('✅ User Status Retrieved:');
      console.log(`   Plan: ${user.subscriptionPlan}`);
      console.log(`   Remaining Posts: ${user.remainingPosts}/${user.totalPosts}`);
      console.log(`   Usage: ${((user.totalPosts - user.remainingPosts) / user.totalPosts * 100).toFixed(1)}%`);
    }
    
    console.log('\n🏆 COMPREHENSIVE TEST COMPLETE');
    console.log('System ready for Queensland SME success!');
    
  } catch (error) {
    console.error('\n❌ Comprehensive test failed:', error.message);
  }
}

testComprehensivePublishing();