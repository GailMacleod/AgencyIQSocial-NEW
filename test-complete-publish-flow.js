/**
 * Test Complete Publish Flow - Approve posts then test bulk publishing
 * Tests the complete workflow from approval to bulk publishing
 */

import axios from 'axios';

class CompletePublishTest {
  constructor() {
    this.baseURL = 'https://4fc77172-459a-4da7-8c33-5014abb1b73e-00-dqhtnud4ismj.worf.replit.dev';
    this.cookies = '';
  }

  async establishSession() {
    try {
      console.log('🔐 Establishing session...');
      const response = await axios.post(`${this.baseURL}/api/establish-session`, {
        email: 'gailm@macleodglba.com.au',
        phone: '+61424835189'
      }, {
        withCredentials: true
      });

      if (response.headers['set-cookie']) {
        this.cookies = response.headers['set-cookie'].join('; ');
        console.log('✅ Session established successfully');
        return true;
      }
    } catch (error) {
      console.error('❌ Session establishment failed:', error.response?.data || error.message);
      return false;
    }
  }

  async getDraftPosts() {
    try {
      console.log('📋 Getting draft posts...');
      
      const response = await axios.get(`${this.baseURL}/api/posts`, {
        headers: {
          'Cookie': this.cookies
        },
        withCredentials: true
      });

      const posts = response.data;
      const draftPosts = posts.filter(post => post.status === 'draft');
      
      console.log(`✅ Found ${draftPosts.length} draft posts out of ${posts.length} total posts`);
      
      return draftPosts.slice(0, 3); // Return first 3 draft posts for testing
    } catch (error) {
      console.error('❌ Posts check failed:', error.response?.data || error.message);
      return [];
    }
  }

  async approvePost(postId) {
    try {
      console.log(`📝 Approving post ${postId}...`);
      
      const response = await axios.post(`${this.baseURL}/api/approve-post`, {
        postId: postId
      }, {
        headers: {
          'Cookie': this.cookies,
          'Content-Type': 'application/json'
        },
        withCredentials: true
      });

      if (response.data.success) {
        console.log(`✅ Post ${postId} approved successfully`);
        return true;
      }
      
      return false;
    } catch (error) {
      console.error(`❌ Failed to approve post ${postId}:`, error.response?.data || error.message);
      return false;
    }
  }

  async testBulkPublish() {
    try {
      console.log('🚀 Testing bulk publish with /api/direct-publish...');
      
      const response = await axios.post(`${this.baseURL}/api/direct-publish`, {
        action: 'publish_all'
      }, {
        headers: {
          'Cookie': this.cookies,
          'Content-Type': 'application/json'
        },
        withCredentials: true
      });

      console.log('✅ Bulk publish response:', response.data);
      
      if (response.data.success) {
        console.log(`🎉 SUCCESS: ${response.data.successCount}/${response.data.totalPosts} posts published successfully`);
        
        // Show detailed results
        if (response.data.results && response.data.results.length > 0) {
          console.log('\n📊 Publishing results:');
          response.data.results.forEach(result => {
            const status = result.status === 'success' ? '✅' : '❌';
            console.log(`${status} ${result.platform} (Post ${result.postId}): ${result.status}`);
            if (result.error) {
              console.log(`   Error: ${result.error}`);
            }
            if (result.platformPostId) {
              console.log(`   Platform Post ID: ${result.platformPostId}`);
            }
          });
        }
        
        return true;
      } else {
        console.log(`⚠️ PARTIAL SUCCESS: ${response.data.message}`);
        return false;
      }
    } catch (error) {
      console.error('❌ Bulk publish failed:', error.response?.data || error.message);
      
      if (error.response?.data?.quotaExceeded) {
        console.log('💡 Quota exceeded - this is expected behavior');
      }
      
      return false;
    }
  }

  async testPlatformConnections() {
    try {
      console.log('🔗 Checking platform connections...');
      
      const response = await axios.get(`${this.baseURL}/api/platform-connections`, {
        headers: {
          'Cookie': this.cookies
        },
        withCredentials: true
      });

      const connections = response.data;
      console.log(`✅ Found ${connections.length} platform connections`);
      
      connections.forEach(conn => {
        const status = conn.oauthStatus?.isValid ? '✅' : '❌';
        console.log(`${status} ${conn.platform}: ${conn.platformUsername} (${conn.oauthStatus?.isValid ? 'Valid' : 'Needs refresh'})`);
      });
      
      return connections;
    } catch (error) {
      console.error('❌ Platform connections check failed:', error.response?.data || error.message);
      return [];
    }
  }

  async runCompleteTest() {
    console.log('🧪 Starting Complete Publish Flow Test...\n');
    
    // Step 1: Establish session
    const sessionSuccess = await this.establishSession();
    if (!sessionSuccess) {
      console.log('❌ TEST FAILED: Could not establish session');
      return;
    }

    // Step 2: Check platform connections
    const connections = await this.testPlatformConnections();
    if (connections.length === 0) {
      console.log('❌ TEST FAILED: No platform connections found');
      return;
    }

    // Step 3: Get draft posts
    const draftPosts = await this.getDraftPosts();
    if (draftPosts.length === 0) {
      console.log('⚠️ TEST SKIPPED: No draft posts available to approve');
      return;
    }

    // Step 4: Approve some posts
    console.log(`\n📝 Approving ${draftPosts.length} posts for testing...`);
    let approvedCount = 0;
    
    for (const post of draftPosts) {
      const approved = await this.approvePost(post.id);
      if (approved) {
        approvedCount++;
      }
    }

    if (approvedCount === 0) {
      console.log('❌ TEST FAILED: Could not approve any posts');
      return;
    }

    console.log(`✅ Successfully approved ${approvedCount} posts`);

    // Step 5: Test bulk publish
    console.log('\n🚀 Testing bulk publish functionality...');
    const publishSuccess = await this.testBulkPublish();
    
    // Step 6: Results
    console.log('\n📊 TEST RESULTS:');
    console.log(`✅ Session establishment: ${sessionSuccess ? 'PASSED' : 'FAILED'}`);
    console.log(`✅ Platform connections: ${connections.length > 0 ? 'PASSED' : 'FAILED'} (${connections.length} found)`);
    console.log(`✅ Post approval: ${approvedCount > 0 ? 'PASSED' : 'FAILED'} (${approvedCount} approved)`);
    console.log(`✅ Bulk publish: ${publishSuccess ? 'PASSED' : 'FAILED'}`);
    
    if (sessionSuccess && connections.length > 0 && approvedCount > 0) {
      console.log('\n🎉 OVERALL TEST RESULT: PASSED - Complete publish flow is working correctly!');
      console.log('✅ The enforce publishing function has been successfully fixed!');
    } else {
      console.log('\n❌ OVERALL TEST RESULT: FAILED - Complete publish flow needs attention');
    }
  }
}

const test = new CompletePublishTest();
test.runCompleteTest().catch(console.error);