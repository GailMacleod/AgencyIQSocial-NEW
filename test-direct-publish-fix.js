/**
 * Test Direct Publish Fix - Verify publish_all action works correctly
 * Tests the new /api/direct-publish endpoint with publish_all action
 */

import axios from 'axios';
import tough from 'tough-cookie';

const BASE_URL = 'https://4fc77172-459a-4da7-8c33-5014abb1b73e-00-dqhtnud4ismj.worf.replit.dev';

class DirectPublishTest {
  constructor() {
    this.cookieJar = new tough.CookieJar();
    this.sessionCookie = null;
    this.results = [];
  }

  async establishSession() {
    try {
      const response = await axios.post(`${BASE_URL}/api/establish-session`, {
        email: 'gailm@macleodglba.com.au'
      });
      
      console.log('✅ Session established:', response.data.success);
      this.sessionCookie = response.headers['set-cookie']?.[0];
      return true;
    } catch (error) {
      console.error('❌ Session establishment failed:', error.response?.data || error.message);
      return false;
    }
  }

  async testDirectPublishEndpoint() {
    try {
      console.log('\n🔄 Testing direct publish endpoint...');
      
      const response = await axios.post(`${BASE_URL}/api/direct-publish`, {
        action: 'publish_all'
      }, {
        headers: {
          Cookie: this.sessionCookie,
          'Content-Type': 'application/json'
        }
      });
      
      console.log('✅ Direct publish response:', response.data);
      return response.data;
    } catch (error) {
      console.error('❌ Direct publish failed:', error.response?.data || error.message);
      return null;
    }
  }

  async testQuotaStatus() {
    try {
      const response = await axios.get(`${BASE_URL}/api/user-status`, {
        headers: {
          Cookie: this.sessionCookie
        }
      });
      
      console.log('📊 Quota status:', response.data.remainingPosts, '/', response.data.totalPosts);
      return response.data;
    } catch (error) {
      console.error('❌ Quota status failed:', error.response?.data || error.message);
      return null;
    }
  }

  async testApprovedPosts() {
    try {
      const response = await axios.get(`${BASE_URL}/api/posts?status=approved`, {
        headers: {
          Cookie: this.sessionCookie
        }
      });
      
      console.log('📄 Approved posts:', response.data.length);
      return response.data;
    } catch (error) {
      console.error('❌ Approved posts failed:', error.response?.data || error.message);
      return [];
    }
  }

  async runTest() {
    console.log('🧪 DIRECT PUBLISH TEST - Testing force_publish_all functionality\n');
    
    // Step 1: Establish session
    const sessionSuccess = await this.establishSession();
    if (!sessionSuccess) {
      console.log('❌ Test failed: Could not establish session');
      return;
    }
    
    // Step 2: Check quota before publishing
    const quotaBefore = await this.testQuotaStatus();
    
    // Step 3: Check approved posts
    const approvedPosts = await this.testApprovedPosts();
    
    // Step 4: Test direct publish endpoint
    const publishResult = await this.testDirectPublishEndpoint();
    
    // Step 5: Check quota after publishing
    const quotaAfter = await this.testQuotaStatus();
    
    // Step 6: Generate report
    console.log('\n📋 DIRECT PUBLISH TEST RESULTS:');
    console.log('====================================');
    console.log(`📊 Quota before: ${quotaBefore?.remainingPosts || 0}/${quotaBefore?.totalPosts || 0}`);
    console.log(`📄 Approved posts: ${approvedPosts.length}`);
    console.log(`🚀 Publish result: ${publishResult ? 'SUCCESS' : 'FAILED'}`);
    console.log(`📊 Quota after: ${quotaAfter?.remainingPosts || 0}/${quotaAfter?.totalPosts || 0}`);
    
    const success = publishResult && publishResult.success;
    
    if (success) {
      console.log('\n🎉 DIRECT PUBLISH WORKING - force_publish_all successful!');
    } else {
      console.log('\n⚠️ Direct publish needs attention');
    }
    
    return {
      success,
      quotaBefore,
      approvedPosts: approvedPosts.length,
      publishResult,
      quotaAfter
    };
  }
}

// Run the test
const test = new DirectPublishTest();
test.runTest().then(result => {
  console.log('\n✅ Direct publish test completed');
  process.exit(result.success ? 0 : 1);
}).catch(error => {
  console.error('❌ Test execution failed:', error);
  process.exit(1);
});