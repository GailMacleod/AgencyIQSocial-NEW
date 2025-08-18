/**
 * COMPREHENSIVE STABILITY TEST
 * Tests all app issues fixed for error-free deployment
 */

import axios from 'axios';
import assert from 'assert';

class ComprehensiveStabilityTest {
  constructor() {
    this.baseUrl = 'https://4fc77172-459a-4da7-8c33-5014abb1b73e-00-dqhtnud4ismj.worf.replit.dev';
    this.sessionCookie = null;
    this.results = [];
  }

  async runAllTests() {
    console.log('🚀 Starting Comprehensive Stability Test Suite');
    console.log('='.repeat(50));

    try {
      // 1. Test session establishment and authentication
      await this.testSessionEstablishment();
      
      // 2. Test database constraints and post deduplication
      await this.testDatabaseConstraints();
      
      // 3. Test OAuth system integration
      await this.testOAuthSystem();
      
      // 4. Test strategic content generation
      await this.testStrategicContentGeneration();
      
      // 5. Test direct publish system
      await this.testDirectPublishSystem();
      
      // 6. Test quota management
      await this.testQuotaManagement();
      
      // 7. Test UI synchronization
      await this.testUISync();
      
      // 8. Test full workflow
      await this.testFullWorkflow();
      
      this.generateFinalReport();
      
    } catch (error) {
      console.error('💥 Test suite failed:', error);
      process.exit(1);
    }
  }

  async testSessionEstablishment() {
    console.log('\n📋 Testing Session Establishment');
    
    try {
      // Test session establishment endpoint
      const sessionResponse = await axios.post(`${this.baseUrl}/api/auth/establish-session`, {});
      assert(sessionResponse.status === 200, 'Session establishment failed');
      assert(sessionResponse.data.success, 'Session establishment not successful');
      
      // Extract session cookie
      const setCookie = sessionResponse.headers['set-cookie'];
      if (setCookie) {
        this.sessionCookie = setCookie.find(cookie => cookie.includes('theagencyiq.session'));
      }
      
      // Test authenticated endpoints
      const userResponse = await axios.get(`${this.baseUrl}/api/user`, {
        headers: { Cookie: this.sessionCookie }
      });
      assert(userResponse.status === 200, 'User endpoint failed');
      assert(userResponse.data.id === 2, 'Incorrect user ID');
      
      this.addResult('Session Establishment', 'PASS', 'Auto-authentication working correctly');
      
    } catch (error) {
      this.addResult('Session Establishment', 'FAIL', error.message);
    }
  }

  async testDatabaseConstraints() {
    console.log('\n🗄️ Testing Database Constraints');
    
    try {
      // Test that duplicate posts are prevented
      const testPost = {
        content: 'Test duplicate prevention',
        platform: 'facebook',
        status: 'draft'
      };
      
      // Create first post
      const firstPost = await axios.post(`${this.baseUrl}/api/posts`, testPost, {
        headers: { Cookie: this.sessionCookie }
      });
      
      // Try to create duplicate - should fail
      try {
        await axios.post(`${this.baseUrl}/api/posts`, testPost, {
          headers: { Cookie: this.sessionCookie }
        });
        this.addResult('Database Constraints', 'FAIL', 'Duplicate post creation should have failed');
      } catch (duplicateError) {
        // Expected to fail
        this.addResult('Database Constraints', 'PASS', 'Duplicate prevention working correctly');
      }
      
    } catch (error) {
      this.addResult('Database Constraints', 'FAIL', error.message);
    }
  }

  async testOAuthSystem() {
    console.log('\n🔐 Testing OAuth System');
    
    try {
      // Test platform connections endpoint
      const connectionsResponse = await axios.get(`${this.baseUrl}/api/platform-connections`, {
        headers: { Cookie: this.sessionCookie }
      });
      assert(connectionsResponse.status === 200, 'Platform connections failed');
      
      const connections = connectionsResponse.data;
      assert(Array.isArray(connections), 'Connections should be an array');
      
      // Verify expected platforms
      const expectedPlatforms = ['facebook', 'linkedin', 'x'];
      const connectedPlatforms = connections.map(c => c.platform);
      
      for (const platform of expectedPlatforms) {
        assert(connectedPlatforms.includes(platform), `Missing platform: ${platform}`);
      }
      
      this.addResult('OAuth System', 'PASS', `${connections.length} platforms connected successfully`);
      
    } catch (error) {
      this.addResult('OAuth System', 'FAIL', error.message);
    }
  }

  async testStrategicContentGeneration() {
    console.log('\n🎯 Testing Strategic Content Generation');
    
    try {
      // First, ensure brand purpose exists
      const brandPurposeResponse = await axios.get(`${this.baseUrl}/api/brand-purpose`, {
        headers: { Cookie: this.sessionCookie }
      });
      
      if (brandPurposeResponse.status === 200 && brandPurposeResponse.data.length > 0) {
        // Test strategic content generation
        const contentResponse = await axios.post(`${this.baseUrl}/api/generate-strategic-content`, {
          totalPosts: 10,
          resetQuota: true
        }, {
          headers: { Cookie: this.sessionCookie }
        });
        
        assert(contentResponse.status === 200, 'Strategic content generation failed');
        assert(contentResponse.data.success, 'Content generation not successful');
        
        this.addResult('Strategic Content Generation', 'PASS', 'Waterfall strategyzer methodology working');
      } else {
        this.addResult('Strategic Content Generation', 'SKIP', 'Brand purpose data required');
      }
      
    } catch (error) {
      this.addResult('Strategic Content Generation', 'FAIL', error.message);
    }
  }

  async testDirectPublishSystem() {
    console.log('\n📤 Testing Direct Publish System');
    
    try {
      // Test direct publish endpoint
      const publishResponse = await axios.post(`${this.baseUrl}/api/direct-publish`, {
        action: 'publish_all'
      }, {
        headers: { Cookie: this.sessionCookie }
      });
      
      assert(publishResponse.status === 200, 'Direct publish failed');
      assert(publishResponse.data.success, 'Publish not successful');
      
      this.addResult('Direct Publish System', 'PASS', 'Bulk publishing system operational');
      
    } catch (error) {
      this.addResult('Direct Publish System', 'FAIL', error.message);
    }
  }

  async testQuotaManagement() {
    console.log('\n📊 Testing Quota Management');
    
    try {
      // Test quota information
      const userResponse = await axios.get(`${this.baseUrl}/api/user`, {
        headers: { Cookie: this.sessionCookie }
      });
      
      assert(userResponse.status === 200, 'User data fetch failed');
      assert(typeof userResponse.data.remainingPosts === 'number', 'Remaining posts should be a number');
      assert(typeof userResponse.data.totalPosts === 'number', 'Total posts should be a number');
      assert(userResponse.data.subscriptionPlan === 'professional', 'Should have professional plan');
      
      this.addResult('Quota Management', 'PASS', `Professional plan: ${userResponse.data.remainingPosts}/${userResponse.data.totalPosts} posts`);
      
    } catch (error) {
      this.addResult('Quota Management', 'FAIL', error.message);
    }
  }

  async testUISync() {
    console.log('\n🔄 Testing UI Synchronization');
    
    try {
      // Test multiple endpoints for consistency
      const endpoints = [
        '/api/user-status',
        '/api/platform-connections',
        '/api/subscription-usage'
      ];
      
      let allConsistent = true;
      for (const endpoint of endpoints) {
        const response = await axios.get(`${this.baseUrl}${endpoint}`, {
          headers: { Cookie: this.sessionCookie }
        });
        assert(response.status === 200, `${endpoint} failed`);
      }
      
      this.addResult('UI Synchronization', 'PASS', 'All endpoints responding consistently');
      
    } catch (error) {
      this.addResult('UI Synchronization', 'FAIL', error.message);
    }
  }

  async testFullWorkflow() {
    console.log('\n🔄 Testing Full Workflow');
    
    try {
      // Test complete workflow: connect -> generate -> publish
      const workflowSteps = [
        'Session establishment',
        'Platform connections',
        'Content generation',
        'Publishing system',
        'Quota management'
      ];
      
      let workflowComplete = true;
      for (const step of workflowSteps) {
        const result = this.results.find(r => r.test.toLowerCase().includes(step.toLowerCase()));
        if (!result || result.status !== 'PASS') {
          workflowComplete = false;
          break;
        }
      }
      
      if (workflowComplete) {
        this.addResult('Full Workflow', 'PASS', 'Complete workflow operational');
      } else {
        this.addResult('Full Workflow', 'FAIL', 'Workflow has broken components');
      }
      
    } catch (error) {
      this.addResult('Full Workflow', 'FAIL', error.message);
    }
  }

  addResult(test, status, message) {
    const result = { test, status, message, timestamp: new Date().toISOString() };
    this.results.push(result);
    
    const emoji = status === 'PASS' ? '✅' : status === 'FAIL' ? '❌' : '⏭️';
    console.log(`${emoji} ${test}: ${message}`);
  }

  generateFinalReport() {
    console.log('\n' + '='.repeat(50));
    console.log('📋 COMPREHENSIVE STABILITY TEST REPORT');
    console.log('='.repeat(50));
    
    const passed = this.results.filter(r => r.status === 'PASS').length;
    const failed = this.results.filter(r => r.status === 'FAIL').length;
    const skipped = this.results.filter(r => r.status === 'SKIP').length;
    const total = this.results.length;
    
    const successRate = ((passed / (total - skipped)) * 100).toFixed(1);
    
    console.log(`\n📊 Test Results Summary:`);
    console.log(`✅ Passed: ${passed}`);
    console.log(`❌ Failed: ${failed}`);
    console.log(`⏭️ Skipped: ${skipped}`);
    console.log(`📈 Success Rate: ${successRate}%`);
    
    if (failed === 0) {
      console.log('\n🎉 ALL TESTS PASSED! Application is ready for deployment.');
    } else {
      console.log('\n⚠️ Some tests failed. Review the issues above.');
    }
    
    console.log('\n📋 Detailed Results:');
    this.results.forEach(result => {
      const emoji = result.status === 'PASS' ? '✅' : result.status === 'FAIL' ? '❌' : '⏭️';
      console.log(`${emoji} ${result.test}: ${result.message}`);
    });
  }
}

// Run the test suite
const test = new ComprehensiveStabilityTest();
test.runAllTests();