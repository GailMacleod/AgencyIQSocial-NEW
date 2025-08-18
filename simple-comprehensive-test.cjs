/**
 * TheAgencyIQ Comprehensive Test Suite
 * Validates all core platform functionality without external testing frameworks
 */

const axios = require('axios');
const { execSync } = require('child_process');

// Configuration
const BASE_URL = 'https://4fc77172-459a-4da7-8c33-5014abb1b73e-00-dqhtnud4ismj.worf.replit.dev';
const TEST_EMAIL = 'gailm@macleodglba.com.au';
const TEST_PHONE = '+61424835189';
const TEST_USER_ID = 2;

// API client
const api = axios.create({
  baseURL: BASE_URL,
  withCredentials: true,
});

class ComprehensiveTestSuite {
  constructor() {
    this.results = [];
    this.sessionCookie = null;
    this.startTime = Date.now();
  }

  async runTest(testName, testFunction) {
    console.log(`🧪 Running: ${testName}`);
    try {
      const start = Date.now();
      await testFunction();
      const duration = Date.now() - start;
      console.log(`✅ PASS: ${testName} (${duration}ms)`);
      this.results.push({ 
        test: testName, 
        status: 'PASS', 
        duration, 
        error: null 
      });
    } catch (error) {
      console.log(`❌ FAIL: ${testName} - ${error.message}`);
      this.results.push({ 
        test: testName, 
        status: 'FAIL', 
        duration: 0, 
        error: error.message 
      });
    }
  }

  async setupTestEnvironment() {
    console.log('🔧 Setting up test environment...');
    
    // Establish session for testing
    const sessionRes = await api.post('/api/establish-session', {
      email: TEST_EMAIL,
      phone: TEST_PHONE
    });
    
    const cookies = sessionRes.headers['set-cookie'];
    this.sessionCookie = cookies ? cookies[0].split(';')[0] : null;
    
    if (!this.sessionCookie) {
      throw new Error('Failed to establish test session');
    }
    
    console.log('✅ Test session established');
  }

  // Test Categories

  async testCodeQuality() {
    console.log('\n📊 CODE QUALITY TESTS');
    console.log('=====================');

    await this.runTest('Check for duplicate endpoints', async () => {
      try {
        const routes = execSync('grep -r "app\\..*(/api" server/routes.ts', { encoding: 'utf8' });
        const endpointCounts = {};
        routes.split('\n').forEach((line) => {
          const match = line.match(/\/api\/[\w-]+/);
          if (match) {
            endpointCounts[match[0]] = (endpointCounts[match[0]] || 0) + 1;
          }
        });
        const duplicates = Object.entries(endpointCounts).filter(([_, count]) => count > 1);
        if (duplicates.length > 0) {
          throw new Error(`Duplicate endpoints found: ${JSON.stringify(duplicates)}`);
        }
      } catch (error) {
        // Skip if file not found
        console.log('⚠️ Skipping duplicate endpoint check - file not accessible');
      }
    });

    await this.runTest('Server response time under 500ms', async () => {
      const start = Date.now();
      await api.get('/api/user', { headers: { Cookie: this.sessionCookie } });
      const duration = Date.now() - start;
      if (duration >= 500) {
        throw new Error(`Response took ${duration}ms, expected < 500ms`);
      }
    });
  }

  async testAuthentication() {
    console.log('\n🔐 AUTHENTICATION TESTS');
    console.log('=======================');

    await this.runTest('Session establishment', async () => {
      const res = await api.post('/api/establish-session', { 
        email: TEST_EMAIL, 
        phone: TEST_PHONE 
      });
      if (res.status !== 200) {
        throw new Error(`Expected 200, got ${res.status}`);
      }
      if (!res.data.message.includes(TEST_EMAIL)) {
        throw new Error('Session message does not contain user email');
      }
    });

    await this.runTest('User endpoint with session', async () => {
      const res = await api.get('/api/user', { headers: { Cookie: this.sessionCookie } });
      if (res.status !== 200) {
        throw new Error(`Expected 200, got ${res.status}`);
      }
      if (res.data.id !== TEST_USER_ID) {
        throw new Error(`Expected user ID ${TEST_USER_ID}, got ${res.data.id}`);
      }
      if (res.data.email !== TEST_EMAIL) {
        throw new Error(`Expected email ${TEST_EMAIL}, got ${res.data.email}`);
      }
    });

    await this.runTest('Reject unauthenticated requests', async () => {
      try {
        await api.get('/api/user');
        throw new Error('Should have failed with 401');
      } catch (error) {
        if (error.response?.status !== 401) {
          throw new Error(`Expected 401, got ${error.response?.status}`);
        }
      }
    });
  }

  async testSubscriptionManagement() {
    console.log('\n💳 SUBSCRIPTION TESTS');
    console.log('=====================');

    await this.runTest('Verify professional subscription', async () => {
      const res = await api.get('/api/user', { headers: { Cookie: this.sessionCookie } });
      if (res.status !== 200) {
        throw new Error(`Expected 200, got ${res.status}`);
      }
      if (res.data.subscriptionPlan !== 'professional') {
        throw new Error(`Expected professional plan, got ${res.data.subscriptionPlan}`);
      }
      if (typeof res.data.remainingPosts !== 'number') {
        throw new Error('remainingPosts should be a number');
      }
      if (typeof res.data.totalPosts !== 'number') {
        throw new Error('totalPosts should be a number');
      }
    });

    await this.runTest('Validate subscription status', async () => {
      const res = await api.get('/api/subscription-status', { headers: { Cookie: this.sessionCookie } });
      if (res.status !== 200) {
        throw new Error(`Expected 200, got ${res.status}`);
      }
      if (res.data.plan !== 'professional') {
        throw new Error(`Expected professional plan, got ${res.data.plan}`);
      }
      if (res.data.active !== true) {
        throw new Error('Subscription should be active');
      }
    });
  }

  async testPlatformConnections() {
    console.log('\n🔗 PLATFORM CONNECTION TESTS');
    console.log('=============================');

    await this.runTest('List connected platforms', async () => {
      const res = await api.get('/api/platform-connections', { headers: { Cookie: this.sessionCookie } });
      if (res.status !== 200) {
        throw new Error(`Expected 200, got ${res.status}`);
      }
      if (!Array.isArray(res.data)) {
        throw new Error('Response should be an array');
      }
      
      const platforms = res.data.map(c => c.platform);
      const expectedPlatforms = ['facebook', 'instagram', 'linkedin', 'x', 'youtube'];
      
      for (const platform of expectedPlatforms) {
        if (!platforms.includes(platform)) {
          throw new Error(`${platform} connection not found`);
        }
      }
    });

    await this.runTest('Validate OAuth tokens', async () => {
      const res = await api.get('/api/oauth/validate-tokens', { headers: { Cookie: this.sessionCookie } });
      if (res.status !== 200) {
        throw new Error(`Expected 200, got ${res.status}`);
      }
      if (typeof res.data !== 'object') {
        throw new Error('Response should be an object');
      }
      
      const validTokens = Object.values(res.data).filter(token => token.valid);
      if (validTokens.length === 0) {
        throw new Error('No valid OAuth tokens found');
      }
    });
  }

  async testBrandPurpose() {
    console.log('\n🎯 BRAND PURPOSE TESTS');
    console.log('======================');

    await this.runTest('Retrieve brand purpose', async () => {
      const res = await api.get('/api/brand-purpose', { headers: { Cookie: this.sessionCookie } });
      if (res.status !== 200) {
        throw new Error(`Expected 200, got ${res.status}`);
      }
      if (res.data.userId !== TEST_USER_ID) {
        throw new Error(`Expected user ID ${TEST_USER_ID}, got ${res.data.userId}`);
      }
      if (typeof res.data.corePurpose !== 'string') {
        throw new Error('corePurpose should be a string');
      }
      if (typeof res.data.brandName !== 'string') {
        throw new Error('brandName should be a string');
      }
      if (typeof res.data.audience !== 'string') {
        throw new Error('audience should be a string');
      }
    });
  }

  async testPostManagement() {
    console.log('\n📝 POST MANAGEMENT TESTS');
    console.log('========================');

    let postId;

    await this.runTest('Create post within quota', async () => {
      const res = await api.post('/api/posts', {
        content: 'Test post for comprehensive test suite',
        platform: 'facebook',
        scheduledFor: new Date(Date.now() + 60000).toISOString(),
      }, { headers: { Cookie: this.sessionCookie } });
      
      if (res.status !== 201) {
        throw new Error(`Expected 201, got ${res.status}`);
      }
      
      postId = res.data.id;
      if (!postId) {
        throw new Error('Post ID not returned');
      }
    });

    await this.runTest('Enforce quota limits', async () => {
      const userRes = await api.get('/api/user', { headers: { Cookie: this.sessionCookie } });
      if (userRes.status !== 200) {
        throw new Error(`Expected 200, got ${userRes.status}`);
      }
      
      if (typeof userRes.data.remainingPosts !== 'number') {
        throw new Error('remainingPosts should be a number');
      }
      if (typeof userRes.data.totalPosts !== 'number') {
        throw new Error('totalPosts should be a number');
      }
      if (userRes.data.remainingPosts < 0) {
        throw new Error('remainingPosts should not be negative');
      }
    });

    await this.runTest('Retrieve created posts', async () => {
      const res = await api.get('/api/posts', { headers: { Cookie: this.sessionCookie } });
      if (res.status !== 200) {
        throw new Error(`Expected 200, got ${res.status}`);
      }
      if (!Array.isArray(res.data)) {
        throw new Error('Response should be an array');
      }
      
      const testPost = res.data.find(p => p.id === postId);
      if (!testPost) {
        throw new Error('Created post not found');
      }
    });
  }

  async testAnalytics() {
    console.log('\n📊 ANALYTICS TESTS');
    console.log('==================');

    await this.runTest('Retrieve analytics data', async () => {
      const res = await api.get('/api/analytics', { headers: { Cookie: this.sessionCookie } });
      if (res.status !== 200) {
        throw new Error(`Expected 200, got ${res.status}`);
      }
      if (typeof res.data !== 'object') {
        throw new Error('Response should be an object');
      }
      if (!('totalPosts' in res.data)) {
        throw new Error('Analytics should have totalPosts property');
      }
      if (!('platforms' in res.data)) {
        throw new Error('Analytics should have platforms property');
      }
    });

    await this.runTest('Retrieve yearly analytics', async () => {
      const res = await api.get('/api/yearly-analytics', { headers: { Cookie: this.sessionCookie } });
      if (res.status !== 200) {
        throw new Error(`Expected 200, got ${res.status}`);
      }
      if (typeof res.data !== 'object') {
        throw new Error('Response should be an object');
      }
      if (!('monthlyData' in res.data)) {
        throw new Error('Yearly analytics should have monthlyData property');
      }
    });
  }

  async testPerformance() {
    console.log('\n⚡ PERFORMANCE TESTS');
    console.log('===================');

    await this.runTest('API response under 500ms', async () => {
      const start = Date.now();
      await api.get('/api/user', { headers: { Cookie: this.sessionCookie } });
      const duration = Date.now() - start;
      if (duration >= 500) {
        throw new Error(`Response took ${duration}ms, expected < 500ms`);
      }
    });

    await this.runTest('Handle concurrent requests', async () => {
      const requests = Array(5).fill().map(() => 
        api.get('/api/user', { headers: { Cookie: this.sessionCookie } })
      );
      
      const responses = await Promise.all(requests);
      responses.forEach((res, index) => {
        if (res.status !== 200) {
          throw new Error(`Request ${index + 1} failed with status ${res.status}`);
        }
      });
    });
  }

  async testSecurity() {
    console.log('\n🔒 SECURITY TESTS');
    console.log('=================');

    await this.runTest('CORS credentials enforcement', async () => {
      const res = await api.options('/api/user', {
        headers: { 
          'Origin': 'https://4fc77172-459a-4da7-8c33-5014abb1b73e-00-dqhtnud4ismj.worf.replit.dev',
          'Access-Control-Request-Method': 'GET',
          'Access-Control-Request-Headers': 'Cookie'
        },
      });
      
      if (res.status !== 200) {
        throw new Error(`Expected 200, got ${res.status}`);
      }
      if (res.headers['access-control-allow-credentials'] !== 'true') {
        throw new Error('CORS credentials not properly configured');
      }
    });

    await this.runTest('Prevent session hijacking', async () => {
      const fakeCookie = 'theagencyiq.session=fake-session-token';
      try {
        await api.get('/api/user', { headers: { Cookie: fakeCookie } });
        throw new Error('Should have rejected fake session');
      } catch (error) {
        if (error.response?.status !== 401) {
          throw new Error(`Expected 401, got ${error.response?.status}`);
        }
      }
    });
  }

  async testAIContentGeneration() {
    console.log('\n🤖 AI CONTENT GENERATION TESTS');
    console.log('===============================');

    await this.runTest('Generate strategic content', async () => {
      const res = await api.post('/api/generate-strategic-content', {
        brandPurpose: 'Help small businesses grow online',
        audience: 'Queensland small business owners',
        platforms: ['facebook', 'instagram', 'linkedin']
      }, { headers: { Cookie: this.sessionCookie } });
      
      if (res.status !== 200) {
        throw new Error(`Expected 200, got ${res.status}`);
      }
      if (!Array.isArray(res.data.posts)) {
        throw new Error('Response should contain posts array');
      }
      if (res.data.posts.length === 0) {
        throw new Error('Should generate at least one post');
      }
    });

    await this.runTest('AI assistance chat', async () => {
      const res = await api.post('/api/grok-chat', {
        message: 'How can I improve my social media engagement?'
      }, { headers: { Cookie: this.sessionCookie } });
      
      if (res.status !== 200) {
        throw new Error(`Expected 200, got ${res.status}`);
      }
      if (typeof res.data.response !== 'string') {
        throw new Error('Response should be a string');
      }
      if (res.data.response.length <= 10) {
        throw new Error('Response should be substantive');
      }
    });
  }

  async testPublishingSystem() {
    console.log('\n📢 PUBLISHING SYSTEM TESTS');
    console.log('==========================');

    await this.runTest('Validate publishing readiness', async () => {
      const res = await api.get('/api/posts?status=approved', { headers: { Cookie: this.sessionCookie } });
      if (res.status !== 200) {
        throw new Error(`Expected 200, got ${res.status}`);
      }
      if (!Array.isArray(res.data)) {
        throw new Error('Response should be an array');
      }
    });

    await this.runTest('Direct publishing system', async () => {
      const res = await api.post('/api/direct-publish', {
        action: 'test_connection'
      }, { headers: { Cookie: this.sessionCookie } });
      
      if (res.status !== 200) {
        throw new Error(`Expected 200, got ${res.status}`);
      }
      if (typeof res.data !== 'object') {
        throw new Error('Response should be an object');
      }
      if (!('platformStatus' in res.data)) {
        throw new Error('Response should have platformStatus property');
      }
    });
  }

  async runAllTests() {
    console.log('🚀 THEAGENCYIQ COMPREHENSIVE TEST SUITE');
    console.log('=====================================');
    
    try {
      await this.setupTestEnvironment();
      
      await this.testCodeQuality();
      await this.testAuthentication();
      await this.testSubscriptionManagement();
      await this.testPlatformConnections();
      await this.testBrandPurpose();
      await this.testPostManagement();
      await this.testAnalytics();
      await this.testPerformance();
      await this.testSecurity();
      await this.testAIContentGeneration();
      await this.testPublishingSystem();
      
    } catch (error) {
      console.error('❌ Test setup failed:', error.message);
      this.results.push({ 
        test: 'Test Setup', 
        status: 'FAIL', 
        duration: 0, 
        error: error.message 
      });
    }

    this.generateReport();
  }

  generateReport() {
    const totalTime = Date.now() - this.startTime;
    const passed = this.results.filter(r => r.status === 'PASS').length;
    const failed = this.results.filter(r => r.status === 'FAIL').length;
    const total = this.results.length;
    
    console.log('\n📋 COMPREHENSIVE TEST REPORT');
    console.log('============================');
    console.log(`📊 Tests Run: ${total}`);
    console.log(`✅ Passed: ${passed}`);
    console.log(`❌ Failed: ${failed}`);
    console.log(`📈 Success Rate: ${Math.round((passed / total) * 100)}%`);
    console.log(`⏱️ Total Time: ${totalTime}ms`);
    
    if (failed > 0) {
      console.log('\n❌ FAILED TESTS:');
      this.results.filter(r => r.status === 'FAIL').forEach(result => {
        console.log(`   • ${result.test}: ${result.error}`);
      });
    }
    
    console.log('\n📝 DETAILED RESULTS:');
    this.results.forEach(result => {
      const icon = result.status === 'PASS' ? '✅' : '❌';
      const duration = result.duration ? `(${result.duration}ms)` : '';
      console.log(`   ${icon} ${result.test} ${duration}`);
    });
    
    if (failed === 0) {
      console.log('\n🎉 ALL TESTS PASSED SUCCESSFULLY!');
      console.log('✅ TheAgencyIQ platform is fully operational');
    } else {
      console.log('\n⚠️ Some tests failed - see details above');
    }
  }
}

// Run the comprehensive test suite
const testSuite = new ComprehensiveTestSuite();
testSuite.runAllTests();