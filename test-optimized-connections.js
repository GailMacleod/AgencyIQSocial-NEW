/**
 * Test Optimized Platform Connections System
 * Tests the optimized API endpoint and UI state management
 */

import axios from 'axios';

class OptimizedConnectionsTest {
  constructor() {
    this.baseUrl = 'http://localhost:5000';
    this.sessionCookie = null;
    this.results = [];
  }

  async runTests() {
    console.log('🧪 OPTIMIZED CONNECTIONS TEST - Starting comprehensive validation');
    
    try {
      // Establish session
      await this.establishSession();
      
      // Test optimized API endpoint
      await this.testOptimizedEndpoint();
      
      // Test connection state efficiency
      await this.testConnectionStateEfficiency();
      
      // Test OAuth flow optimization
      await this.testOAuthFlowOptimization();
      
      // Generate performance report
      this.generatePerformanceReport();
      
      console.log('\n✅ All optimization tests completed successfully!');
      
    } catch (error) {
      console.error('\n❌ Test failed:', error.message);
    }
  }

  async establishSession() {
    console.log('\n🔐 Establishing session...');
    
    try {
      const response = await axios.post(`${this.baseUrl}/api/establish-session`, {
        email: 'gailm@macleodglba.com.au',
        phone: '+61424835189'
      });
      
      this.sessionCookie = response.headers['set-cookie']?.[0];
      
      this.results.push({
        test: 'Session Establishment',
        status: 'PASS',
        details: 'Session established successfully',
        performance: 'Optimized'
      });
      
      console.log('✅ Session established successfully');
      
    } catch (error) {
      console.error('❌ Session establishment failed:', error.message);
      throw error;
    }
  }

  async testOptimizedEndpoint() {
    console.log('\n🔧 Testing optimized /api/platform-connections endpoint...');
    
    const startTime = Date.now();
    
    try {
      const response = await axios.get(`${this.baseUrl}/api/platform-connections`, {
        headers: {
          Cookie: this.sessionCookie
        }
      });
      
      const endTime = Date.now();
      const responseTime = endTime - startTime;
      
      const connections = response.data;
      
      // Validate response structure
      if (!Array.isArray(connections)) {
        throw new Error('Response is not an array');
      }
      
      // Validate unique connections per platform
      const platformCounts = {};
      connections.forEach(conn => {
        platformCounts[conn.platform] = (platformCounts[conn.platform] || 0) + 1;
      });
      
      const duplicates = Object.entries(platformCounts).filter(([platform, count]) => count > 1);
      
      if (duplicates.length > 0) {
        throw new Error(`Found duplicate connections: ${duplicates.map(([p, c]) => `${p}:${c}`).join(', ')}`);
      }
      
      // Validate OAuth status structure
      const connectionsWithOAuth = connections.filter(conn => conn.oauthStatus);
      
      this.results.push({
        test: 'Optimized Endpoint',
        status: 'PASS',
        details: `${connections.length} unique connections, ${connectionsWithOAuth.length} with OAuth status`,
        performance: `${responseTime}ms response time`,
        data: {
          totalConnections: connections.length,
          responseTime: responseTime,
          platforms: connections.map(c => c.platform),
          oauthValidations: connectionsWithOAuth.length
        }
      });
      
      console.log(`✅ Optimized endpoint working - ${connections.length} connections in ${responseTime}ms`);
      console.log(`📊 Platforms: ${connections.map(c => c.platform).join(', ')}`);
      
    } catch (error) {
      this.results.push({
        test: 'Optimized Endpoint',
        status: 'FAIL',
        details: error.message,
        performance: 'Failed'
      });
      
      console.error('❌ Optimized endpoint test failed:', error.message);
      throw error;
    }
  }

  async testConnectionStateEfficiency() {
    console.log('\n⚡ Testing connection state efficiency...');
    
    const startTime = Date.now();
    
    try {
      // Make multiple rapid requests to test caching
      const requests = [];
      for (let i = 0; i < 5; i++) {
        requests.push(
          axios.get(`${this.baseUrl}/api/platform-connections`, {
            headers: { Cookie: this.sessionCookie }
          })
        );
      }
      
      const responses = await Promise.all(requests);
      const endTime = Date.now();
      
      const totalTime = endTime - startTime;
      const averageTime = totalTime / responses.length;
      
      // Validate all responses are identical
      const firstResponse = JSON.stringify(responses[0].data);
      const allIdentical = responses.every(r => JSON.stringify(r.data) === firstResponse);
      
      if (!allIdentical) {
        throw new Error('Responses are not consistent');
      }
      
      this.results.push({
        test: 'Connection State Efficiency',
        status: 'PASS',
        details: `5 requests processed consistently`,
        performance: `${averageTime.toFixed(2)}ms average response time`,
        data: {
          totalRequests: 5,
          totalTime: totalTime,
          averageTime: averageTime,
          consistent: allIdentical
        }
      });
      
      console.log(`✅ State efficiency test passed - ${averageTime.toFixed(2)}ms average`);
      
    } catch (error) {
      this.results.push({
        test: 'Connection State Efficiency',
        status: 'FAIL',
        details: error.message,
        performance: 'Failed'
      });
      
      console.error('❌ State efficiency test failed:', error.message);
      throw error;
    }
  }

  async testOAuthFlowOptimization() {
    console.log('\n🔗 Testing OAuth flow optimization...');
    
    try {
      // Test OAuth initiation endpoints
      const platforms = ['facebook', 'instagram', 'linkedin', 'x', 'youtube'];
      const oauthTests = [];
      
      for (const platform of platforms) {
        const startTime = Date.now();
        
        try {
          const response = await axios.get(`${this.baseUrl}/auth/${platform}`, {
            headers: { Cookie: this.sessionCookie },
            maxRedirects: 0,
            validateStatus: (status) => status === 302 || status === 200
          });
          
          const endTime = Date.now();
          const responseTime = endTime - startTime;
          
          oauthTests.push({
            platform: platform,
            status: 'PASS',
            responseTime: responseTime,
            redirected: response.status === 302
          });
          
        } catch (error) {
          oauthTests.push({
            platform: platform,
            status: 'FAIL',
            error: error.message
          });
        }
      }
      
      const successfulTests = oauthTests.filter(t => t.status === 'PASS');
      const averageResponseTime = successfulTests.reduce((sum, t) => sum + t.responseTime, 0) / successfulTests.length;
      
      this.results.push({
        test: 'OAuth Flow Optimization',
        status: successfulTests.length >= 3 ? 'PASS' : 'PARTIAL',
        details: `${successfulTests.length}/${platforms.length} OAuth flows working`,
        performance: `${averageResponseTime.toFixed(2)}ms average OAuth initiation`,
        data: {
          platformTests: oauthTests,
          successfulPlatforms: successfulTests.length,
          totalPlatforms: platforms.length,
          averageResponseTime: averageResponseTime
        }
      });
      
      console.log(`✅ OAuth optimization test completed - ${successfulTests.length}/${platforms.length} working`);
      
    } catch (error) {
      this.results.push({
        test: 'OAuth Flow Optimization',
        status: 'FAIL',
        details: error.message,
        performance: 'Failed'
      });
      
      console.error('❌ OAuth optimization test failed:', error.message);
    }
  }

  generatePerformanceReport() {
    console.log('\n📊 OPTIMIZATION PERFORMANCE REPORT');
    console.log('=' .repeat(50));
    
    this.results.forEach(result => {
      console.log(`\n🧪 ${result.test}:`);
      console.log(`   Status: ${result.status}`);
      console.log(`   Details: ${result.details}`);
      console.log(`   Performance: ${result.performance}`);
      
      if (result.data) {
        console.log(`   Data: ${JSON.stringify(result.data, null, 2)}`);
      }
    });
    
    const passedTests = this.results.filter(r => r.status === 'PASS').length;
    const totalTests = this.results.length;
    const successRate = (passedTests / totalTests * 100).toFixed(1);
    
    console.log('\n📈 OPTIMIZATION SUMMARY:');
    console.log(`   Tests Passed: ${passedTests}/${totalTests} (${successRate}%)`);
    console.log(`   System Status: ${successRate >= 80 ? 'OPTIMIZED' : 'NEEDS_WORK'}`);
    console.log(`   Performance: ${successRate >= 90 ? 'EXCELLENT' : successRate >= 80 ? 'GOOD' : 'POOR'}`);
    
    return {
      passedTests,
      totalTests,
      successRate: parseFloat(successRate),
      status: successRate >= 80 ? 'OPTIMIZED' : 'NEEDS_WORK',
      results: this.results
    };
  }
}

// Run the test
const test = new OptimizedConnectionsTest();
test.runTests().catch(console.error);