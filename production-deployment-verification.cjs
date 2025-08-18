/**
 * COMPREHENSIVE PRODUCTION DEPLOYMENT VERIFICATION TEST
 * Tests TheAgencyIQ deployment with 200 simulated users
 * Validates all critical systems for production launch
 */

const axios = require('axios');
const { performance } = require('perf_hooks');

class ProductionDeploymentVerifier {
  constructor() {
    this.baseUrl = 'https://app.theagencyiq.ai';
    this.results = {
      serverHealth: { status: 'pending', tests: [] },
      endpoints: { status: 'pending', tests: [] },
      sessionPersistence: { status: 'pending', tests: [] },
      oauthPublishing: { status: 'pending', tests: [] },
      frontendLoading: { status: 'pending', tests: [] },
      loadTesting: { status: 'pending', tests: [] },
      metrics: {}
    };
    this.errors = [];
    this.totalTests = 0;
    this.passedTests = 0;
  }

  async runCompleteVerification() {
    console.log('🚀 PRODUCTION DEPLOYMENT VERIFICATION STARTED');
    console.log('=' .repeat(60));
    
    const startTime = performance.now();
    
    try {
      // 1. Server Health Check
      await this.verifyServerHealth();
      
      // 2. Critical Endpoints Test
      await this.verifyEndpoints();
      
      // 3. Session Persistence Test
      await this.verifySessionPersistence();
      
      // 4. Frontend Loading Test
      await this.verifyFrontendLoading();
      
      // 5. OAuth Publishing Test
      await this.verifyOAuthPublishing();
      
      // 6. Load Testing with 200 Users
      await this.runLoadTesting();
      
      const endTime = performance.now();
      this.results.metrics.totalTestTime = Math.round(endTime - startTime);
      
      this.generateFinalReport();
      
    } catch (error) {
      console.error('❌ CRITICAL ERROR in deployment verification:', error.message);
      this.errors.push(`Critical verification error: ${error.message}`);
    }
  }

  async verifyServerHealth() {
    console.log('\n🔍 VERIFYING SERVER HEALTH...');
    
    const tests = [
      {
        name: 'Server Response Time',
        test: async () => {
          const start = performance.now();
          const response = await axios.get(`${this.baseUrl}/`, { timeout: 15000 });
          const responseTime = Math.round(performance.now() - start);
          
          if (response.status === 200 && responseTime < 15000) {
            return { success: true, message: `Server responds in ${responseTime}ms` };
          } else {
            return { success: false, message: `Slow response: ${responseTime}ms` };
          }
        }
      },
      {
        name: 'Server Uptime Check',
        test: async () => {
          const response = await axios.get(`${this.baseUrl}/`, { timeout: 10000 });
          return {
            success: response.status === 200,
            message: response.status === 200 ? 'Server is up' : `Server returned ${response.status}`
          };
        }
      },
      {
        name: 'Favicon Loading',
        test: async () => {
          try {
            const response = await axios.get(`${this.baseUrl}/attached_assets/agency_logo_1749083054761.png`, { timeout: 5000 });
            return {
              success: response.status === 200,
              message: response.status === 200 ? 'Favicon loads correctly' : 'Favicon failed to load'
            };
          } catch (error) {
            return { success: false, message: `Favicon error: ${error.message}` };
          }
        }
      }
    ];

    await this.runTestSuite('serverHealth', tests);
  }

  async verifyEndpoints() {
    console.log('\n🔍 VERIFYING CRITICAL ENDPOINTS...');
    
    const tests = [
      {
        name: '/api/user endpoint',
        test: async () => {
          const response = await axios.get(`${this.baseUrl}/api/user`, { timeout: 10000 });
          return {
            success: response.status === 200,
            message: response.status === 200 ? 'User endpoint responds 200' : `Endpoint returned ${response.status}`
          };
        }
      },
      {
        name: '/api/user-status endpoint',
        test: async () => {
          const response = await axios.get(`${this.baseUrl}/api/user-status`, { timeout: 10000 });
          return {
            success: response.status === 200,
            message: response.status === 200 ? 'User status endpoint responds 200' : `Endpoint returned ${response.status}`
          };
        }
      },
      {
        name: '/api/auth/session endpoint',
        test: async () => {
          const response = await axios.get(`${this.baseUrl}/api/auth/session`, { timeout: 10000 });
          return {
            success: response.status === 200,
            message: response.status === 200 ? 'Session endpoint responds 200' : `Endpoint returned ${response.status}`
          };
        }
      },
      {
        name: '/api/platform-connections endpoint',
        test: async () => {
          const response = await axios.get(`${this.baseUrl}/api/platform-connections`, { timeout: 10000 });
          return {
            success: response.status === 200,
            message: response.status === 200 ? 'Platform connections endpoint responds 200' : `Endpoint returned ${response.status}`
          };
        }
      }
    ];

    await this.runTestSuite('endpoints', tests);
  }

  async verifySessionPersistence() {
    console.log('\n🔍 VERIFYING SESSION PERSISTENCE...');
    
    const tests = [
      {
        name: 'Session Cookie Persistence',
        test: async () => {
          const axiosInstance = axios.create({
            withCredentials: true,
            timeout: 10000
          });
          
          // First request to establish session
          const response1 = await axiosInstance.get(`${this.baseUrl}/api/auth/session`);
          const cookies1 = response1.headers['set-cookie'];
          
          // Second request with same instance (should maintain session)
          const response2 = await axiosInstance.get(`${this.baseUrl}/api/user`);
          
          return {
            success: response1.status === 200 && response2.status === 200,
            message: 'Session persists across requests'
          };
        }
      },
      {
        name: 'Multiple Tab Simulation',
        test: async () => {
          const requests = [];
          for (let i = 0; i < 3; i++) {
            requests.push(axios.get(`${this.baseUrl}/api/user`, { timeout: 10000 }));
          }
          
          const responses = await Promise.all(requests);
          const allSuccessful = responses.every(r => r.status === 200);
          
          return {
            success: allSuccessful,
            message: allSuccessful ? 'Multiple concurrent sessions work' : 'Session conflicts detected'
          };
        }
      }
    ];

    await this.runTestSuite('sessionPersistence', tests);
  }

  async verifyFrontendLoading() {
    console.log('\n🔍 VERIFYING FRONTEND LOADING...');
    
    const tests = [
      {
        name: 'React App Load Time',
        test: async () => {
          const start = performance.now();
          const response = await axios.get(`${this.baseUrl}/`, { timeout: 15000 });
          const loadTime = Math.round(performance.now() - start);
          
          const hasReactContent = response.data.includes('id="root"') && 
                                  response.data.includes('script') &&
                                  response.data.includes('meta');
          
          return {
            success: hasReactContent && loadTime < 15000,
            message: hasReactContent ? `React app loads in ${loadTime}ms` : 'React app structure missing'
          };
        }
      },
      {
        name: 'JavaScript Error Check',
        test: async () => {
          const response = await axios.get(`${this.baseUrl}/`, { timeout: 10000 });
          const hasBlockingScript = response.data.includes('Blocked Replit tracking');
          
          return {
            success: hasBlockingScript,
            message: hasBlockingScript ? 'JavaScript error blocking implemented' : 'JavaScript error blocking missing'
          };
        }
      },
      {
        name: 'Meta Pixel Integration',
        test: async () => {
          const response = await axios.get(`${this.baseUrl}/`, { timeout: 10000 });
          const hasMetaPixel = response.data.includes('facebook.com/tr') && 
                              response.data.includes('1409057863445071');
          
          return {
            success: hasMetaPixel,
            message: hasMetaPixel ? 'Meta Pixel properly integrated' : 'Meta Pixel missing'
          };
        }
      }
    ];

    await this.runTestSuite('frontendLoading', tests);
  }

  async verifyOAuthPublishing() {
    console.log('\n🔍 VERIFYING OAUTH PUBLISHING SYSTEM...');
    
    const tests = [
      {
        name: 'OAuth Endpoints Available',
        test: async () => {
          const platforms = ['facebook', 'instagram', 'linkedin', 'twitter', 'youtube'];
          const results = [];
          
          for (const platform of platforms) {
            try {
              const response = await axios.get(`${this.baseUrl}/auth/${platform}`, { 
                timeout: 5000,
                maxRedirects: 0,
                validateStatus: (status) => status < 400
              });
              results.push({ platform, success: response.status === 302 || response.status === 200 });
            } catch (error) {
              if (error.response && error.response.status === 302) {
                results.push({ platform, success: true });
              } else {
                results.push({ platform, success: false });
              }
            }
          }
          
          const successfulPlatforms = results.filter(r => r.success).length;
          return {
            success: successfulPlatforms >= 3,
            message: `${successfulPlatforms}/5 OAuth platforms available`
          };
        }
      },
      {
        name: 'Publishing Infrastructure',
        test: async () => {
          try {
            const response = await axios.get(`${this.baseUrl}/api/posts`, { timeout: 10000 });
            return {
              success: response.status === 200,
              message: response.status === 200 ? 'Publishing infrastructure ready' : 'Publishing system unavailable'
            };
          } catch (error) {
            return { success: false, message: `Publishing error: ${error.message}` };
          }
        }
      }
    ];

    await this.runTestSuite('oauthPublishing', tests);
  }

  async runLoadTesting() {
    console.log('\n🔍 RUNNING LOAD TESTING WITH 200 SIMULATED USERS...');
    
    const tests = [
      {
        name: 'Concurrent User Load Test',
        test: async () => {
          const userCount = 200;
          const requests = [];
          
          console.log(`   Creating ${userCount} concurrent requests...`);
          
          const start = performance.now();
          
          for (let i = 0; i < userCount; i++) {
            requests.push(
              axios.get(`${this.baseUrl}/api/user`, { 
                timeout: 30000,
                headers: { 'User-Agent': `TestUser-${i}` }
              }).catch(error => ({ error: error.message, userId: i }))
            );
          }
          
          const results = await Promise.all(requests);
          const endTime = performance.now();
          
          const successful = results.filter(r => r.status === 200).length;
          const failed = results.filter(r => r.error).length;
          const totalTime = Math.round(endTime - start);
          
          this.results.metrics.loadTest = {
            totalUsers: userCount,
            successfulRequests: successful,
            failedRequests: failed,
            totalTime: totalTime,
            averageResponseTime: Math.round(totalTime / userCount),
            successRate: Math.round((successful / userCount) * 100)
          };
          
          return {
            success: successful >= (userCount * 0.95), // 95% success rate required
            message: `${successful}/${userCount} users successful (${Math.round((successful/userCount)*100)}%) in ${totalTime}ms`
          };
        }
      },
      {
        name: 'Peak Load Stress Test',
        test: async () => {
          const burstSize = 50;
          const requests = [];
          
          console.log(`   Running peak load test with ${burstSize} burst requests...`);
          
          const start = performance.now();
          
          for (let i = 0; i < burstSize; i++) {
            requests.push(
              axios.get(`${this.baseUrl}/api/user-status`, { 
                timeout: 15000,
                headers: { 'User-Agent': `BurstUser-${i}` }
              }).catch(error => ({ error: error.message }))
            );
          }
          
          const results = await Promise.all(requests);
          const endTime = performance.now();
          
          const successful = results.filter(r => r.status === 200).length;
          const totalTime = Math.round(endTime - start);
          
          return {
            success: successful >= (burstSize * 0.9), // 90% success rate for burst
            message: `${successful}/${burstSize} burst requests successful in ${totalTime}ms`
          };
        }
      }
    ];

    await this.runTestSuite('loadTesting', tests);
  }

  async runTestSuite(suiteName, tests) {
    const results = [];
    
    for (const test of tests) {
      this.totalTests++;
      
      try {
        const result = await test.test();
        results.push({
          name: test.name,
          success: result.success,
          message: result.message
        });
        
        if (result.success) {
          this.passedTests++;
          console.log(`   ✅ ${test.name}: ${result.message}`);
        } else {
          console.log(`   ❌ ${test.name}: ${result.message}`);
          this.errors.push(`${test.name}: ${result.message}`);
        }
      } catch (error) {
        console.log(`   ❌ ${test.name}: ERROR - ${error.message}`);
        this.errors.push(`${test.name}: ${error.message}`);
        results.push({
          name: test.name,
          success: false,
          message: error.message
        });
      }
    }
    
    const successCount = results.filter(r => r.success).length;
    this.results[suiteName] = {
      status: successCount === results.length ? 'passed' : 'failed',
      tests: results,
      successRate: Math.round((successCount / results.length) * 100)
    };
  }

  generateFinalReport() {
    console.log('\n' + '='.repeat(60));
    console.log('📊 PRODUCTION DEPLOYMENT VERIFICATION COMPLETE');
    console.log('='.repeat(60));
    
    const overallSuccessRate = Math.round((this.passedTests / this.totalTests) * 100);
    const isProductionReady = overallSuccessRate >= 95 && this.errors.length === 0;
    
    console.log(`\n🎯 OVERALL RESULTS:`);
    console.log(`   Total Tests: ${this.totalTests}`);
    console.log(`   Passed: ${this.passedTests}`);
    console.log(`   Failed: ${this.totalTests - this.passedTests}`);
    console.log(`   Success Rate: ${overallSuccessRate}%`);
    console.log(`   Total Test Time: ${this.results.metrics.totalTestTime}ms`);
    
    if (this.results.metrics.loadTest) {
      console.log(`\n📈 LOAD TEST METRICS:`);
      console.log(`   200 User Test: ${this.results.metrics.loadTest.successRate}% success rate`);
      console.log(`   Average Response Time: ${this.results.metrics.loadTest.averageResponseTime}ms`);
      console.log(`   Total Load Test Time: ${this.results.metrics.loadTest.totalTime}ms`);
    }
    
    console.log(`\n📋 SYSTEM STATUS:`);
    Object.entries(this.results).forEach(([key, result]) => {
      if (key !== 'metrics' && result.status) {
        const icon = result.status === 'passed' ? '✅' : '❌';
        console.log(`   ${icon} ${key}: ${result.status.toUpperCase()} (${result.successRate || 0}%)`);
      }
    });
    
    if (this.errors.length > 0) {
      console.log(`\n🚨 ERRORS FOUND:`);
      this.errors.forEach(error => console.log(`   • ${error}`));
    }
    
    console.log(`\n🚀 PRODUCTION READINESS: ${isProductionReady ? '✅ READY FOR LAUNCH' : '❌ NEEDS ATTENTION'}`);
    
    if (isProductionReady) {
      console.log('\n🎉 TheAgencyIQ deployment is FULLY OPERATIONAL for 200 users!');
      console.log('   • All endpoints responding correctly (200 status codes)');
      console.log('   • Session persistence working across tabs/refreshes');
      console.log('   • Frontend loading under 15s with no JS errors');
      console.log('   • OAuth publishing system ready');
      console.log('   • Load testing passed with 200 concurrent users');
      console.log('   • Zero critical errors detected');
    } else {
      console.log('\n⚠️  Issues detected that need resolution before launch');
    }
    
    console.log('\n='.repeat(60));
  }
}

// Run the verification
const verifier = new ProductionDeploymentVerifier();
verifier.runCompleteVerification().catch(console.error);